// Package alerting handles proactive security notifications.
// Cert expiry alerting is the primary feature — it builds on the existing
// TLS checker to queue notifications when certificates are about to expire.
package alerting

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"ke-scan/internal/db"
)

// CertChecker checks TLS certificate expiry for verified domains
// and creates notifications for expiring certs.
type CertChecker struct {
	db *db.DB
}

// NewCertChecker creates a new cert expiry alerting service.
func NewCertChecker(database *db.DB) *CertChecker {
	return &CertChecker{db: database}
}

// DaysUntilWarning is the threshold for cert expiry notifications.
// If a cert expires within this many days, we queue a notification.
const DaysUntilWarning = 30

// CheckAllDomains iterates over verified domains and checks their
// TLS certificate expiry. Creates notifications for expiring certs.
func (c *CertChecker) CheckAllDomains() error {
	// Get all domains that have auto_scan enabled and are verified
	domains, err := c.db.GetVerifiedDomains()
	if err != nil {
		return fmt.Errorf("failed to get verified domains: %w", err)
	}

	log.Printf("Cert check: checking %d verified domains", len(domains))

	for _, domain := range domains {
		daysLeft, expiryDate, err := checkCertExpiry(domain.Domain)
		if err != nil {
			log.Printf("Cert check error for %s: %v", domain.Domain, err)
			continue
		}

		if daysLeft < 0 {
			// Certificate has already expired
			c.createCertNotification(domain.TenantID, domain.Domain, "expired", 0, expiryDate)
		} else if daysLeft <= DaysUntilWarning {
			// Certificate is expiring soon
			c.createCertNotification(domain.TenantID, domain.Domain, "expiring", int(daysLeft), expiryDate)
		}
	}

	return nil
}

// CheckDomain checks a single domain's cert and creates a notification if needed.
func (c *CertChecker) CheckDomain(domainID int64, domainName string, tenantID int64) error {
	daysLeft, expiryDate, err := checkCertExpiry(domainName)
	if err != nil {
		return fmt.Errorf("cert check failed for %s: %w", domainName, err)
	}

	if daysLeft < 0 {
		c.createCertNotification(tenantID, domainName, "expired", 0, expiryDate)
	} else if daysLeft <= DaysUntilWarning {
		c.createCertNotification(tenantID, domainName, "expiring", int(daysLeft), expiryDate)
	}

	// Update last_scanned_at on the domain
	_ = c.db.UpdateDomainLastScanned(domainID)

	return nil
}

// createCertNotification creates a notification for an expiring/expired cert.
// It deduplicates: if an unread notification for this domain already exists,
// it doesn't create another one.
func (c *CertChecker) createCertNotification(tenantID int64, domain, status string, daysLeft int, expiryDate time.Time) {
	// Check for existing unread notification for this domain
	exists, err := c.db.HasUnreadCertNotification(tenantID, domain)
	if err != nil {
		log.Printf("Error checking existing notification for %s: %v", domain, err)
		return
	}
	if exists {
		return // Don't duplicate notifications
	}

	var title, message string
	if status == "expired" {
		title = fmt.Sprintf("🔴 TLS Certificate EXPIRED: %s", domain)
		message = fmt.Sprintf(
			"The TLS certificate for %s expired on %s. "+
				"Your site may show security warnings to visitors. "+
				"Renew the certificate immediately.",
			domain, expiryDate.Format("January 2, 2006"),
		)
	} else {
		title = fmt.Sprintf("⚠️ TLS Certificate Expiring: %s", domain)
		message = fmt.Sprintf(
			"The TLS certificate for %s expires in %d days (%s). "+
				"Renew before expiry to avoid service disruption.",
			domain, daysLeft, expiryDate.Format("January 2, 2006"),
		)
	}

	err = c.db.CreateNotification(
		&tenantID, nil,
		"cert_expiry",
		title,
		message,
		nil, nil,
	)
	if err != nil {
		log.Printf("Error creating cert notification for %s: %v", domain, err)
		return
	}

	log.Printf("Created cert expiry notification for %s (tenant %d)", domain, tenantID)
}

// checkCertExpiry connects to a host over TLS and returns the days
// until the certificate expires.
func checkCertExpiry(domain string) (daysLeft float64, expiryDate time.Time, err error) {
	host := extractHost(domain)
	if host == "" {
		host = domain
	}

	// Ensure port 443
	addr := host
	if !strings.Contains(host, ":") {
		addr = host + ":443"
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true, // We just want to inspect the cert
	})
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("TLS dial failed: %w", err)
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return 0, time.Time{}, fmt.Errorf("no certificates returned")
	}

	cert := certs[0]
	expiryDate = cert.NotAfter
	daysLeft = time.Until(expiryDate).Hours() / 24

	return daysLeft, expiryDate, nil
}

// extractHost pulls the hostname from a URL string.
func extractHost(rawURL string) string {
	host := rawURL
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}
	return host
}
