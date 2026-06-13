// Package scanner implements the core scanning engine for KE-SCAN
package scanner

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"ke-scan/config"
	"ke-scan/internal/compliance"
	"ke-scan/internal/db"
	"ke-scan/internal/scanner/loader"
)

// Engine orchestrates all scan modules
type Engine struct {
	db   *db.DB
	cfg  *config.Config
	cves *loader.Loader
}

// NewEngine creates and initialises the scanner engine
func NewEngine(database *db.DB, cfg *config.Config) (*Engine, error) {
	cveLoader := loader.NewLoader()

	// Load CVE definitions from data/cves — non-fatal if directory missing
	if err := cveLoader.LoadAll("data/cves"); err != nil {
		log.Printf("Warning: could not load CVE definitions: %v", err)
	} else {
		log.Printf("Loaded %d CVE definitions", len(cveLoader.GetAll()))
	}

	return &Engine{
		db:   database,
		cfg:  cfg,
		cves: cveLoader,
	}, nil
}

// RunScan executes a full scan pipeline for the given scan ID and target.
// Intended to be called in a goroutine.
func (e *Engine) RunScan(scanID int64, targetURL, scanType string) {
	log.Printf("Starting scan %d for %s (type: %s)", scanID, targetURL, scanType)

	// Mark scan as running
	if err := e.db.StartScan(scanID); err != nil {
		log.Printf("Error starting scan %d: %v", scanID, err)
		return
	}

	var allFindings []*db.Finding
	var runErr error

	switch scanType {
	case "compliance_only":
		allFindings, runErr = e.runComplianceChecks(scanID, targetURL)
	case "quick":
		allFindings, runErr = e.runQuickChecks(scanID, targetURL)
	case "deep":
		allFindings, runErr = e.runFullScan(scanID, targetURL) // Deep scans currently map to full scans
	default: // "full"
		allFindings, runErr = e.runFullScan(scanID, targetURL)
	}

	if runErr != nil {
		log.Printf("Scan %d failed: %v", scanID, runErr)
		_ = e.db.UpdateScanStatus(scanID, "failed", 0)
		return
	}

	// Persist findings
	for _, f := range allFindings {
		_, err := e.db.CreateFinding(
			f.ScanID,
			f.Title,
			f.Description,
			f.Severity,
			f.Category,
			f.Remediation,
			f.Evidence,
			f.CVEID,
			f.ODPCSection,
		)
		if err != nil {
			log.Printf("Error saving finding for scan %d: %v", scanID, err)
		}
	}

	// Auto-reopen resolved findings that reappear in this scan
	scan, err := e.db.GetScan(scanID)
	if err == nil {
		reopenedIDs, err := e.db.AutoReopenResolvedFindings(scanID, scan.TenantID)
		if err != nil {
			log.Printf("Error auto-reopening findings for scan %d: %v", scanID, err)
		} else if len(reopenedIDs) > 0 {
			log.Printf("Scan %d: auto-reopened %d previously resolved findings", scanID, len(reopenedIDs))
		}

		// Create notification for new critical findings
		for _, f := range allFindings {
			if f.Severity == "critical" {
				e.db.CreateNotification(
					&scan.TenantID,
					nil,
					"new_critical_finding",
					"🔴 New Critical Finding Detected",
					fmt.Sprintf("A critical finding was detected on %s: %s", scan.TargetURL, f.Title),
					nil,
					&scanID,
				)
			}
		}

		// Mark domain as scanned and update last_scanned_at
		if scan.DomainID > 0 {
			e.db.UpdateDomainLastScanned(scan.DomainID)
		}
	}

	// Mark complete
	if err := e.db.CompleteScan(scanID); err != nil {
		log.Printf("Error completing scan %d: %v", scanID, err)
	}

	log.Printf("Scan %d complete — %d findings", scanID, len(allFindings))
}

// runFullScan runs all check modules and merges results
// runFullScan runs all check modules and merges results
func (e *Engine) runFullScan(scanID int64, targetURL string) ([]*db.Finding, error) {
	var findings []*db.Finding

	// Update progress: 5%
	_ = e.db.UpdateScanStatus(scanID, "running", 5)

	// TLS / HTTP headers
	tlsFindings, err := e.runTLSChecks(scanID, targetURL)
	if err != nil {
		log.Printf("TLS checks error for scan %d: %v", scanID, err)
	}
	findings = append(findings, tlsFindings...)
	_ = e.db.UpdateScanStatus(scanID, "running", 25)

	// HTTP security headers
	headerFindings, err := e.runHeaderChecks(scanID, targetURL)
	if err != nil {
		log.Printf("Header checks error for scan %d: %v", scanID, err)
	}
	findings = append(findings, headerFindings...)
	_ = e.db.UpdateScanStatus(scanID, "running", 50)

	// CVE Software Signature Checks (New module integration)
	cveFindings, err := e.runCVEChecks(scanID, targetURL)
	if err != nil {
		log.Printf("CVE checks error for scan %d: %v", scanID, err)
	}
	findings = append(findings, cveFindings...)
	_ = e.db.UpdateScanStatus(scanID, "running", 75)

	// Subdomain discovery (only for full scans)
	subdomainScanner := NewSubdomainScanner(e)
	subdomainFindings := subdomainScanner.Run(scanID, extractDomainFromURL(targetURL))
	findings = append(findings, subdomainFindings...)
	_ = e.db.UpdateScanStatus(scanID, "running", 85)

	// ODPC compliance
	complianceFindings, err := e.runComplianceChecks(scanID, targetURL)
	if err != nil {
		log.Printf("Compliance checks error for scan %d: %v", scanID, err)
	}
	findings = append(findings, complianceFindings...)
	_ = e.db.UpdateScanStatus(scanID, "running", 95)

	return findings, nil
}

// runQuickChecks runs only TLS and headers
func (e *Engine) runQuickChecks(scanID int64, targetURL string) ([]*db.Finding, error) {
	var findings []*db.Finding

	_ = e.db.UpdateScanStatus(scanID, "running", 20)
	tlsFindings, err := e.runTLSChecks(scanID, targetURL)
	if err != nil {
		log.Printf("TLS checks error for scan %d: %v", scanID, err)
	}
	findings = append(findings, tlsFindings...)

	_ = e.db.UpdateScanStatus(scanID, "running", 60)
	headerFindings, err := e.runHeaderChecks(scanID, targetURL)
	if err != nil {
		log.Printf("Header checks error for scan %d: %v", scanID, err)
	}
	findings = append(findings, headerFindings...)

	return findings, nil
}

// runComplianceChecks runs ODPC compliance module
func (e *Engine) runComplianceChecks(scanID int64, targetURL string) ([]*db.Finding, error) {
	assessor := compliance.NewODPCAssessor()
	results, err := assessor.Assess(targetURL)
	if err != nil {
		return nil, fmt.Errorf("compliance assessment failed: %w", err)
	}
	findings := compliance.ConvertComplianceResultsToFindings(scanID, results)
	return findings, nil
}

// runTLSChecks checks TLS certificate and configuration.
// Sprint 5: real implementation goes here.
func (e *Engine) runTLSChecks(scanID int64, targetURL string) ([]*db.Finding, error) {
	checker := NewTLSChecker(targetURL)
	return checker.Run(scanID)
}

// runHeaderChecks checks HTTP security headers.
// Sprint 5: real implementation goes here.
func (e *Engine) runHeaderChecks(scanID int64, targetURL string) ([]*db.Finding, error) {
	checker := NewHeaderChecker(targetURL)
	return checker.Run(scanID)
}

// TLSChecker checks TLS certificate validity and configuration
type TLSChecker struct {
	targetURL string
}

func NewTLSChecker(targetURL string) *TLSChecker {
	return &TLSChecker{targetURL: targetURL}
}

// Run performs TLS checks against the target.
// Sprint 5: replace stub logic with real crypto/tls inspection.
func (c *TLSChecker) Run(scanID int64) ([]*db.Finding, error) {
	var findings []*db.Finding

	host := extractHost(c.targetURL)
	if host == "" {
		return findings, nil
	}

	// Dial TLS and inspect certificate — with proper certificate validation
	tlsState, certChain, err := dialTLSWithValidation(host)
	if err != nil {
		// Could not connect over TLS — that itself is a finding
		findings = append(findings, &db.Finding{
			ScanID:      scanID,
			Title:       "TLS Connection Failed",
			Description: fmt.Sprintf("Could not establish a TLS connection to %s: %v", host, err),
			Severity:    "critical",
			Category:    "tls",
			Remediation: "Ensure HTTPS is enabled and a valid certificate is installed.",
			Evidence:    fmt.Sprintf("dial error: %v", err),
		})
		return findings, nil
	}

	// Check certificate expiry
	if len(tlsState.PeerCertificates) > 0 {
		cert := tlsState.PeerCertificates[0]
		daysUntilExpiry := time.Until(cert.NotAfter).Hours() / 24

		if daysUntilExpiry < 0 {
			findings = append(findings, &db.Finding{
				ScanID:      scanID,
				Title:       "TLS Certificate Expired",
				Description: fmt.Sprintf("Certificate expired on %s", cert.NotAfter.Format(time.RFC3339)),
				Severity:    "critical",
				Category:    "tls",
				Remediation: "Renew the TLS certificate immediately.",
				Evidence:    fmt.Sprintf("NotAfter: %s", cert.NotAfter),
			})
		} else if daysUntilExpiry < 30 {
			findings = append(findings, &db.Finding{
				ScanID:      scanID,
				Title:       "TLS Certificate Expiring Soon",
				Description: fmt.Sprintf("Certificate expires in %.0f days (%s)", daysUntilExpiry, cert.NotAfter.Format(time.RFC3339)),
				Severity:    "high",
				Category:    "tls",
				Remediation: "Renew the TLS certificate before it expires.",
				Evidence:    fmt.Sprintf("NotAfter: %s", cert.NotAfter),
			})
		}

		// Check certificate validation results
		if len(certChain) > 0 {
			// Determine severity: self-signed certs on private/internal hosts are less severe
			severity := "high"
			title := "TLS Certificate Validation Issues"
			remediation := "Ensure the certificate is signed by a trusted CA and matches the hostname."
			if isPrivateHost(host) && containsSelfSignedError(certChain) {
				severity = "info"
				title = "Self-Signed Certificate on Internal Host"
				remediation = "Consider using a trusted certificate for internal hosts, or accept as expected for development environments."
			}
			findings = append(findings, &db.Finding{
				ScanID:      scanID,
				Title:       title,
				Description: fmt.Sprintf("Certificate chain validation failed: %s", strings.Join(certChain, "; ")),
				Severity:    severity,
				Category:    "tls",
				Remediation: remediation,
				Evidence:    strings.Join(certChain, "\n"),
			})
		}
	}

	return findings, nil
}

// HeaderChecker checks HTTP security response headers
type HeaderChecker struct {
	targetURL string
}

func NewHeaderChecker(targetURL string) *HeaderChecker {
	return &HeaderChecker{targetURL: targetURL}
}

// Run performs HTTP header checks against the target.
// Sprint 5: expand with full header policy analysis.
func (c *HeaderChecker) Run(scanID int64) ([]*db.Finding, error) {
	var findings []*db.Finding

	headers, err := fetchHeaders(c.targetURL)
	if err != nil {
		return findings, fmt.Errorf("failed to fetch headers: %w", err)
	}

	type headerCheck struct {
		header      string
		title       string
		description string
		severity    string
		remediation string
	}

	checks := []headerCheck{
		{
			header:      "Strict-Transport-Security",
			title:       "Missing HSTS Header",
			description: "The Strict-Transport-Security header is not set. Browsers may allow HTTP connections.",
			severity:    "high",
			remediation: "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
		},
		{
			header:      "Content-Security-Policy",
			title:       "Missing Content-Security-Policy Header",
			description: "No CSP header detected. XSS attacks may be possible.",
			severity:    "high",
			remediation: "Define a Content-Security-Policy that whitelists trusted sources.",
		},
		{
			header:      "X-Frame-Options",
			title:       "Missing X-Frame-Options Header",
			description: "The page may be embeddable in iframes, enabling clickjacking attacks.",
			severity:    "medium",
			remediation: "Add: X-Frame-Options: DENY or SAMEORIGIN",
		},
		{
			header:      "X-Content-Type-Options",
			title:       "Missing X-Content-Type-Options Header",
			description: "Browser MIME sniffing is not disabled.",
			severity:    "medium",
			remediation: "Add: X-Content-Type-Options: nosniff",
		},
		{
			header:      "Referrer-Policy",
			title:       "Missing Referrer-Policy Header",
			description: "Full referrer URLs may be leaked to third parties.",
			severity:    "low",
			remediation: "Add: Referrer-Policy: strict-origin-when-cross-origin",
		},
		{
			header:      "Permissions-Policy",
			title:       "Missing Permissions-Policy Header",
			description: "Browser features (camera, microphone, geolocation) are not restricted.",
			severity:    "low",
			remediation: "Add a Permissions-Policy header restricting unused browser features.",
		},
	}

	for _, check := range checks {
		// Use headers.Get() for case-insensitive lookup
		if headers.Get(check.header) == "" {
			findings = append(findings, &db.Finding{
				ScanID:      scanID,
				Title:       check.title,
				Description: check.description,
				Severity:    check.severity,
				Category:    "headers",
				Remediation: check.remediation,
				Evidence:    fmt.Sprintf("Header '%s' absent from response", check.header),
			})
		}
	}

	return findings, nil
}

func extractHost(targetURL string) string {
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}

	u, err := url.Parse(targetURL)
	if err != nil {
		return ""
	}

	return u.Hostname()
}

// dialTLSWithValidation dials TLS with proper certificate validation.
// Returns the TLS connection state, any verification error strings, and error.
func dialTLSWithValidation(host string) (*tls.ConnectionState, []string, error) {
	// Load system root CA pool
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		// Fallback to an empty pool if system roots are unavailable
		rootCAs = x509.NewCertPool()
	}

	// First dial with InsecureSkipVerify to get the raw certificate chain for inspection
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", host+":443", &tls.Config{
		InsecureSkipVerify: true, // Only to get the cert chain; we validate manually below
		RootCAs:            rootCAs,
	})
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()

	// Now validate the certificate manually
	var verifyErrors []string
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]

		// Build intermediate pool from the remaining certs in the chain
		intermediatePool := x509.NewCertPool()
		for i, c := range state.PeerCertificates {
			if i > 0 {
				intermediatePool.AddCert(c)
			}
		}

		// Verify the certificate against system roots
		opts := x509.VerifyOptions{
			Roots:         rootCAs,
			Intermediates: intermediatePool,
			DNSName:       host,
		}

		if _, err := cert.Verify(opts); err != nil {
			verifyErrors = append(verifyErrors, err.Error())
		}
	}

	return &state, verifyErrors, nil
}

// isPrivateHost checks whether a hostname resolves to a private/internal IP address
// (RFC 1918, RFC 3927, loopback).
func isPrivateHost(host string) bool {
	// Check for obvious internal hostnames
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}
	// Check for .local, .internal, .lan, .home TLDs
	privateTLDs := []string{".local", ".internal", ".lan", ".home", ".localhost", ".corp"}
	for _, tld := range privateTLDs {
		if strings.HasSuffix(host, tld) {
			return true
		}
	}
	// Try to resolve and check IP ranges
	ips, err := net.LookupIP(host)
	if err != nil {
		return false
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return true
		}
		// Check RFC 1918 ranges
		if ip4 := ip.To4(); ip4 != nil {
			if ip4[0] == 10 || // 10.0.0.0/8
				(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) || // 172.16.0.0/12
				(ip4[0] == 192 && ip4[1] == 168) { // 192.168.0.0/16
				return true
			}
		}
	}
	return false
}

// containsSelfSignedError checks if the verification errors indicate a self-signed certificate.
func containsSelfSignedError(errors []string) bool {
	selfSignedPatterns := []string{
		"certificate is not trusted",
		"certificate signed by unknown authority",
		"x509: certificate signed by unknown authority",
		"x509: certificate has expired",
		"self-signed",
		"SSL certificate problem: self signed certificate",
	}
	for _, err := range errors {
		errLower := strings.ToLower(err)
		for _, pattern := range selfSignedPatterns {
			if strings.Contains(errLower, pattern) {
				return true
			}
		}
	}
	return false
}

// reHostnameError matches x509 hostname verification errors
var reHostnameError = regexp.MustCompile(`x509:.*(?:cannot validate|certificate is valid for)`)

func fetchHeaders(targetURL string) (http.Header, error) {
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Head(targetURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return resp.Header, nil
}

// runCVEChecks analyzes the remote server software versions and flags matching CVE definitions
func (e *Engine) runCVEChecks(scanID int64, targetURL string) ([]*db.Finding, error) {
	var findings []*db.Finding

	// Initialize our new behavioral fingerprinter
	printer := NewFingerprinter(targetURL)
	profile := printer.ProfileTarget()

	// Loop over all our definitions loaded from data/cves
	for _, cve := range e.cves.GetAll() {
		for _, softwareName := range cve.AffectedSoftware {
			softwareLower := strings.ToLower(softwareName)
			isMatch := (profile.Software == softwareLower)

			// Defensive baseline: only match "generic" CVEs when software is unknown.
			// Do NOT match all critical CVEs — that would cause every critical CVE to fire
			// against any host with an unidentifiable stack.
			if profile.Software == "unknown" && softwareLower == "generic" {
				isMatch = true
			}

			// Version gating: if we extracted a version from fingerprinting and the CVE
			// specifies affected versions, verify the target version falls within range.
			if isMatch && profile.Version != "" && len(cve.AffectedVersions) > 0 {
				if constraints, ok := cve.AffectedVersions[softwareLower]; ok && len(constraints) > 0 {
					// Check version against ALL constraints for this software
					// Version is affected if it matches ANY single constraint
					matchedVersion := false
					for _, constraint := range constraints {
						if VersionAffected(profile.Version, constraint) {
							matchedVersion = true
							break
						}
					}
					if !matchedVersion {
						isMatch = false // Version is not in any affected range
					}
				}
			}

			if isMatch {
				cveIDPtr := cve.ID
				odpcPtr := cve.ODPCSection

				titleText := cve.Title
				evidenceText := fmt.Sprintf("Inferred Stack: %s (Confidence: %.0f%%)", profile.Software, profile.Confidence*100)

				if profile.IsHidden {
					titleText += " (Suspected Risk)"
					evidenceText += "\nNotice: Target server signature is concealed. Finding flagged using fallback defensive heuristics."
				}
				if profile.Version != "" {
					evidenceText += fmt.Sprintf("\nExtracted Version: %s", profile.Version)
				}

				// Include version constraint in evidence when available
				if constraints, ok := cve.AffectedVersions[softwareLower]; ok {
					evidenceText += fmt.Sprintf("\nAffected Version Range: %s", strings.Join(constraints, " || "))
				}

				// Generate finding struct
				finding := &db.Finding{
					ScanID:      scanID,
					Title:       titleText,
					Description: cve.Description,
					Severity:    cve.Severity,
					Category:    "vulnerability",
					Remediation: cve.Remediation,
					Evidence:    evidenceText,
					CVEID:       &cveIDPtr,
					ODPCSection: &odpcPtr,
				}

				// Evaluate risk metrics through the updated scorer matrix
				risk := AssessRisk(finding, profile.Confidence)
				if risk.IsSuspected && finding.Severity == "critical" {
					finding.Severity = "medium" // Demote critical alert noise if it's an unverified guess
				}

				findings = append(findings, finding)
				break
			}
		}
	}

	return findings, nil
}

// parseVersionString is a helper to pull versions out of typical HTTP response headers
func parseVersionString(headerValue, software string) string {
	idx := strings.Index(headerValue, software)
	if idx == -1 {
		return ""
	}

	// Substring starting right from software token name
	sub := headerValue[idx+len(software):]
	sub = strings.TrimLeft(sub, "/ ")

	// Split by spaces or trailing components to isolate clean version block (e.g. "2.4.41")
	fields := strings.FieldsFunc(sub, func(r rune) bool {
		return r == ' ' || r == '(' || r == ';'
	})

	if len(fields) > 0 {
		return fields[0]
	}
	return ""
}
