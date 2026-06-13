package db

import (
	"database/sql"
	"fmt"
	"time"
)

// Domain represents a verified domain owned by a tenant
type Domain struct {
	ID              int64      `json:"id"`
	TenantID        int64      `json:"tenant_id"`
	Domain          string     `json:"domain"`
	VerificationTxt string     `json:"verification_txt"` // DNS TXT record value
	Verified        bool       `json:"verified"`
	VerifiedAt      *time.Time `json:"verified_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// CreateDomain adds an unverified domain for a tenant and stores the
// DNS TXT token they need to publish to prove ownership.
func (d *DB) CreateDomain(tenantID int64, domain, verificationTxt string) (*Domain, error) {
	query := `
		INSERT INTO domains (tenant_id, domain, verification_txt, verified, created_at, updated_at)
		VALUES (?, ?, ?, 0, ?, ?)
	`
	now := time.Now()
	result, err := d.Exec(query, tenantID, domain, verificationTxt, now, now)
	if err != nil {
		return nil, fmt.Errorf("failed to create domain: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get domain ID: %w", err)
	}

	return &Domain{
		ID:              id,
		TenantID:        tenantID,
		Domain:          domain,
		VerificationTxt: verificationTxt,
		Verified:        false,
		CreatedAt:       now,
		UpdatedAt:       now,
	}, nil
}

// GetDomainByID retrieves a domain record by its primary key.
func (d *DB) GetDomainByID(id int64) (*Domain, error) {
	query := `
		SELECT id, tenant_id, domain, verification_txt, verified, verified_at, created_at, updated_at
		FROM domains WHERE id = ?
	`
	return d.scanDomain(d.QueryRow(query, id))
}

// GetDomainByName retrieves a domain record by domain name string.
func (d *DB) GetDomainByName(domain string) (*Domain, error) {
	query := `
		SELECT id, tenant_id, domain, verification_txt, verified, verified_at, created_at, updated_at
		FROM domains WHERE domain = ?
	`
	return d.scanDomain(d.QueryRow(query, domain))
}

// ListTenantDomains returns all domains belonging to a tenant.
func (d *DB) ListTenantDomains(tenantID int64) ([]*Domain, error) {
	query := `
		SELECT id, tenant_id, domain, verification_txt, verified, verified_at, created_at, updated_at
		FROM domains WHERE tenant_id = ? ORDER BY created_at DESC
	`
	rows, err := d.Query(query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list domains: %w", err)
	}
	defer rows.Close()

	var domains []*Domain
	for rows.Next() {
		dom, err := d.scanDomainRow(rows)
		if err != nil {
			return nil, err
		}
		domains = append(domains, dom)
	}
	return domains, nil
}

// MarkDomainVerified sets a domain as verified with the current timestamp.
func (d *DB) MarkDomainVerified(id int64) error {
	now := time.Now()
	query := `UPDATE domains SET verified = 1, verified_at = ?, updated_at = ? WHERE id = ?`

	result, err := d.Exec(query, now, now, id)
	if err != nil {
		return fmt.Errorf("failed to verify domain: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("domain %d not found", id)
	}
	return nil
}

// DeleteDomain removes a domain and cascades to scans/findings via FK.
func (d *DB) DeleteDomain(id int64) error {
	result, err := d.Exec(`DELETE FROM domains WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed to delete domain: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("domain %d not found", id)
	}
	return nil
}

// --- internal helpers ---

func (d *DB) scanDomain(row *sql.Row) (*Domain, error) {
	var dom Domain
	var verifiedAt sql.NullTime

	err := row.Scan(
		&dom.ID,
		&dom.TenantID,
		&dom.Domain,
		&dom.VerificationTxt,
		&dom.Verified,
		&verifiedAt,
		&dom.CreatedAt,
		&dom.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan domain: %w", err)
	}
	if verifiedAt.Valid {
		dom.VerifiedAt = &verifiedAt.Time
	}
	return &dom, nil
}

func (d *DB) scanDomainRow(rows *sql.Rows) (*Domain, error) {
	var dom Domain
	var verifiedAt sql.NullTime

	err := rows.Scan(
		&dom.ID,
		&dom.TenantID,
		&dom.Domain,
		&dom.VerificationTxt,
		&dom.Verified,
		&verifiedAt,
		&dom.CreatedAt,
		&dom.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to scan domain row: %w", err)
	}
	if verifiedAt.Valid {
		dom.VerifiedAt = &verifiedAt.Time
	}
	return &dom, nil
}

// GetVerifiedDomains returns all verified domains with auto_scan enabled
func (d *DB) GetVerifiedDomains() ([]*Domain, error) {
	query := `
		SELECT id, tenant_id, domain, verification_txt, verified, verified_at, created_at, updated_at
		FROM domains WHERE verified = 1 AND auto_scan_enabled = 1
	`

	rows, err := d.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to get verified domains: %w", err)
	}
	defer rows.Close()

	var domains []*Domain
	for rows.Next() {
		dom, err := d.scanDomainRow(rows)
		if err != nil {
			return nil, err
		}
		domains = append(domains, dom)
	}
	return domains, nil
}

// UpdateDomainLastScanned updates the last_scanned_at timestamp for a domain
func (d *DB) UpdateDomainLastScanned(domainID int64) error {
	_, err := d.Exec(`UPDATE domains SET last_scanned_at = ?, updated_at = ? WHERE id = ?`, time.Now(), time.Now(), domainID)
	if err != nil {
		return fmt.Errorf("failed to update domain last scanned: %w", err)
	}
	return nil
}

// HasUnreadCertNotification checks if an unread cert notification already exists for a domain
func (d *DB) HasUnreadCertNotification(tenantID int64, domain string) (bool, error) {
	var count int
	err := d.QueryRow(`
		SELECT COUNT(*) FROM notifications
		WHERE tenant_id = ? AND notification_type = 'cert_expiry' AND status = 'unread'
		AND message LIKE ?
	`, tenantID, "%"+domain+"%").Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check cert notification: %w", err)
	}
	return count > 0, nil
}
