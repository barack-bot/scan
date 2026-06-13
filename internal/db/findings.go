package db

import (
	"database/sql"
	"fmt"
	"time"
)

// CreateFinding adds a vulnerability finding to a scan
func (d *DB) CreateFinding(scanID int64, title, description, severity, category, remediation, evidence string, cveID, odpcSection *string) (*Finding, error) {
	return d.CreateFindingFull(scanID, title, description, severity, 50, category, remediation, evidence, cveID, odpcSection, "", "")
}

// CreateFindingFull adds a vulnerability finding with all fields
func (d *DB) CreateFindingFull(scanID int64, title, description, severity string, confidence int, category, remediation, evidence string, cveID, odpcSection *string, affectedComponent, status string) (*Finding, error) {
	if status == "" {
		status = "open"
	}
	if confidence == 0 {
		confidence = 50
	}
	query := `
		INSERT INTO findings (scan_id, title, description, severity, confidence, category, cve_id, odpc_section, affected_component, remediation, evidence, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	result, err := d.Exec(query, scanID, title, description, severity, confidence, category, cveID, odpcSection, affectedComponent, remediation, evidence, status)
	if err != nil {
		return nil, fmt.Errorf("failed to create finding: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get finding ID: %w", err)
	}

	now := time.Now()
	return &Finding{
		ID:                id,
		ScanID:            scanID,
		Title:             title,
		Description:       description,
		Severity:          severity,
		Confidence:        confidence,
		Category:          category,
		CVEID:             cveID,
		ODPCSection:       odpcSection,
		AffectedComponent: affectedComponent,
		Remediation:       remediation,
		Evidence:          evidence,
		Status:            status,
		CreatedAt:         now,
		UpdatedAt:         now,
	}, nil
}

// GetFindingsByScanID retrieves all findings for a specific scan
func (d *DB) GetFindingsByScanID(scanID int64) ([]*Finding, error) {
	query := `
		SELECT id, scan_id, title, description, severity, confidence, category, cve_id, odpc_section,
		       affected_component, remediation, evidence, status, resolved_at, resolved_by,
		       created_at, updated_at
		FROM findings WHERE scan_id = ? ORDER BY 
			CASE severity
				WHEN 'critical' THEN 1
				WHEN 'high' THEN 2
				WHEN 'medium' THEN 3
				WHEN 'low' THEN 4
				ELSE 5
			END
	`

	rows, err := d.Query(query, scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to get findings: %w", err)
	}
	defer rows.Close()

	return d.scanFindings(rows)
}

// GetFindingsBySeverity returns findings of a specific severity level
func (d *DB) GetFindingsBySeverity(scanID int64, severity string) ([]*Finding, error) {
	query := `
		SELECT id, scan_id, title, description, severity, confidence, category, cve_id, odpc_section,
		       affected_component, remediation, evidence, status, resolved_at, resolved_by,
		       created_at, updated_at
		FROM findings WHERE scan_id = ? AND severity = ?
	`

	rows, err := d.Query(query, scanID, severity)
	if err != nil {
		return nil, fmt.Errorf("failed to get findings by severity: %w", err)
	}
	defer rows.Close()

	return d.scanFindings(rows)
}

// GetComplianceFindings returns only ODPC compliance-related findings
func (d *DB) GetComplianceFindings(scanID int64) ([]*Finding, error) {
	query := `
		SELECT id, scan_id, title, description, severity, confidence, category, cve_id, odpc_section,
		       affected_component, remediation, evidence, status, resolved_at, resolved_by,
		       created_at, updated_at
		FROM findings WHERE scan_id = ? AND category = 'odpc_compliance'
	`

	rows, err := d.Query(query, scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to get compliance findings: %w", err)
	}
	defer rows.Close()

	return d.scanFindings(rows)
}

// GetFindingsSummary returns counts by severity for a scan
func (d *DB) GetFindingsSummary(scanID int64) (map[string]int, error) {
	query := `
		SELECT severity, COUNT(*) as count
		FROM findings
		WHERE scan_id = ?
		GROUP BY severity
	`

	rows, err := d.Query(query, scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to get summary: %w", err)
	}
	defer rows.Close()

	summary := make(map[string]int)
	for rows.Next() {
		var severity string
		var count int
		if err := rows.Scan(&severity, &count); err != nil {
			return nil, fmt.Errorf("failed to scan summary: %w", err)
		}
		summary[severity] = count
	}

	return summary, nil
}

// GetFindingsSummaryByTenant returns severity counts across all scans for a tenant
func (d *DB) GetFindingsSummaryByTenant(tenantID int64) (map[string]int, error) {
	query := `
		SELECT f.severity, COUNT(*) as count
		FROM findings f
		JOIN scans s ON f.scan_id = s.id
		WHERE s.tenant_id = ?
		GROUP BY f.severity
	`

	rows, err := d.Query(query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant summary: %w", err)
	}
	defer rows.Close()

	summary := make(map[string]int)
	for rows.Next() {
		var severity string
		var count int
		if err := rows.Scan(&severity, &count); err != nil {
			return nil, fmt.Errorf("failed to scan tenant summary: %w", err)
		}
		summary[severity] = count
	}

	return summary, nil
}

// GetFindingCount returns the number of findings for a specific scan
func (d *DB) GetFindingCount(scanID int64) (int, error) {
	row := d.QueryRow(`SELECT COUNT(*) FROM findings WHERE scan_id = ?`, scanID)
	var count int
	if err := row.Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to count findings: %w", err)
	}
	return count, nil
}

// UpdateFindingStatus changes a finding's status (open, acknowledged, resolved)
func (d *DB) UpdateFindingStatus(findingID int64, status string, userID *int64) error {
	now := time.Now()
	var query string
	if status == "resolved" {
		query = `UPDATE findings SET status = ?, resolved_at = ?, resolved_by = ?, updated_at = ? WHERE id = ?`
		_, err := d.Exec(query, status, now, userID, now, findingID)
		if err != nil {
			return fmt.Errorf("failed to update finding status: %w", err)
		}
	} else {
		query = `UPDATE findings SET status = ?, updated_at = ? WHERE id = ?`
		_, err := d.Exec(query, status, now, findingID)
		if err != nil {
			return fmt.Errorf("failed to update finding status: %w", err)
		}
	}
	return nil
}

// AutoReopenResolvedFindings checks if previously resolved findings reappear in a new scan.
// When the same CVE or title+category is found again, it reopens the finding.
// Returns the list of reopened finding IDs.
func (d *DB) AutoReopenResolvedFindings(scanID int64, tenantID int64) ([]int64, error) {
	// Bind all parameters once — avoids fragile positional parameter duplication
	// that could break if query structure changes.
	rows, err := d.Query(`
		SELECT DISTINCT new_f.id
		FROM findings new_f
		JOIN scans new_s ON new_f.scan_id = new_s.id
		WHERE new_s.tenant_id = ?
		  AND new_f.scan_id = ?
		  AND new_f.status IN ('open', 'acknowledged')
		  AND (
			(new_f.cve_id IS NOT NULL AND new_f.cve_id != '' AND EXISTS (
				SELECT 1 FROM findings old_f
				JOIN scans old_s ON old_f.scan_id = old_s.id
				WHERE old_s.tenant_id = ?
				  AND old_f.status = 'resolved'
				  AND old_f.cve_id = new_f.cve_id
			))
			OR
			EXISTS (
				SELECT 1 FROM findings old_f
				JOIN scans old_s ON old_f.scan_id = old_s.id
				WHERE old_s.tenant_id = ?
				  AND old_f.status = 'resolved'
				  AND old_f.title = new_f.title
				  AND old_f.category = new_f.category
			)
		  )
	`, tenantID, scanID, tenantID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to query reopenable findings: %w", err)
	}
	defer rows.Close()

	var reopenedIDs []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan reopened finding ID: %w", err)
		}
		reopenedIDs = append(reopenedIDs, id)
	}

	if len(reopenedIDs) == 0 {
		return nil, nil
	}

	// Mark the previously resolved findings as reopened (set back to 'open')
	// Use a single well-known scanID parameter for all the inner queries
	_, err = d.Exec(`
		UPDATE findings SET status = 'open', resolved_at = NULL, resolved_by = NULL, updated_at = ?
		WHERE id IN (
			SELECT old_f.id FROM findings old_f
			JOIN scans old_s ON old_f.scan_id = old_s.id
			WHERE old_s.tenant_id = ?
			  AND old_f.status = 'resolved'
			  AND (
				(old_f.cve_id IS NOT NULL AND old_f.cve_id != '' AND old_f.cve_id IN (
					SELECT new_f.cve_id FROM findings new_f
					WHERE new_f.scan_id = ? AND new_f.cve_id IS NOT NULL AND new_f.cve_id != ''
				))
				OR
				(old_f.title IN (
					SELECT new_f.title FROM findings new_f
					WHERE new_f.scan_id = ?
				) AND old_f.category IN (
					SELECT new_f.category FROM findings new_f
					WHERE new_f.scan_id = ?
				))
			  )
		)
	`, time.Now(), tenantID, scanID, scanID, scanID)
	if err != nil {
		return nil, fmt.Errorf("failed to reopen findings: %w", err)
	}

	return reopenedIDs, nil
}

// GetTenantFindingsByCVE returns all findings matching a specific CVE across all scans for a tenant
func (d *DB) GetTenantFindingsByCVE(tenantID int64, cveID string) ([]*Finding, error) {
	query := `
		SELECT f.id, f.scan_id, f.title, f.description, f.severity, f.confidence, f.cve_id, f.odpc_section,
		       f.affected_component, f.category, f.remediation, f.evidence, f.status, f.resolved_at, f.resolved_by,
		       f.created_at, f.updated_at
		FROM findings f
		JOIN scans s ON f.scan_id = s.id
		WHERE s.tenant_id = ? AND f.cve_id = ?
		ORDER BY f.created_at DESC
	`

	rows, err := d.Query(query, tenantID, cveID)
	if err != nil {
		return nil, fmt.Errorf("failed to get findings by CVE: %w", err)
	}
	defer rows.Close()

	return d.scanFindings(rows)
}

// GetTenantFindingsBySeverity returns findings of a given severity across all scans for a tenant
func (d *DB) GetTenantFindingsBySeverity(tenantID int64, severity string) ([]*Finding, error) {
	query := `
		SELECT f.id, f.scan_id, f.title, f.description, f.severity, f.confidence, f.cve_id, f.odpc_section,
		       f.affected_component, f.category, f.remediation, f.evidence, f.status, f.resolved_at, f.resolved_by,
		       f.created_at, f.updated_at
		FROM findings f
		JOIN scans s ON f.scan_id = s.id
		WHERE s.tenant_id = ? AND f.severity = ?
		ORDER BY f.created_at DESC
	`

	rows, err := d.Query(query, tenantID, severity)
	if err != nil {
		return nil, fmt.Errorf("failed to get findings by severity: %w", err)
	}
	defer rows.Close()

	return d.scanFindings(rows)
}

// GetOpenFindingsCount returns the number of open findings for a tenant
func (d *DB) GetOpenFindingsCount(tenantID int64) (int, error) {
	row := d.QueryRow(`
		SELECT COUNT(*) FROM findings f
		JOIN scans s ON f.scan_id = s.id
		WHERE s.tenant_id = ? AND f.status = 'open'
	`, tenantID)
	var count int
	if err := row.Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to count open findings: %w", err)
	}
	return count, nil
}

// CreateNotification creates a notification record
func (d *DB) CreateNotification(tenantID *int64, userID *int64, notifType, title, message string, findingID, scanID *int64) error {
	_, err := d.Exec(`
		INSERT INTO notifications (tenant_id, user_id, notification_type, title, message, finding_id, scan_id, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, 'unread')
	`, tenantID, userID, notifType, title, message, findingID, scanID)
	if err != nil {
		return fmt.Errorf("failed to create notification: %w", err)
	}
	return nil
}

// GetUnreadNotifications returns unread notifications for a tenant
func (d *DB) GetUnreadNotifications(tenantID int64) ([]*Notification, error) {
	rows, err := d.Query(`
		SELECT id, tenant_id, user_id, notification_type, title, message, finding_id, scan_id, status, created_at
		FROM notifications WHERE tenant_id = ? AND status = 'unread'
		ORDER BY created_at DESC
	`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get notifications: %w", err)
	}
	defer rows.Close()

	var notifs []*Notification
	for rows.Next() {
		var n Notification
		if err := rows.Scan(&n.ID, &n.TenantID, &n.UserID, &n.Type, &n.Title, &n.Message,
			&n.FindingID, &n.ScanID, &n.Status, &n.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan notification: %w", err)
		}
		notifs = append(notifs, &n)
	}
	return notifs, nil
}

// MarkNotificationRead marks a notification as read
func (d *DB) MarkNotificationRead(id int64) error {
	_, err := d.Exec(`UPDATE notifications SET status = 'read', read_at = ? WHERE id = ?`, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to mark notification read: %w", err)
	}
	return nil
}

// GetScheduledScansDue returns scheduled scans that are due to run
func (d *DB) GetScheduledScansDue() ([]*ScheduledScan, error) {
	rows, err := d.Query(`
		SELECT ss.id, ss.tenant_id, ss.domain_id, ss.scan_type, ss.frequency, ss.next_run_at,
		       ss.last_run_at, ss.enabled, ss.last_scan_id
		FROM scheduled_scans ss
		JOIN domains d ON ss.domain_id = d.id
		WHERE ss.enabled = 1 AND ss.next_run_at <= ? AND d.verified = 1
		ORDER BY ss.next_run_at ASC
	`, time.Now())
	if err != nil {
		return nil, fmt.Errorf("failed to get due scheduled scans: %w", err)
	}
	defer rows.Close()

	var scans []*ScheduledScan
	for rows.Next() {
		var s ScheduledScan
		var lastRunAt sql.NullTime
		var lastScanID sql.NullInt64
		if err := rows.Scan(&s.ID, &s.TenantID, &s.DomainID, &s.ScanType, &s.Frequency, &s.NextRunAt,
			&lastRunAt, &s.Enabled, &lastScanID); err != nil {
			return nil, fmt.Errorf("failed to scan scheduled scan: %w", err)
		}
		if lastRunAt.Valid {
			s.LastRunAt = &lastRunAt.Time
		}
		if lastScanID.Valid {
			s.LastScanID = &lastScanID.Int64
		}
		scans = append(scans, &s)
	}
	return scans, nil
}

// UpdateScheduledScanAfterRun updates a scheduled scan after it executes
func (d *DB) UpdateScheduledScanAfterRun(id int64, lastScanID int64, nextRunAt time.Time) error {
	_, err := d.Exec(`
		UPDATE scheduled_scans SET last_run_at = ?, last_scan_id = ?, next_run_at = ?, updated_at = ?
		WHERE id = ?
	`, time.Now(), lastScanID, nextRunAt, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to update scheduled scan: %w", err)
	}
	return nil
}

// --- Helper types ---

// Notification represents an alert/notification record
type Notification struct {
	ID        int64     `json:"id"`
	TenantID  int64     `json:"tenant_id"`
	UserID    *int64    `json:"user_id,omitempty"`
	Type      string    `json:"notification_type"`
	Title     string    `json:"title"`
	Message   string    `json:"message"`
	FindingID *int64    `json:"finding_id,omitempty"`
	ScanID    *int64    `json:"scan_id,omitempty"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

// ScheduledScan represents a recurring scan job
type ScheduledScan struct {
	ID         int64      `json:"id"`
	TenantID   int64      `json:"tenant_id"`
	DomainID   int64      `json:"domain_id"`
	ScanType   string     `json:"scan_type"`
	Frequency  string     `json:"frequency"`
	NextRunAt  time.Time  `json:"next_run_at"`
	LastRunAt  *time.Time `json:"last_run_at,omitempty"`
	Enabled    bool       `json:"enabled"`
	LastScanID *int64     `json:"last_scan_id,omitempty"`
}

// --- Internal helpers ---

func (d *DB) scanFindings(rows *sql.Rows) ([]*Finding, error) {
	var findings []*Finding
	for rows.Next() {
		var f Finding
		var cveID, odpcSection sql.NullString
		var resolvedAt sql.NullTime
		var resolvedBy sql.NullInt64
		var updatedAt time.Time

		err := rows.Scan(
			&f.ID, &f.ScanID, &f.Title, &f.Description, &f.Severity, &f.Confidence,
			&cveID, &odpcSection, &f.AffectedComponent, &f.Category,
			&f.Remediation, &f.Evidence, &f.Status, &resolvedAt, &resolvedBy,
			&f.CreatedAt, &updatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan finding: %w", err)
		}
		if cveID.Valid {
			f.CVEID = &cveID.String
		}
		if odpcSection.Valid {
			f.ODPCSection = &odpcSection.String
		}
		if resolvedAt.Valid {
			f.ResolvedAt = &resolvedAt.Time
		}
		if resolvedBy.Valid {
			f.ResolvedBy = &resolvedBy.Int64
		}
		f.UpdatedAt = updatedAt
		findings = append(findings, &f)
	}
	return findings, nil
}
