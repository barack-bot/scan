package db

import (
	"database/sql"
	"fmt"
	"time"
)

// CreateScan creates a new scan job
func (d *DB) CreateScan(tenantID int64, targetURL, scanType string) (*Scan, error) {
	query := `
		INSERT INTO scans (tenant_id, target_url, status, scan_type, progress, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`

	now := time.Now()
	result, err := d.Exec(query, tenantID, targetURL, "pending", scanType, 0, now)
	if err != nil {
		return nil, fmt.Errorf("failed to create scan: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get scan ID: %w", err)
	}

	return &Scan{
		ID:        id,
		TenantID:  tenantID,
		TargetURL: targetURL,
		Status:    "pending",
		ScanType:  scanType,
		Progress:  0,
		CreatedAt: now,
	}, nil
}

// GetScan retrieves a scan by ID
func (d *DB) GetScan(id int64) (*Scan, error) {
	query := `
		SELECT id, tenant_id, target_url, status, scan_type, progress, started_at, completed_at, created_at
		FROM scans WHERE id = ?
	`

	var scan Scan
	var startedAt, completedAt sql.NullTime // Handle NULL values

	err := d.QueryRow(query, id).Scan(
		&scan.ID,
		&scan.TenantID,
		&scan.TargetURL,
		&scan.Status,
		&scan.ScanType,
		&scan.Progress,
		&startedAt,
		&completedAt,
		&scan.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get scan: %w", err)
	}

	// Convert NULL times to nil pointers
	if startedAt.Valid {
		scan.StartedAt = &startedAt.Time
	}
	if completedAt.Valid {
		scan.CompletedAt = &completedAt.Time
	}

	return &scan, nil
}

// UpdateScanStatus changes a scan's status and optionally sets timestamps
func (d *DB) UpdateScanStatus(id int64, status string, progress int) error {
	query := `UPDATE scans SET status = ?, progress = ?, updated_at = ? WHERE id = ?`

	result, err := d.Exec(query, status, progress, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to update scan status: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("scan with id %d not found", id)
	}

	return nil
}

// StartScan marks a scan as running with start time
func (d *DB) StartScan(id int64) error {
	now := time.Now()
	query := `UPDATE scans SET status = 'running', started_at = ?, updated_at = ? WHERE id = ? AND status = 'pending'`

	result, err := d.Exec(query, now, now, id)
	if err != nil {
		return fmt.Errorf("failed to start scan: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("scan %d not found or already started", id)
	}

	return nil
}

// CompleteScan marks a scan as finished
func (d *DB) CompleteScan(id int64) error {
	now := time.Now()
	query := `UPDATE scans SET status = 'completed', progress = 100, completed_at = ?, updated_at = ? WHERE id = ?`

	result, err := d.Exec(query, now, now, id)
	if err != nil {
		return fmt.Errorf("failed to complete scan: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("scan with id %d not found", id)
	}

	return nil
}

// ListTenantScans returns all scans for a specific tenant
func (d *DB) ListTenantScans(tenantID int64, limit, offset int) ([]*Scan, error) {
	query := `
		SELECT id, tenant_id, target_url, status, scan_type, progress, started_at, completed_at, created_at
		FROM scans WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?
	`

	rows, err := d.Query(query, tenantID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list scans: %w", err)
	}
	defer rows.Close()

	var scans []*Scan
	for rows.Next() {
		var scan Scan
		var startedAt, completedAt sql.NullTime

		err := rows.Scan(
			&scan.ID,
			&scan.TenantID,
			&scan.TargetURL,
			&scan.Status,
			&scan.ScanType,
			&scan.Progress,
			&startedAt,
			&completedAt,
			&scan.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan scan row: %w", err)
		}

		if startedAt.Valid {
			scan.StartedAt = &startedAt.Time
		}
		if completedAt.Valid {
			scan.CompletedAt = &completedAt.Time
		}

		scans = append(scans, &scan)
	}

	return scans, nil
}
