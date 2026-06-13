package db

import (
	"fmt"
	"time"
)

// AuditLog represents a system audit entry
type AuditLog struct {
	ID        int64     `json:"id"`
	TenantID  *int64    `json:"tenant_id,omitempty"` // NULL for system actions
	UserID    *int64    `json:"user_id,omitempty"`   // NULL for system actions
	Action    string    `json:"action"`              // e.g., "login", "scan_started"
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	Details   *string   `json:"details,omitempty"` // JSON string with extra data
	CreatedAt time.Time `json:"created_at"`
}

// CreateAuditLog records an action for compliance tracking
func (d *DB) CreateAuditLog(tenantID, userID *int64, action, ipAddress, userAgent string, details *string) error {
	query := `
		INSERT INTO audit_logs (tenant_id, user_id, action, ip_address, user_agent, details)
		VALUES (?, ?, ?, ?, ?, ?)
	`

	_, err := d.Exec(query, tenantID, userID, action, ipAddress, userAgent, details)
	if err != nil {
		return fmt.Errorf("failed to create audit log: %w", err)
	}

	return nil
}

// GetAuditLogs returns audit logs for a tenant with pagination
func (d *DB) GetAuditLogs(tenantID int64, limit, offset int) ([]*AuditLog, error) {
	query := `
		SELECT id, tenant_id, user_id, action, ip_address, user_agent, details, created_at
		FROM audit_logs
		WHERE tenant_id = ?
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?
	`

	rows, err := d.Query(query, tenantID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to get audit logs: %w", err)
	}
	defer rows.Close()

	var logs []*AuditLog
	for rows.Next() {
		var log AuditLog
		err := rows.Scan(
			&log.ID,
			&log.TenantID,
			&log.UserID,
			&log.Action,
			&log.IPAddress,
			&log.UserAgent,
			&log.Details,
			&log.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan audit log: %w", err)
		}
		logs = append(logs, &log)
	}

	return logs, nil
}
