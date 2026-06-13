package db

import (
	"database/sql"
	"fmt"
	"time"
)

// CreateTenant adds a new organization
func (d *DB) CreateTenant(name, domain, plan, odpcNumber string) (*Tenant, error) {
	query := `
		INSERT INTO tenants (name, domain, plan, odpc_number, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`

	now := time.Now()
	result, err := d.Exec(query, name, domain, plan, odpcNumber, now, now)
	if err != nil {
		return nil, fmt.Errorf("failed to create tenant: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant ID: %w", err)
	}

	return &Tenant{
		ID:                 id,
		Name:               name,
		Domain:             domain,
		Plan:               plan,
		ODPCNumber:         odpcNumber,
		SubscriptionStatus: "trial",
		ScanLimit:          3,
		ScanCountThisMonth: 0,
		CreatedAt:          now,
		UpdatedAt:          now,
	}, nil
}

// GetTenantByDomain retrieves a tenant by their domain
func (d *DB) GetTenantByDomain(domain string) (*Tenant, error) {
	query := `SELECT id, name, domain, plan, odpc_number, subscription_status, scan_limit, scan_count_this_month, last_billing_date, trial_expires_at, created_at, updated_at FROM tenants WHERE domain = ?`

	var tenant Tenant
	var lastBillingDate, trialExpiresAt sql.NullTime
	err := d.QueryRow(query, domain).Scan(
		&tenant.ID,
		&tenant.Name,
		&tenant.Domain,
		&tenant.Plan,
		&tenant.ODPCNumber,
		&tenant.SubscriptionStatus,
		&tenant.ScanLimit,
		&tenant.ScanCountThisMonth,
		&lastBillingDate,
		&trialExpiresAt,
		&tenant.CreatedAt,
		&tenant.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant: %w", err)
	}
	if lastBillingDate.Valid {
		tenant.LastBillingDate = &lastBillingDate.Time
	}
	if trialExpiresAt.Valid {
		tenant.TrialExpiresAt = &trialExpiresAt.Time
	}

	return &tenant, nil
}

// GetTenantByID retrieves a tenant by ID
func (d *DB) GetTenantByID(id int64) (*Tenant, error) {
	query := `SELECT id, name, domain, plan, odpc_number, subscription_status, scan_limit, scan_count_this_month, last_billing_date, trial_expires_at, created_at, updated_at FROM tenants WHERE id = ?`

	var tenant Tenant
	var lastBillingDate, trialExpiresAt sql.NullTime
	err := d.QueryRow(query, id).Scan(
		&tenant.ID,
		&tenant.Name,
		&tenant.Domain,
		&tenant.Plan,
		&tenant.ODPCNumber,
		&tenant.SubscriptionStatus,
		&tenant.ScanLimit,
		&tenant.ScanCountThisMonth,
		&lastBillingDate,
		&trialExpiresAt,
		&tenant.CreatedAt,
		&tenant.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant: %w", err)
	}
	if lastBillingDate.Valid {
		tenant.LastBillingDate = &lastBillingDate.Time
	}
	if trialExpiresAt.Valid {
		tenant.TrialExpiresAt = &trialExpiresAt.Time
	}

	return &tenant, nil
}

// UpdateTenantPlan changes a tenant's subscription plan
func (d *DB) UpdateTenantPlan(id int64, newPlan string) error {
	query := `UPDATE tenants SET plan = ?, updated_at = ? WHERE id = ?`

	result, err := d.Exec(query, newPlan, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to update plan: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("tenant with id %d not found", id)
	}

	return nil
}

// CheckScanQuota returns true if the tenant can perform another scan this month
func (d *DB) CheckScanQuota(tenantID int64) (bool, error) {
	var scanLimit int
	var count int
	var status string
	err := d.QueryRow(`SELECT scan_limit, scan_count_this_month, subscription_status FROM tenants WHERE id = ?`, tenantID).Scan(
		&scanLimit, &count, &status,
	)
	if err != nil {
		return false, fmt.Errorf("failed to check quota: %w", err)
	}
	if status == "suspended" || status == "cancelled" {
		return false, nil
	}
	if scanLimit == -1 {
		return true, nil
	}
	return count < scanLimit, nil
}

// IncrementScanCount increments the scan counter for the tenant
func (d *DB) IncrementScanCount(tenantID int64) error {
	_, err := d.Exec(`UPDATE tenants SET scan_count_this_month = scan_count_this_month + 1, updated_at = ? WHERE id = ?`, time.Now(), tenantID)
	if err != nil {
		return fmt.Errorf("failed to increment scan count: %w", err)
	}
	return nil
}

// UpdateTenantSubscription updates subscription status and related fields
func (d *DB) UpdateTenantSubscription(id int64, status string, trialExpiry *time.Time) error {
	_, err := d.Exec(`UPDATE tenants SET subscription_status = ?, trial_expires_at = ?, updated_at = ? WHERE id = ?`, status, trialExpiry, time.Now(), id)
	if err != nil {
		return fmt.Errorf("failed to update subscription: %w", err)
	}
	return nil
}

// ListTenants returns a list of tenants with pagination.
func (d *DB) ListTenants(limit, offset int) ([]*Tenant, error) {
	rows, err := d.Query(`
		SELECT id, name, domain, plan, odpc_number, subscription_status, scan_limit, scan_count_this_month, last_billing_date, trial_expires_at, created_at, updated_at
		FROM tenants ORDER BY created_at DESC LIMIT ? OFFSET ?
	`, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list tenants: %w", err)
	}
	defer rows.Close()

	var tenants []*Tenant
	for rows.Next() {
		var tenant Tenant
		var lastBillingDate, trialExpiresAt sql.NullTime
		if err := rows.Scan(&tenant.ID, &tenant.Name, &tenant.Domain, &tenant.Plan, &tenant.ODPCNumber, &tenant.SubscriptionStatus, &tenant.ScanLimit, &tenant.ScanCountThisMonth, &lastBillingDate, &trialExpiresAt, &tenant.CreatedAt, &tenant.UpdatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan tenant: %w", err)
		}
		if lastBillingDate.Valid {
			tenant.LastBillingDate = &lastBillingDate.Time
		}
		if trialExpiresAt.Valid {
			tenant.TrialExpiresAt = &trialExpiresAt.Time
		}
		tenants = append(tenants, &tenant)
	}

	return tenants, nil
}

// DeleteTenant removes a tenant by ID. Used for rollback when user creation fails during registration.
func (d *DB) DeleteTenant(id int64) error {
	_, err := d.Exec(`DELETE FROM tenants WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed to delete tenant: %w", err)
	}
	return nil
}

// GetTenantScansCount returns number of scans a tenant has run (for billing)
func (d *DB) GetTenantScansCount(tenantID int64, since time.Time) (int, error) {
	query := `SELECT COUNT(*) FROM scans WHERE tenant_id = ? AND created_at > ?`

	var count int
	err := d.QueryRow(query, tenantID, since).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count scans: %w", err)
	}

	return count, nil
}
