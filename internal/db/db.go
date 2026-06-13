// Package db handles all database operations for KE-SCAN
package db

import (
	"database/sql" // Go's standard SQL interface
	"fmt"          // For formatting error messages
	"log"          // For logging database events
	"time"         // For working with timestamps

	"ke-scan/config" // Our config package for database settings

	_ "github.com/mattn/go-sqlite3" // SQLite driver (underscore = import for side effects only)
)

// DB wraps the database connection with our custom methods
type DB struct {
	*sql.DB                // Embedded SQL connection (can call db.Query() directly)
	Config  *config.Config // App configuration
}

// User represents a registered user in the system
type User struct {
	ID        int64     `json:"id"`         // Unique user ID, maps to "id" in JSON
	Email     string    `json:"email"`      // User's email address (used for login)
	Password  string    `json:"-"`          // Hashed password (never send in JSON)
	Name      string    `json:"name"`       // User's full name
	Role      string    `json:"role"`       // admin, user, or enterprise
	TenantID  *int64    `json:"tenant_id"`  // Which tenant this user belongs to (nil = no tenant)
	CreatedAt time.Time `json:"created_at"` // When account was created
	UpdatedAt time.Time `json:"updated_at"` // Last profile update
}

// Tenant represents an organization (multi-tenant support)
type Tenant struct {
	ID                 int64      `json:"id"`                    // Unique tenant ID
	Name               string     `json:"name"`                  // Organization name
	Domain             string     `json:"domain"`                // Organization's domain
	Plan               string     `json:"plan"`                  // Subscription: free, business, enterprise
	ODPCNumber         string     `json:"odpc_number"`           // ODPC registration number
	SubscriptionStatus string     `json:"subscription_status"`   // trial, active, suspended, cancelled
	ScanLimit          int        `json:"scan_limit"`            // Max scans per month (-1 = unlimited)
	ScanCountThisMonth int        `json:"scan_count_this_month"` // Scans used this billing period
	LastBillingDate    *time.Time `json:"last_billing_date,omitempty"`
	TrialExpiresAt     *time.Time `json:"trial_expires_at,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

// Scan represents a security scanning job
type Scan struct {
	ID          int64      `json:"id"`                     // Unique scan ID
	TenantID    int64      `json:"tenant_id"`              // Which organization owns this scan
	DomainID    int64      `json:"domain_id"`              // Linked domain (0 = none)
	TargetURL   string     `json:"target_url"`             // Website to scan (e.g., "https://example.com")
	Status      string     `json:"status"`                 // pending, running, completed, failed
	ScanType    string     `json:"scan_type"`              // full, quick, compliance_only
	Progress    int        `json:"progress"`               // Percentage complete (0-100)
	StartedAt   *time.Time `json:"started_at,omitempty"`   // When scan began (pointer = can be null)
	CompletedAt *time.Time `json:"completed_at,omitempty"` // When scan finishes (pointer = can be null)
	CreatedAt   time.Time  `json:"created_at"`             // When scan was scheduled
}

// Finding represents a vulnerability or compliance issue discovered during a scan
type Finding struct {
	ID                int64      `json:"id"`                     // Unique finding ID
	ScanID            int64      `json:"scan_id"`                // Which scan found this issue
	Title             string     `json:"title"`                  // Short description
	Description       string     `json:"description"`            // Detailed explanation
	Severity          string     `json:"severity"`               // critical, high, medium, low, info
	Confidence        int        `json:"confidence"`             // 0-100 confidence score
	CVEID             *string    `json:"cve_id,omitempty"`       // CVE identifier
	ODPCSection       *string    `json:"odpc_section,omitempty"` // DPA section reference
	AffectedComponent string     `json:"affected_component"`     // e.g., "Apache 2.4.49"
	Category          string     `json:"category"`               // cve, odpc_compliance, tls, headers, dns
	Remediation       string     `json:"remediation"`            // Steps to fix
	Evidence          string     `json:"evidence"`               // Proof of the finding
	Status            string     `json:"status"`                 // open, acknowledged, resolved
	ResolvedAt        *time.Time `json:"resolved_at,omitempty"`  // When marked resolved
	ResolvedBy        *int64     `json:"resolved_by,omitempty"`  // User who resolved it
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

// New creates a new database connection and runs migrations
func New(cfg *config.Config) (*DB, error) {
	// Open SQLite database using path from config
	db, err := sql.Open("sqlite3", cfg.GetDSN())
	if err != nil {
		// Return nil for DB and the wrapped error
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool limits (prevents too many connections)
	db.SetMaxOpenConns(cfg.Database.MaxOpenConns) // Max 25 connections at once
	db.SetMaxIdleConns(cfg.Database.MaxIdleConns) // Keep 5 idle connections ready

	// Test the connection is actually alive
	if err := db.Ping(); err != nil {
		db.Close() // Clean up if ping fails
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Wrap the raw connection in our DB struct
	database := &DB{
		DB:     db,  // Embedded sql.DB connection
		Config: cfg, // Store config for later use
	}

	// Enable foreign key constraints for SQLite
	if _, err := db.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	// Create tables if they don't exist
	if err := database.runMigrations(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	// Ensure at least one tenant exists so scans can be assigned correctly
	if err := database.ensureDefaultTenant(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ensure default tenant: %w", err)
	}

	log.Println("Database connected successfully")
	return database, nil
}

// ensureDefaultTenant creates a fallback tenant when none exist.
func (d *DB) ensureDefaultTenant() error {
	var count int
	row := d.QueryRow(`SELECT COUNT(*) FROM tenants`)
	if err := row.Scan(&count); err != nil {
		return fmt.Errorf("failed to count tenants: %w", err)
	}

	if count > 0 {
		return nil
	}

	_, err := d.CreateTenant("KE-SCAN Default Tenant", "default.ke-scan.local", "free", "")
	if err != nil {
		return fmt.Errorf("failed to create default tenant: %w", err)
	}

	log.Println("Created default tenant for scan operations")
	return nil
}

// Close gracefully closes the database connection
func (d *DB) Close() error {
	log.Println("Closing database connection")
	return d.DB.Close() // Call the embedded sql.DB's Close method
}

// runMigrations creates all necessary tables (safe to run multiple times)
func (d *DB) runMigrations() error {
	// Create users table
	// Create tenants table (with plan enforcement columns)
	tenantsTable := `
	CREATE TABLE IF NOT EXISTS tenants (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		domain TEXT NOT NULL UNIQUE,              -- Each tenant needs unique domain
		plan TEXT NOT NULL DEFAULT 'free',        -- Subscription tier: free, business, enterprise
		odpc_number TEXT,                         -- Optional ODPC registration
		subscription_status TEXT NOT NULL DEFAULT 'trial',  -- trial, active, suspended, cancelled
		scan_limit INTEGER NOT NULL DEFAULT 3,    -- Max scans per month (-1 = unlimited)
		scan_count_this_month INTEGER NOT NULL DEFAULT 0,  -- Scans used this billing period
		last_billing_date DATETIME,               -- When current billing cycle started
		trial_expires_at DATETIME,                -- When trial ends (NULL = no trial)
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	);`

	if _, err := d.Exec(tenantsTable); err != nil {
		return fmt.Errorf("tenants table failed: %w", err)
	}

	// Create users table
	usersTable := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,     -- Auto-incrementing ID
		email TEXT NOT NULL UNIQUE,               -- Email must be unique
		password TEXT NOT NULL,                   -- Hashed password (bcrypt)
		name TEXT NOT NULL,                       -- User's full name
		role TEXT NOT NULL DEFAULT 'user',        -- Role with default 'user'
		tenant_id INTEGER,                        -- Which tenant this user belongs to
		active INTEGER NOT NULL DEFAULT 0,        -- 0 = inactive, 1 = active
		activation_token TEXT,                    -- Token for email activation
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE SET NULL
	);`

	if _, err := d.Exec(usersTable); err != nil {
		return fmt.Errorf("users table failed: %w", err)
	}

	// Create domains table (with scan scheduling columns)
	domainsTable := `
	CREATE TABLE IF NOT EXISTS domains (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		tenant_id INTEGER NOT NULL,
		domain TEXT NOT NULL,
		verification_txt TEXT NOT NULL,
		verified INTEGER NOT NULL DEFAULT 0,
		verified_at DATETIME,
		scan_frequency TEXT NOT NULL DEFAULT 'weekly',  -- daily, weekly, monthly
		last_scanned_at DATETIME,                        -- when this domain was last scanned
		next_scan_at DATETIME,                           -- when next scheduled scan should run
		auto_scan_enabled INTEGER NOT NULL DEFAULT 1,    -- 1=enabled, 0=disabled
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
		UNIQUE(tenant_id, domain)
	);`

	if _, err := d.Exec(domainsTable); err != nil {
		return fmt.Errorf("domains table failed: %w", err)
	}

	// Create scans table (with domain_id link)
	scansTable := `
	CREATE TABLE IF NOT EXISTS scans (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		tenant_id INTEGER NOT NULL,               -- Foreign key to tenants
		domain_id INTEGER,                        -- Linked domain (optional)
		target_url TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'pending',   -- pending/running/completed/failed
		scan_type TEXT NOT NULL DEFAULT 'full',   -- full/quick/compliance_only
		progress INTEGER NOT NULL DEFAULT 0,      -- 0 to 100
		started_at DATETIME,                      -- NULL until scan starts
		completed_at DATETIME,                    -- NULL until scan finishes
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
		FOREIGN KEY(domain_id) REFERENCES domains(id) ON DELETE SET NULL
	);`

	if _, err := d.Exec(scansTable); err != nil {
		return fmt.Errorf("scans table failed: %w", err)
	}

	// Create findings table (properly queryable with status workflow)
	findingsTable := `
	CREATE TABLE IF NOT EXISTS findings (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id INTEGER NOT NULL,                 -- Foreign key to scans
		title TEXT NOT NULL,
		description TEXT NOT NULL,
		severity TEXT NOT NULL,                   -- critical/high/medium/low/info
		confidence INTEGER DEFAULT 50,            -- 0-100 confidence score
		cve_id TEXT,                              -- Optional CVE identifier
		odpc_section TEXT,                        -- Optional ODPC section reference
		affected_component TEXT,                  -- e.g., "Apache 2.4.49", "nginx/1.18.0"
		category TEXT NOT NULL,                   -- cve/odpc_compliance/tls/headers/dns
		remediation TEXT NOT NULL,
		evidence TEXT NOT NULL,                   -- Proof of the finding
		status TEXT NOT NULL DEFAULT 'open',      -- open/acknowledged/resolved
		resolved_at DATETIME,                     -- when marked resolved
		resolved_by INTEGER,                      -- user who resolved it
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE,
		FOREIGN KEY(resolved_by) REFERENCES users(id) ON DELETE SET NULL
	);`

	if _, err := d.Exec(findingsTable); err != nil {
		return fmt.Errorf("findings table failed: %w", err)
	}

	// Create audit_logs table (for compliance tracking)
	auditLogsTable := `
	CREATE TABLE IF NOT EXISTS audit_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		tenant_id INTEGER,                        -- Which tenant (NULL for system actions)
		user_id INTEGER,                          -- Which user (NULL for system actions)
		action TEXT NOT NULL,                     -- e.g., "scan_started", "report_downloaded"
		ip_address TEXT NOT NULL,                 -- Client IP address
		user_agent TEXT NOT NULL,                 -- Browser/API client info
		details TEXT,                             -- JSON with additional context
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE SET NULL,
		FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
	);`

	if _, err := d.Exec(auditLogsTable); err != nil {
		return fmt.Errorf("audit_logs table failed: %w", err)
	}

	// Create payments table (M-PESA integration)
	paymentsTable := `
	CREATE TABLE IF NOT EXISTS payments (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		tenant_id INTEGER NOT NULL,
		checkout_request_id TEXT,                 -- M-PESA STK push checkout request ID
		transaction_id TEXT,                       -- M-PESA transaction ID (from callback)
		mpesa_receipt_number TEXT,                 -- Safaricom receipt number (proof of payment)
		merchant_request_id TEXT,                  -- M-PESA merchant request ID
		amount REAL NOT NULL,                     -- amount in KES
		currency TEXT NOT NULL DEFAULT 'KES',
		phone_number TEXT,                         -- M-PESA phone number used
		subscription_id TEXT,                      -- unique subscription identifier
		plan TEXT NOT NULL,                       -- plan purchased
		period_start DATETIME,                    -- billing period start
		period_end DATETIME,                      -- billing period end
		status TEXT NOT NULL DEFAULT 'pending',   -- pending/completed/failed/refunded
		result_code TEXT,                          -- M-PESA result code
		result_desc TEXT,                          -- M-PESA result description
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
	);`

	if _, err := d.Exec(paymentsTable); err != nil {
		return fmt.Errorf("payments table failed: %w", err)
	}

	// Create scheduled_scans table (recurring scan system)
	scheduledScansTable := `
	CREATE TABLE IF NOT EXISTS scheduled_scans (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		tenant_id INTEGER NOT NULL,
		domain_id INTEGER NOT NULL,
		scan_type TEXT NOT NULL DEFAULT 'full',
		frequency TEXT NOT NULL DEFAULT 'weekly',  -- daily, weekly, monthly
		next_run_at DATETIME NOT NULL,
		last_run_at DATETIME,
		enabled INTEGER NOT NULL DEFAULT 1,
		last_scan_id INTEGER,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
		FOREIGN KEY(domain_id) REFERENCES domains(id) ON DELETE CASCADE,
		FOREIGN KEY(last_scan_id) REFERENCES scans(id) ON DELETE SET NULL
	);`

	if _, err := d.Exec(scheduledScansTable); err != nil {
		return fmt.Errorf("scheduled_scans table failed: %w", err)
	}

	// Create notifications table
	notificationsTable := `
	CREATE TABLE IF NOT EXISTS notifications (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		tenant_id INTEGER NOT NULL,
		user_id INTEGER,
		notification_type TEXT NOT NULL,           -- cert_expiry, new_critical_finding, scan_complete, etc.
		title TEXT NOT NULL,
		message TEXT NOT NULL,
		finding_id INTEGER,
		scan_id INTEGER,
		status TEXT NOT NULL DEFAULT 'unread',     -- unread, read, dismissed
		read_at DATETIME,
		dismissed_at DATETIME,
		scheduled_at DATETIME,                     -- when to notify (NULL = immediate)
		sent_at DATETIME,                          -- when actually sent
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
		FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL,
		FOREIGN KEY(finding_id) REFERENCES findings(id) ON DELETE SET NULL,
		FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE SET NULL
	);`

	if _, err := d.Exec(notificationsTable); err != nil {
		return fmt.Errorf("notifications table failed: %w", err)
	}

	// --- Migrations for existing databases: add missing columns ---
	// These are safe to run multiple times; SQLite returns an error
	// "duplicate column name" which we intentionally ignore.
	// MUST run before index creation since indexes reference new columns.
	alterStmts := []string{
		// Tenants: plan enforcement
		`ALTER TABLE tenants ADD COLUMN subscription_status TEXT NOT NULL DEFAULT 'trial'`,
		`ALTER TABLE tenants ADD COLUMN scan_limit INTEGER NOT NULL DEFAULT 3`,
		`ALTER TABLE tenants ADD COLUMN scan_count_this_month INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE tenants ADD COLUMN last_billing_date DATETIME`,
		`ALTER TABLE tenants ADD COLUMN trial_expires_at DATETIME`,

		// Domains: scan scheduling
		`ALTER TABLE domains ADD COLUMN scan_frequency TEXT NOT NULL DEFAULT 'weekly'`,
		`ALTER TABLE domains ADD COLUMN last_scanned_at DATETIME`,
		`ALTER TABLE domains ADD COLUMN next_scan_at DATETIME`,
		`ALTER TABLE domains ADD COLUMN auto_scan_enabled INTEGER NOT NULL DEFAULT 1`,

		// Scans: domain link
		`ALTER TABLE scans ADD COLUMN domain_id INTEGER`,

		// Findings: status workflow
		`ALTER TABLE findings ADD COLUMN confidence INTEGER DEFAULT 50`,
		`ALTER TABLE findings ADD COLUMN affected_component TEXT`,
		`ALTER TABLE findings ADD COLUMN status TEXT NOT NULL DEFAULT 'open'`,
		`ALTER TABLE findings ADD COLUMN resolved_at DATETIME`,
		`ALTER TABLE findings ADD COLUMN resolved_by INTEGER`,
		`ALTER TABLE findings ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP`,
	}

	for _, stmt := range alterStmts {
		_, _ = d.Exec(stmt) // Ignore "duplicate column name" errors
	}

	// Create indexes for better query performance
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);",
		"CREATE INDEX IF NOT EXISTS idx_scans_tenant_id ON scans(tenant_id);",
		"CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);",
		"CREATE INDEX IF NOT EXISTS idx_scans_domain_id ON scans(domain_id);",
		"CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);",
		"CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);",
		"CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);",
		"CREATE INDEX IF NOT EXISTS idx_findings_cve_id ON findings(cve_id);",
		"CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_id ON audit_logs(tenant_id);",
		"CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);",
		"CREATE INDEX IF NOT EXISTS idx_payments_tenant_id ON payments(tenant_id);",
		"CREATE INDEX IF NOT EXISTS idx_payments_receipt ON payments(mpesa_receipt_number);",
		"CREATE INDEX IF NOT EXISTS idx_scheduled_scans_next_run ON scheduled_scans(next_run_at);",
		"CREATE INDEX IF NOT EXISTS idx_scheduled_scans_enabled ON scheduled_scans(enabled);",
		"CREATE INDEX IF NOT EXISTS idx_notifications_tenant_id ON notifications(tenant_id);",
		"CREATE INDEX IF NOT EXISTS idx_notifications_status ON notifications(status);",
		"CREATE INDEX IF NOT EXISTS idx_notifications_scheduled ON notifications(scheduled_at);",
		"CREATE INDEX IF NOT EXISTS idx_domains_next_scan ON domains(next_scan_at);",
	}

	for _, indexSQL := range indexes {
		if _, err := d.Exec(indexSQL); err != nil {
			return fmt.Errorf("failed to create index: %w", err)
		}
	}

	log.Println("Database migrations completed successfully")
	return nil
}

// GetTotalUsers returns the total number of users in the system.
func (d *DB) GetTotalUsers() (int, error) {
	row := d.QueryRow(`SELECT COUNT(*) FROM users`)
	var count int
	if err := row.Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to count users: %w", err)
	}
	return count, nil
}

// GetTotalScans returns the total number of scans.
func (d *DB) GetTotalScans() (int, error) {
	row := d.QueryRow(`SELECT COUNT(*) FROM scans`)
	var count int
	if err := row.Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to count scans: %w", err)
	}
	return count, nil
}

// GetTotalTenants returns the total number of tenants.
func (d *DB) GetTotalTenants() (int, error) {
	row := d.QueryRow(`SELECT COUNT(*) FROM tenants`)
	var count int
	if err := row.Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to count tenants: %w", err)
	}
	return count, nil
}
