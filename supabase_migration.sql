-- =============================================================================
-- KE-SCAN Supabase PostgreSQL Migration
-- =============================================================================
-- Run this entire script in the Supabase SQL Editor to create all tables.
-- This replaces the SQLite schema with a production-grade PostgreSQL schema.
-- =============================================================================

-- =============================================================================
-- 1. ENABLE REQUIRED EXTENSIONS
-- =============================================================================
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- =============================================================================
-- 2. CUSTOM ENUM TYPES
-- =============================================================================

-- Subscription status for tenants
CREATE TYPE subscription_status AS ENUM (
    'trial',
    'active',
    'suspended',
    'cancelled'
);

-- Scan frequency for domain scheduling
CREATE TYPE scan_frequency AS ENUM (
    'daily',
    'weekly',
    'monthly'
);

-- Subscription plans
CREATE TYPE plan_tier AS ENUM (
    'free',
    'business',
    'enterprise'
);

-- Finding status for tracking resolution
CREATE TYPE finding_status AS ENUM (
    'open',
    'acknowledged',
    'resolved'
);

-- Scan status
CREATE TYPE scan_status AS ENUM (
    'pending',
    'running',
    'completed',
    'failed'
);

-- Scan type
CREATE TYPE scan_type AS ENUM (
    'full',
    'quick',
    'compliance_only'
);

-- Severity levels
CREATE TYPE severity_level AS ENUM (
    'critical',
    'high',
    'medium',
    'low',
    'info'
);

-- User roles
CREATE TYPE user_role AS ENUM (
    'user',
    'admin',
    'enterprise'
);

-- Notification type
CREATE TYPE notification_type AS ENUM (
    'cert_expiry',
    'new_critical_finding',
    'scan_complete',
    'plan_expiring',
    'subscription_cancelled',
    'scan_quota_warning',
    'general'
);

-- Notification status
CREATE TYPE notification_status AS ENUM (
    'unread',
    'read',
    'dismissed'
);

-- Payment status
CREATE TYPE payment_status AS ENUM (
    'pending',
    'completed',
    'failed',
    'refunded'
);

-- =============================================================================
-- 3. TENANTS TABLE (Enhanced with plan enforcement)
-- =============================================================================
DROP TABLE IF EXISTS tenants CASCADE;

CREATE TABLE tenants (
    id                  BIGSERIAL PRIMARY KEY,
    name                TEXT NOT NULL,
    domain              TEXT NOT NULL UNIQUE,
    plan                plan_tier NOT NULL DEFAULT 'free',
    odpc_number         TEXT,

    -- Plan enforcement columns
    subscription_status subscription_status NOT NULL DEFAULT 'trial',
    scan_limit          INTEGER NOT NULL DEFAULT 3,               -- max scans per month (free=3, business=50, enterprise=unlimited=-1)
    scan_count_this_month INTEGER NOT NULL DEFAULT 0,             -- scans used in current billing period
    last_billing_date   TIMESTAMPTZ,                              -- when last billing cycle started
    trial_expires_at    TIMESTAMPTZ,                              -- when trial ends (NULL = no trial)

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for tenant queries
CREATE INDEX idx_tenants_domain ON tenants(domain);
CREATE INDEX idx_tenants_plan ON tenants(plan);
CREATE INDEX idx_tenants_subscription_status ON tenants(subscription_status);
CREATE INDEX idx_tenants_trial_expires_at ON tenants(trial_expires_at);

-- =============================================================================
-- 4. USERS TABLE
-- =============================================================================
DROP TABLE IF EXISTS users CASCADE;

CREATE TABLE users (
    id                  BIGSERIAL PRIMARY KEY,
    email               TEXT NOT NULL UNIQUE,
    password            TEXT NOT NULL,
    name                TEXT NOT NULL,
    role                user_role NOT NULL DEFAULT 'user',

    active              BOOLEAN NOT NULL DEFAULT FALSE,
    activation_token    TEXT,
    tenant_id           BIGINT REFERENCES tenants(id) ON DELETE SET NULL,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_tenant_id ON users(tenant_id);
CREATE INDEX idx_users_role ON users(role);

-- =============================================================================
-- 5. DOMAINS TABLE (Enhanced with scan scheduling)
-- =============================================================================
DROP TABLE IF EXISTS domains CASCADE;

CREATE TABLE domains (
    id                  BIGSERIAL PRIMARY KEY,
    tenant_id           BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    domain              TEXT NOT NULL,

    verification_txt    TEXT NOT NULL,
    verified            BOOLEAN NOT NULL DEFAULT FALSE,
    verified_at         TIMESTAMPTZ,

    -- Scan scheduling columns (new)
    scan_frequency      scan_frequency NOT NULL DEFAULT 'weekly',  -- daily, weekly, monthly
    last_scanned_at     TIMESTAMPTZ,                                -- when this domain was last scanned
    next_scan_at        TIMESTAMPTZ,                                -- when the next scheduled scan should run
    auto_scan_enabled   BOOLEAN NOT NULL DEFAULT TRUE,              -- whether automatic scans are enabled

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(tenant_id, domain)
);

CREATE INDEX idx_domains_tenant_id ON domains(tenant_id);
CREATE INDEX idx_domains_next_scan_at ON domains(next_scan_at);
CREATE INDEX idx_domains_verified ON domains(verified);
CREATE INDEX idx_domains_scan_frequency ON domains(scan_frequency);

-- =============================================================================
-- 6. SCANS TABLE
-- =============================================================================
DROP TABLE IF EXISTS scans CASCADE;

CREATE TABLE scans (
    id                  BIGSERIAL PRIMARY KEY,
    tenant_id           BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    domain_id           BIGINT REFERENCES domains(id) ON DELETE SET NULL,  -- linked domain (optional)
    target_url          TEXT NOT NULL,

    status              scan_status NOT NULL DEFAULT 'pending',
    scan_type           scan_type NOT NULL DEFAULT 'full',
    progress            INTEGER NOT NULL DEFAULT 0,                   -- 0 to 100

    started_at          TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scans_tenant_id ON scans(tenant_id);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created_at ON scans(created_at);
CREATE INDEX idx_scans_domain_id ON scans(domain_id);
CREATE INDEX idx_scans_completed_at ON scans(completed_at);

-- =============================================================================
-- 7. FINDINGS TABLE (CRITICAL - Properly queryable findings)
-- =============================================================================
-- This is the most important schema change. Findings are no longer a JSON blob
-- stored inside scans. They are their own table with structured columns so you
-- can query: "show me all tenants with a critical Apache CVE", "how many ODPC
-- failures across all scans this week", etc.
-- =============================================================================
DROP TABLE IF EXISTS findings CASCADE;

CREATE TABLE findings (
    id                  BIGSERIAL PRIMARY KEY,
    scan_id             BIGINT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,

    -- Core finding data
    title               TEXT NOT NULL,
    description         TEXT NOT NULL,
    severity            severity_level NOT NULL,
    confidence          INTEGER DEFAULT 50,                         -- 0-100 confidence score

    -- Vulnerability identifiers
    cve_id              TEXT,                                       -- CVE identifier (e.g., CVE-2021-41773)
    odpc_section        TEXT,                                       -- ODPC compliance section (e.g., DPA 2019 Part V)

    -- Technical details
    affected_component  TEXT,                                       -- e.g., "Apache 2.4.49", "nginx/1.18.0", "PHP 7.4"
    category            TEXT NOT NULL,                              -- cve, odpc_compliance, tls, headers, dns
    
    -- Resolution tracking
    remediation         TEXT NOT NULL,
    evidence            TEXT NOT NULL,                              -- Proof (curl command, screenshot ref, etc.)
    status              finding_status NOT NULL DEFAULT 'open',     -- open, acknowledged, resolved
    resolved_at         TIMESTAMPTZ,
    resolved_by         BIGINT REFERENCES users(id) ON DELETE SET NULL,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for powerful querying across findings
CREATE INDEX idx_findings_scan_id ON findings(scan_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_cve_id ON findings(cve_id);
CREATE INDEX idx_findings_status ON findings(status);
CREATE INDEX idx_findings_category ON findings(category);
CREATE INDEX idx_findings_created_at ON findings(created_at);
CREATE INDEX idx_findings_affected_component ON findings(affected_component);

-- Composite index for cross-tenant CVE queries
CREATE INDEX idx_findings_severity_category ON findings(severity, category);

-- Partial index for open findings (most common query)
CREATE INDEX idx_findings_open ON findings(severity, created_at) WHERE status = 'open';

-- =============================================================================
-- 8. SCHEDULED SCANS TABLE (Recurring scan system)
-- =============================================================================
DROP TABLE IF EXISTS scheduled_scans CASCADE;

CREATE TABLE scheduled_scans (
    id                  BIGSERIAL PRIMARY KEY,
    tenant_id           BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    domain_id           BIGINT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,

    scan_type           scan_type NOT NULL DEFAULT 'full',
    frequency           scan_frequency NOT NULL DEFAULT 'weekly',
    next_run_at         TIMESTAMPTZ NOT NULL,                       -- when to execute next
    last_run_at         TIMESTAMPTZ,                                -- when last executed
    enabled             BOOLEAN NOT NULL DEFAULT TRUE,

    -- If a scheduled scan creates a scan record, link it here
    last_scan_id        BIGINT REFERENCES scans(id) ON DELETE SET NULL,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scheduled_scans_next_run_at ON scheduled_scans(next_run_at);
CREATE INDEX idx_scheduled_scans_tenant_id ON scheduled_scans(tenant_id);
CREATE INDEX idx_scheduled_scans_enabled ON scheduled_scans(enabled);
-- Partial index for jobs due now (only enabled ones)
CREATE INDEX idx_scheduled_scans_due ON scheduled_scans(next_run_at) WHERE enabled = TRUE;

-- =============================================================================
-- 9. PAYMENTS TABLE (M-PESA integration)
-- =============================================================================
DROP TABLE IF EXISTS payments CASCADE;

CREATE TABLE payments (
    id                  BIGSERIAL PRIMARY KEY,
    tenant_id           BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- M-PESA payment details
    checkout_request_id TEXT,                                       -- M-PESA STK push checkout request ID
    transaction_id      TEXT,                                       -- M-PESA transaction ID (from callback)
    mpesa_receipt_number TEXT,                                      -- Safaricom receipt number (proof of payment)
    merchant_request_id TEXT,                                       -- M-PESA merchant request ID

    -- Payment metadata
    amount              NUMERIC(10, 2) NOT NULL,                   -- amount in KES
    currency            TEXT NOT NULL DEFAULT 'KES',
    phone_number        TEXT,                                       -- M-PESA phone number used

    -- Subscription tracking
    subscription_id     TEXT,                                       -- unique subscription identifier
    plan                plan_tier NOT NULL,                         -- plan purchased
    period_start        TIMESTAMPTZ,                                -- billing period start
    period_end          TIMESTAMPTZ,                                -- billing period end

    -- Status
    status              payment_status NOT NULL DEFAULT 'pending',
    result_code         TEXT,                                       -- M-PESA result code ("0" = success)
    result_desc         TEXT,                                       -- M-PESA result description

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_payments_tenant_id ON payments(tenant_id);
CREATE INDEX idx_payments_status ON payments(status);
CREATE INDEX idx_payments_mpesa_receipt ON payments(mpesa_receipt_number);
CREATE INDEX idx_payments_subscription_id ON payments(subscription_id);
CREATE INDEX idx_payments_created_at ON payments(created_at);

-- =============================================================================
-- 10. AUDIT LOGS TABLE (Enhanced with event-driven tracking)
-- =============================================================================
DROP TABLE IF EXISTS audit_logs CASCADE;

CREATE TABLE audit_logs (
    id                  BIGSERIAL PRIMARY KEY,
    tenant_id           BIGINT REFERENCES tenants(id) ON DELETE SET NULL,
    user_id             BIGINT REFERENCES users(id) ON DELETE SET NULL,

    action              TEXT NOT NULL,                              -- e.g., "login", "scan_started", "plan_changed"
    ip_address          TEXT NOT NULL,
    user_agent          TEXT NOT NULL,
    details             JSONB,                                      -- structured JSON with event-specific context

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_tenant_id ON audit_logs(tenant_id);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);

-- =============================================================================
-- 11. NOTIFICATIONS TABLE (Alerts and scheduled notifications)
-- =============================================================================
DROP TABLE IF EXISTS notifications CASCADE;

CREATE TABLE notifications (
    id                  BIGSERIAL PRIMARY KEY,
    tenant_id           BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id             BIGINT REFERENCES users(id) ON DELETE SET NULL,  -- NULL = tenant-wide

    -- Notification content
    notification_type   notification_type NOT NULL,
    title               TEXT NOT NULL,
    message             TEXT NOT NULL,

    -- Context linking (which finding/scan triggered this)
    finding_id          BIGINT REFERENCES findings(id) ON DELETE SET NULL,
    scan_id             BIGINT REFERENCES scans(id) ON DELETE SET NULL,

    -- Delivery tracking
    status              notification_status NOT NULL DEFAULT 'unread',
    read_at             TIMESTAMPTZ,
    dismissed_at        TIMESTAMPTZ,

    -- Scheduling (for future notifications like "cert expires in 7 days")
    scheduled_at        TIMESTAMPTZ,                                -- when to notify (NULL = immediate)
    sent_at             TIMESTAMPTZ,                                -- when actually sent

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_notifications_tenant_id ON notifications(tenant_id);
CREATE INDEX idx_notifications_user_id ON notifications(user_id);
CREATE INDEX idx_notifications_status ON notifications(status);
CREATE INDEX idx_notifications_type ON notifications(notification_type);
CREATE INDEX idx_notifications_scheduled_at ON notifications(scheduled_at);
CREATE INDEX idx_notifications_unread ON notifications(tenant_id, status) WHERE status = 'unread';

-- =============================================================================
-- 12. HELPER FUNCTIONS
-- =============================================================================

-- Auto-update updated_at timestamp on row modification
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply the trigger to all tables with updated_at
CREATE TRIGGER trg_tenants_updated_at BEFORE UPDATE ON tenants
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_domains_updated_at BEFORE UPDATE ON domains
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_scans_updated_at BEFORE UPDATE ON scans
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_findings_updated_at BEFORE UPDATE ON findings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_payments_updated_at BEFORE UPDATE ON payments
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_scheduled_scans_updated_at BEFORE UPDATE ON scheduled_scans
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Function to increment scan count and check quota
CREATE OR REPLACE FUNCTION check_scan_quota(p_tenant_id BIGINT)
RETURNS BOOLEAN AS $$
DECLARE
    v_limit INTEGER;
    v_count INTEGER;
    v_status subscription_status;
BEGIN
    SELECT scan_limit, scan_count_this_month, subscription_status
    INTO v_limit, v_count, v_status
    FROM tenants WHERE id = p_tenant_id;

    -- Suspended or cancelled tenants can't scan
    IF v_status IN ('suspended', 'cancelled') THEN
        RETURN FALSE;
    END IF;

    -- -1 means unlimited
    IF v_limit = -1 THEN
        RETURN TRUE;
    END IF;

    RETURN v_count < v_limit;
END;
$$ LANGUAGE plpgsql;

-- Function to reset monthly scan counts (run via cron or pg_cron)
CREATE OR REPLACE FUNCTION reset_monthly_scan_counts()
RETURNS VOID AS $$
BEGIN
    UPDATE tenants
    SET scan_count_this_month = 0,
        last_billing_date = NOW()
    WHERE subscription_status = 'active';
END;
$$ LANGUAGE plpgsql;

-- Function to check trial expiry
CREATE OR REPLACE FUNCTION expire_trials()
RETURNS VOID AS $$
BEGIN
    UPDATE tenants
    SET subscription_status = 'suspended',
        plan = 'free'
    WHERE subscription_status = 'trial'
      AND trial_expires_at IS NOT NULL
      AND trial_expires_at < NOW();
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- 13. ROW LEVEL SECURITY (RLS) POLICIES
-- =============================================================================
-- Enable RLS on all tables
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE domains ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE payments ENABLE ROW LEVEL SECURITY;
ALTER TABLE notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE scheduled_scans ENABLE ROW LEVEL SECURITY;

-- Service role bypasses RLS (for Go backend API calls)
CREATE POLICY "Service role full access on tenants"
    ON tenants FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

CREATE POLICY "Service role full access on users"
    ON users FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

CREATE POLICY "Service role full access on domains"
    ON domains FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

CREATE POLICY "Service role full access on scans"
    ON scans FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

CREATE POLICY "Service role full access on findings"
    ON findings FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

CREATE POLICY "Service role full access on audit_logs"
    ON audit_logs FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

CREATE POLICY "Service role full access on payments"
    ON payments FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

CREATE POLICY "Service role full access on notifications"
    ON notifications FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

CREATE POLICY "Service role full access on scheduled_scans"
    ON scheduled_scans FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

-- =============================================================================
-- 14. SEED DATA
-- =============================================================================

-- Insert default tenant
INSERT INTO tenants (name, domain, plan, subscription_status, scan_limit, scan_count_this_month, trial_expires_at)
VALUES (
    'KE-SCAN Default Tenant',
    'default.ke-scan.local',
    'free',
    'trial',
    3,
    0,
    NOW() + INTERVAL '14 days'
);

-- =============================================================================
-- 15. HELPER VIEWS (Useful for dashboards)
-- =============================================================================

-- View: Findings summary by tenant and severity
CREATE OR REPLACE VIEW v_tenant_findings_summary AS
SELECT
    s.tenant_id,
    f.severity,
    f.status,
    COUNT(*) AS finding_count
FROM findings f
JOIN scans s ON f.scan_id = s.id
GROUP BY s.tenant_id, f.severity, f.status;

-- View: Pending scheduled scans (for the scanner job)
CREATE OR REPLACE VIEW v_pending_scheduled_scans AS
SELECT
    ss.id AS scheduled_scan_id,
    ss.tenant_id,
    ss.domain_id,
    d.domain AS domain_name,
    ss.frequency,
    ss.next_run_at,
    ss.last_run_at
FROM scheduled_scans ss
JOIN domains d ON ss.domain_id = d.id
WHERE ss.enabled = TRUE
  AND ss.next_run_at <= NOW()
  AND d.verified = TRUE;

-- View: Tenant scan usage this month
CREATE OR REPLACE VIEW v_tenant_scan_usage AS
SELECT
    t.id AS tenant_id,
    t.name AS tenant_name,
    t.plan,
    t.scan_limit,
    t.scan_count_this_month,
    t.subscription_status,
    CASE
        WHEN t.scan_limit = -1 THEN 'unlimited'
        ELSE (t.scan_limit - t.scan_count_this_month)::TEXT
    END AS scans_remaining
FROM tenants t;

-- View: Open critical findings for notifications
CREATE OR REPLACE VIEW v_open_critical_findings AS
SELECT
    f.id AS finding_id,
    f.title,
    f.severity,
    f.cve_id,
    f.affected_component,
    s.tenant_id,
    s.target_url,
    f.created_at AS detected_at
FROM findings f
JOIN scans s ON f.scan_id = s.id
WHERE f.status = 'open'
  AND f.severity IN ('critical', 'high');

-- =============================================================================
-- MIGRATION COMPLETE
-- =============================================================================
-- Tables created:
--   1. tenants         - with plan enforcement columns
--   2. users           - with proper PostgreSQL types
--   3. domains         - with scan scheduling columns
--   4. scans           - with domain_id link
--   5. findings        - proper queryable table (most important change)
--   6. scheduled_scans - for recurring scan system
--   7. payments        - with M-PESA receipt tracking
--   8. audit_logs      - with JSONB details
--   9. notifications   - for alerts and scheduled notifications
--
-- Views:
--   - v_tenant_findings_summary  (dashboard data)
--   - v_pending_scheduled_scans  (scanner job queue)
--   - v_tenant_scan_usage        (quota tracking)
--   - v_open_critical_findings   (notifications trigger)
--
-- Functions:
--   - update_updated_at()           (auto timestamps)
--   - check_scan_quota()            (enforce scan limits)
--   - reset_monthly_scan_counts()   (billing cycle reset)
--   - expire_trials()               (trial expiry check)
-- =============================================================================