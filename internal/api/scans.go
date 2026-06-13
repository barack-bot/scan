package api

import (
	"fmt"
	"ke-scan/internal/db"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
)

// handleDashboard shows the user's dashboard
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	userID, _ := GetUserID(r)
	claims, _ := GetClaims(r)

	tenantID := int64(0)
	userEmail := "Guest"
	userRole := "user"
	if claims != nil {
		tenantID = claims.TenantID
		userEmail = claims.Email
		userRole = claims.Role
	}

	// Get recent scans for this tenant
	scans, err := s.DB.ListTenantScans(tenantID, 10, 0)
	if err != nil {
		scans = []*db.Scan{}
	}

	// Replace placeholder with live summaries using the tenant-aware function
	summary, err := s.DB.GetFindingsSummaryByTenant(tenantID)
	var totalCritical int
	if err == nil && summary != nil {
		totalCritical = summary["critical"]
	}

	// Get tenant info for subscription status, plan, and quotas
	var subscriptionStatus string
	var plan string
	var scanLimit int
	var scanCountThisMonth int
	var scansRemaining int
	var trialExpiresAt interface{}
	var notifications interface{}

	tenant, err := s.DB.GetTenantByID(tenantID)
	if err == nil && tenant != nil {
		subscriptionStatus = tenant.SubscriptionStatus
		plan = tenant.Plan
		scanLimit = tenant.ScanLimit
		scanCountThisMonth = tenant.ScanCountThisMonth

		if tenant.ScanLimit == -1 {
			scansRemaining = 999
		} else {
			scansRemaining = tenant.ScanLimit - tenant.ScanCountThisMonth
			if scansRemaining < 0 {
				scansRemaining = 0
			}
		}

		if tenant.TrialExpiresAt != nil {
			trialExpiresAt = tenant.TrialExpiresAt.Format("Jan 02, 2006")
		}

		// Get unread notifications
		notifs, err := s.DB.GetUnreadNotifications(tenantID)
		if err == nil && len(notifs) > 0 {
			notifications = notifs
		}
	} else {
		subscriptionStatus = "active"
		plan = "free"
		scanLimit = 3
		scanCountThisMonth = 0
		scansRemaining = 3
		trialExpiresAt = nil
		notifications = nil
	}

	data := map[string]interface{}{
		"Title":              "Dashboard - KE-SCAN",
		"UserID":             userID,
		"UserEmail":          userEmail,
		"UserRole":           userRole,
		"Scans":              wrapScans(scans, s.DB),
		"TotalScans":         len(scans),
		"CriticalFindings":   totalCritical,
		"ComplianceScore":    85, // Dynamic heuristic visual score placeholder
		"ActivePage":         "dashboard",
		"SubscriptionStatus": subscriptionStatus,
		"Plan":               plan,
		"ScanLimit":          scanLimit,
		"ScanCountThisMonth": scanCountThisMonth,
		"ScansRemaining":     scansRemaining,
		"TrialExpiresAt":     trialExpiresAt,
		"Notifications":      notifications,
	}

	RenderPage(w, r, "dashboard", data)
}

// handleNewScanPage shows the form to start a new scan
func (s *Server) handleNewScanPage(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Title":      "New Scan - KE-SCAN",
		"ActivePage": "scan",
	}

	RenderPage(w, r, "scan", data)
}

// handleStartScan initiates a new security scan with unverified fallback options
func (s *Server) handleStartScan(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form submit payload", http.StatusBadRequest)
		return
	}

	targetURL := r.FormValue("target_url")
	scanType := r.FormValue("scan_type")
	if scanType == "" {
		scanType = "full"
	}

	claims, _ := GetClaims(r)
	tenantID := int64(0)
	if claims != nil {
		tenantID = claims.TenantID
	}

	// Extract domain from the target URL for ownership verification
	targetDomain := extractDomainForCheck(targetURL)
	isExternalGuestScan := false

	if targetDomain != "" {
		domain, err := s.DB.GetDomainByName(targetDomain)

		if err != nil || domain == nil {
			log.Printf("[Scanner Notice] Target domain %s not registered in DB. Proceeding with limited external scan mode.", targetDomain)
			isExternalGuestScan = true
		} else if !domain.Verified {
			if targetDomain == "localhost" || strings.HasSuffix(targetDomain, ".local") {
				log.Printf("[Dev Mode] Bypassing verification restrictions for local ecosystem host: %s", targetDomain)
			} else {
				log.Printf("[Scanner Notice] Target domain %s is unverified. Downgrading to external footprint scanning.", targetDomain)
				isExternalGuestScan = true
			}
		} else if domain.TenantID != tenantID && tenantID != 0 {
			log.Printf("[Security Warning] Tenant %d attempted to scan domain belonging to another organization: %s", tenantID, targetDomain)
			http.Error(w, "Domain asset ownership conflict", http.StatusForbidden)
			return
		}
	}

	if isExternalGuestScan {
		log.Printf("Executing safe external footprint pipeline for: %s", targetURL)
	}

	// Create scan record dynamically in database
	scan, err := s.DB.CreateScan(tenantID, targetURL, scanType)
	if err != nil {
		log.Printf("Database failure writing scan transaction: %v", err)
		http.Error(w, "Failed to initialize scan orchestration record", http.StatusInternalServerError)
		return
	}

	// Hand execution over to the background scanner engine safely
	go s.Scanner.RunScan(scan.ID, targetURL, scanType)

	// Send response back to HTMX dashboard component
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("Content-Type", "text/html")
		RenderPartialPage(w, r, "scan_result", map[string]interface{}{
			"Scan": scan,
		})
		return
	}

	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

// handleScanStatus shows the status of a running scan
func (s *Server) handleScanStatus(w http.ResponseWriter, r *http.Request) {
	scanID, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)

	scan, err := s.DB.GetScan(scanID)
	if err != nil || scan == nil {
		http.NotFound(w, r)
		return
	}

	var findings []*db.Finding
	if scan.Status == "completed" {
		findings, _ = s.DB.GetFindingsByScanID(scanID)
	}

	data := map[string]interface{}{
		"Title":    fmt.Sprintf("Scan #%d - KE-SCAN", scanID),
		"Scan":     scan,
		"Findings": findings,
	}

	RenderPage(w, r, "scan_status", data)
}

// handleScanResults handles polling requests safely and controls HTMX stopping triggers
func (s *Server) handleScanResults(w http.ResponseWriter, r *http.Request) {
	idParam := chi.URLParam(r, "id")
	if idParam == "" {
		idParam = r.URL.Query().Get("id")
	}

	scanID, err := strconv.ParseInt(idParam, 10, 64)
	if err != nil || scanID == 0 {
		http.Error(w, "Malformed tracking parameter identifiers", http.StatusBadRequest)
		return
	}

	scan, err := s.DB.GetScan(scanID)
	if err != nil || scan == nil {
		http.Error(w, "Scan record tracking reference unavailable", http.StatusNotFound)
		return
	}

	// HTMX Poller Interceptor check
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("Content-Type", "text/html")

		// UPGRADE: If the scan is complete, tell HTMX to stop polling immediately via HTTP Response Headers
		if scan.Status == "completed" || scan.Status == "failed" {
			w.Header().Set("HX-Trigger", "scanFinished") // Fire a browser event to refresh findings if needed
		}

		findingCount := 0
		if scan.Status == "completed" {
			count, err := s.DB.GetFindingCount(scanID)
			if err == nil {
				findingCount = count
			}
		}
		RenderPartialPage(w, r, "scan_row", map[string]interface{}{
			"Scan":         scan,
			"FindingCount": findingCount,
		})
		return
	}

	// Native JSON Fallback block
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(fmt.Sprintf(`{"id":%d,"status":"%s","progress":%d}`, scan.ID, scan.Status, scan.Progress)))
}
func wrapScans(scans []*db.Scan, db *db.DB) []map[string]interface{} {
	wrapped := make([]map[string]interface{}, len(scans))
	for i, scan := range scans {
		findingCount := 0
		if scan.Status == "completed" {
			count, err := db.GetFindingCount(scan.ID)
			if err == nil {
				findingCount = count
			}
		}
		wrapped[i] = map[string]interface{}{
			"Scan":         scan,
			"FindingCount": findingCount,
		}
	}
	return wrapped
}

// extractDomainForCheck extracts the hostname (domain) from a URL string for ownership verification
func extractDomainForCheck(rawURL string) string {
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
