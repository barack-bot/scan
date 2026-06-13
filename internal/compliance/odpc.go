// Package compliance handles ODPC (Office of Data Protection Commissioner) compliance checks
package compliance

import (
	"fmt"      // For formatting
	"io"       // For reading response body
	"net/http" // For checking HTTP responses
	"net/url"  // For URL parsing
	"regexp"   // For HTML parsing
	"strings"  // For string searching
	"time"     // For timing checks

	"ke-scan/internal/db" // Our database types
)

// ComplianceCheck represents a single ODPC requirement check
type ComplianceCheck struct {
	ID          string                                          `json:"id"`          // ODPC-001, ODPC-002, etc.
	Name        string                                          `json:"name"`        // Human-readable name
	Description string                                          `json:"description"` // What this check does
	DPASection  string                                          `json:"dpa_section"` // Which DPA 2019 section
	Severity    string                                          `json:"severity"`    // critical, high, medium, low
	TestFunc    func(*ComplianceContext) (bool, string, string) // Test function
}

// ComplianceContext holds data for compliance checks
type ComplianceContext struct {
	URL           string            // Target URL being scanned
	Response      *http.Response    // HTTP response from the site
	Body          string            // Response body as string
	Headers       map[string]string // HTTP headers
	Cookies       []string          // Cookie names found
	Forms         []FormInfo        // Forms found on the page
	ExternalLinks []string          // Third-party domains linked
}

// FormInfo represents an HTML form on the page
type FormInfo struct {
	Action    string   // Where the form submits to
	Method    string   // GET or POST
	Fields    []string // Input field names
	HasSubmit bool     // Has submit button?
}

// Result represents the outcome of a compliance check
type Result struct {
	CheckID     string    `json:"check_id"`
	Name        string    `json:"name"`
	Passed      bool      `json:"passed"`
	Severity    string    `json:"severity"`
	DPASection  string    `json:"dpa_section"`
	Message     string    `json:"message"`     // Explanation of result
	Remediation string    `json:"remediation"` // How to fix if failed
	CheckedAt   time.Time `json:"checked_at"`
}

// ODPCAssessor runs all compliance checks
type ODPCAssessor struct {
	checks []*ComplianceCheck // List of checks to run
}

// NewODPCAssessor creates a new compliance assessor
func NewODPCAssessor() *ODPCAssessor {
	assessor := &ODPCAssessor{
		checks: make([]*ComplianceCheck, 0),
	}
	assessor.registerChecks()
	return assessor
}

// registerChecks adds all ODPC compliance checks
func (a *ODPCAssessor) registerChecks() {
	a.checks = []*ComplianceCheck{
		{
			ID:          "ODPC-001",
			Name:        "Privacy Policy Published",
			Description: "Checks if the website has a publicly accessible privacy policy",
			DPASection:  "Section 31 - Data subject information",
			Severity:    "critical",
			TestFunc:    checkPrivacyPolicy,
		},
		{
			ID:          "ODPC-002",
			Name:        "HTTPS Enforcement",
			Description: "Checks if the website enforces HTTPS encryption",
			DPASection:  "Section 41 - Security of personal data",
			Severity:    "critical",
			TestFunc:    checkHTTPSEnforced,
		},
		{
			ID:          "ODPC-003",
			Name:        "Cookie Consent Mechanism",
			Description: "Checks if cookie consent banner is present",
			DPASection:  "Section 32 - Lawful basis for processing",
			Severity:    "high",
			TestFunc:    checkCookieConsent,
		},
		{
			ID:          "ODPC-004",
			Name:        "Data Subject Rights Contact",
			Description: "Checks if contact information for data subject requests is available",
			DPASection:  "Section 26 - Rights of data subjects",
			Severity:    "high",
			TestFunc:    checkContactInfo,
		},
		{
			ID:          "ODPC-005",
			Name:        "Third-Party Data Transfer",
			Description: "Checks for third-party scripts that may transfer data outside Kenya",
			DPASection:  "Section 48 - Restriction on transfer of personal data",
			Severity:    "medium",
			TestFunc:    checkThirdPartyTransfer,
		},
		{
			ID:          "ODPC-006",
			Name:        "Data Collection Disclosure",
			Description: "Checks if forms disclose how data will be used",
			DPASection:  "Section 31 - Data subject information",
			Severity:    "high",
			TestFunc:    checkDataCollectionDisclosure,
		},
	}
}

// Assess runs all compliance checks on a target URL
func (a *ODPCAssessor) Assess(url string) ([]*Result, error) {
	// Build context by fetching the target website
	ctx, err := a.buildContext(url)
	if err != nil {
		return nil, fmt.Errorf("failed to build context: %w", err)
	}

	// Run all checks
	results := make([]*Result, 0)
	for _, check := range a.checks {
		passed, message, remediation := check.TestFunc(ctx)
		results = append(results, &Result{
			CheckID:     check.ID,
			Name:        check.Name,
			Passed:      passed,
			Severity:    check.Severity,
			DPASection:  check.DPASection,
			Message:     message,
			Remediation: remediation,
			CheckedAt:   time.Now(),
		})
	}

	return results, nil
}

// buildContext fetches the target website and extracts relevant data
func (a *ODPCAssessor) buildContext(url string) (*ComplianceContext, error) {
	// Ensure URL has protocol
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil // Allow redirects
		},
	}

	// Make request
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	// Read body with 1MB limit
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB max
	bodyStr := string(bodyBytes)

	// Extract headers
	headers := make(map[string]string)
	for key, values := range resp.Header {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}

	// Extract cookies
	var cookies []string
	for _, cookie := range resp.Cookies() {
		cookies = append(cookies, cookie.Name)
	}

	// Extract forms (simplified regex - use proper HTML parser in production)
	forms := extractForms(bodyStr)

	// Extract external links
	externalLinks := extractExternalLinks(bodyStr, url)

	return &ComplianceContext{
		URL:           url,
		Response:      resp,
		Body:          bodyStr,
		Headers:       headers,
		Cookies:       cookies,
		Forms:         forms,
		ExternalLinks: externalLinks,
	}, nil
}

// Check functions (these are the actual compliance tests)

func checkPrivacyPolicy(ctx *ComplianceContext) (bool, string, string) {
	// Common privacy policy paths
	paths := []string{"/privacy", "/privacy-policy", "/privacy-policy.html", "/privacy.php"}

	// Use the context's HTTP client which has a 10s timeout, or create a default one
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil // Allow redirects
		},
	}

	for _, path := range paths {
		testURL := ctx.URL + path
		resp, err := client.Get(testURL)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return true, "Privacy policy found at " + path, "No action needed"
			}
		}
	}

	return false, "No privacy policy found at common paths", "Add a privacy policy page at /privacy or /privacy-policy that explains data collection, usage, and user rights under DPA 2019"
}

func checkHTTPSEnforced(ctx *ComplianceContext) (bool, string, string) {
	// Check if already using HTTPS
	if strings.HasPrefix(ctx.URL, "https://") {
		// Check HSTS header
		hsts := ctx.Headers["Strict-Transport-Security"]
		if hsts != "" {
			return true, "HTTPS enforced with HSTS header", "No action needed"
		}
		return true, "HTTPS used but HSTS header missing", "Add Strict-Transport-Security header to enforce HTTPS"
	}

	return false, "Website does not use HTTPS", "Install SSL certificate and redirect all HTTP traffic to HTTPS"
}

func checkCookieConsent(ctx *ComplianceContext) (bool, string, string) {
	bodyLower := strings.ToLower(ctx.Body)

	// Strong signals: actual consent UI elements (buttons, banners, libraries)
	// These indicate a real consent mechanism, not just a mention of "cookie" in text.
	strongIndicators := []string{
		"accept cookies", "reject cookies", "manage cookies",
		"cookie preferences", "cookie settings", "cookie consent",
		"cookie-banner", "cookiebanner", "onetrust", "cookiebot",
		"cookie-notice", "consent-banner", "gdpr-cookie",
		"we use cookies", "this website uses cookies",
		"accept-all", "reject-all", "allow all cookies",
		"cookie policy", "decline cookies",
	}
	for _, indicator := range strongIndicators {
		if strings.Contains(bodyLower, indicator) {
			return true, "Cookie consent mechanism detected: " + indicator, "No action needed"
		}
	}

	// Check for consent-related HTML elements (class/id attributes with cookie/consent keywords)
	consentElementRe := regexp.MustCompile(`(?i)(?:class|id)\s*=\s*["'][^"']*(?:cookie[-_ ]?consent|cookie[-_ ]?banner|consent[-_ ]?banner|cookie[-_ ]?notice|gdpr[-_ ]?banner)[^"']*["']`)
	if consentElementRe.MatchString(ctx.Body) {
		return true, "Cookie consent UI element detected in HTML", "No action needed"
	}

	// Check for cookie consent button elements
	consentButtonRe := regexp.MustCompile(`(?i)<(?:button|a)[^>]*(?:cookie|consent)[^>]*>`)
	if consentButtonRe.MatchString(ctx.Body) {
		return true, "Cookie consent button element detected", "No action needed"
	}

	return false, "No cookie consent mechanism detected", "Implement a cookie consent banner that allows users to accept/reject non-essential cookies before they are set"
}

func checkContactInfo(ctx *ComplianceContext) (bool, string, string) {
	// Check for contact information
	indicators := []string{
		"contact@", "info@", "privacy@", "dpo@", "data protection officer",
		"/contact", "/contact-us", "/privacy-contact",
	}
	bodyLower := strings.ToLower(ctx.Body)

	for _, indicator := range indicators {
		if strings.Contains(bodyLower, indicator) {
			return true, "Contact information found", "No action needed"
		}
	}

	return false, "No contact information for data subject requests found", "Publish contact email (e.g., dpo@yourdomain.com) and physical address for data subject access requests"
}

func checkThirdPartyTransfer(ctx *ComplianceContext) (bool, string, string) {
	// Known third-party domains that may transfer data
	thirdParties := []string{
		"google.com", "facebook.com", "twitter.com", "cloudflare.com",
		"aws.amazon.com", "azure.com", "salesforce.com", "zendesk.com",
	}

	found := make([]string, 0)
	for _, party := range thirdParties {
		for _, link := range ctx.ExternalLinks {
			if strings.Contains(link, party) {
				found = append(found, party)
			}
		}
	}

	if len(found) > 0 {
		return false, fmt.Sprintf("Third-party services detected: %v - These may transfer data outside Kenya", found),
			"Review all third-party services for data processing agreements (DPAs) that comply with Section 48 of DPA 2019. Ensure data remains within Kenya or has adequate safeguards."
	}

	return true, "No third-party data transfer risks detected", "No action needed"
}

func checkDataCollectionDisclosure(ctx *ComplianceContext) (bool, string, string) {
	// Check if forms have privacy notices nearby
	hasForm := len(ctx.Forms) > 0
	if !hasForm {
		return true, "No data collection forms found", "No action needed"
	}

	// Look for disclosure text
	disclosureTerms := []string{"data will be used", "privacy policy", "how we use your", "terms of service"}
	bodyLower := strings.ToLower(ctx.Body)

	for _, term := range disclosureTerms {
		if strings.Contains(bodyLower, term) {
			return true, "Data collection disclosure found", "No action needed"
		}
	}

	return false, "Forms collect data but no disclosure of how data will be used", "Add a notice near forms explaining: what data is collected, why it's collected, how it will be used, and link to privacy policy"
}

// Helper functions for context building (simplified - use proper HTML parser in production)

func extractForms(html string) []FormInfo {
	var forms []FormInfo

	// Match <form> tags with their content
	formTagRe := regexp.MustCompile(`(?i)<form\b[^>]*>(.*?)</form>`)
	formAttrRe := regexp.MustCompile(`(?i)<form\b([^>]*)>`)
	inputRe := regexp.MustCompile(`(?i)<input\b[^>]*name\s*=\s*["']([^"']*)["']`)
	textareaRe := regexp.MustCompile(`(?i)<textarea\b[^>]*name\s*=\s*["']([^"']*)["']`)
	selectRe := regexp.MustCompile(`(?i)<select\b[^>]*name\s*=\s*["']([^"']*)["']`)

	formMatches := formTagRe.FindAllStringSubmatch(html, -1)
	for _, match := range formMatches {
		if len(match) < 2 {
			continue
		}
		fullForm := match[0]
		formContent := match[1]

		fi := FormInfo{Method: "GET"}

		// Extract form attributes from the opening tag
		if attrMatch := formAttrRe.FindStringSubmatch(fullForm); len(attrMatch) > 1 {
			tagAttrs := strings.ToLower(attrMatch[1])
			// Extract action
			actionRe := regexp.MustCompile(`action\s*=\s*["']([^"']*)["']`)
			if am := actionRe.FindStringSubmatch(attrMatch[1]); len(am) > 1 {
				fi.Action = am[1]
			}
			// Extract method
			if strings.Contains(tagAttrs, `method="post"`) || strings.Contains(tagAttrs, `method='post'`) {
				fi.Method = "POST"
			}
		}

		// Extract input field names
		inputs := inputRe.FindAllStringSubmatch(formContent, -1)
		for _, inp := range inputs {
			if len(inp) > 1 && inp[1] != "" {
				fi.Fields = append(fi.Fields, inp[1])
			}
		}

		// Extract textarea field names
		textareas := textareaRe.FindAllStringSubmatch(formContent, -1)
		for _, ta := range textareas {
			if len(ta) > 1 && ta[1] != "" {
				fi.Fields = append(fi.Fields, ta[1])
			}
		}

		// Extract select field names
		selects := selectRe.FindAllStringSubmatch(formContent, -1)
		for _, sel := range selects {
			if len(sel) > 1 && sel[1] != "" {
				fi.Fields = append(fi.Fields, sel[1])
			}
		}

		// Check for submit button
		fi.HasSubmit = strings.Contains(strings.ToLower(formContent), `type="submit"`) ||
			strings.Contains(strings.ToLower(formContent), `type='submit'`) ||
			strings.Contains(strings.ToLower(formContent), "<button")

		forms = append(forms, fi)
	}

	return forms
}

func extractExternalLinks(html, baseURL string) []string {
	baseParsed, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}
	baseHost := strings.ToLower(baseParsed.Hostname())

	// Match src and href attributes with URL values
	re := regexp.MustCompile(`(?i)(?:src|href)\s*=\s*["']([^"']+)["']`)
	matches := re.FindAllStringSubmatch(html, -1)

	seen := make(map[string]bool)
	var links []string
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		u, err := url.Parse(match[1])
		if err != nil || u.Hostname() == "" {
			continue
		}
		linkHost := strings.ToLower(u.Hostname())
		// Skip empty hosts, same-domain links, and protocol-relative without host
		if linkHost == "" || linkHost == baseHost {
			continue
		}
		if !seen[linkHost] {
			seen[linkHost] = true
			links = append(links, linkHost)
		}
	}
	return links
}

// ConvertComplianceResultsToFindings converts compliance results to DB findings
func ConvertComplianceResultsToFindings(scanID int64, results []*Result) []*db.Finding {
	findings := make([]*db.Finding, 0)

	for _, result := range results {
		if !result.Passed {
			// Create a section pointer for ODPC reference
			odpcSection := result.DPASection
			finding := &db.Finding{
				ScanID:      scanID,
				Title:       result.Name,
				Description: result.Message,
				Severity:    result.Severity,
				Category:    "odpc_compliance",
				ODPCSection: &odpcSection,
				Remediation: result.Remediation,
				Evidence:    "Automated compliance scan - " + result.CheckedAt.Format(time.RFC3339),
			}
			findings = append(findings, finding)
		}
	}

	return findings
}
