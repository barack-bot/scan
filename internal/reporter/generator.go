// Package reporter generates compliance and vulnerability reports
package reporter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"strings"
	"time"

	"ke-scan/internal/db"
)

// AttackChain represents a single exploit path from network access to impact
type AttackChain struct {
	Description    string   `json:"description"`    // e.g., "Network → RCE → Data Exfiltration"
	Steps          []string `json:"steps"`          // ordered chain steps
	RiskLevel      string   `json:"risk_level"`     // Critical, High, Medium, Low
	Exploitability float64  `json:"exploitability"` // 0.0 - 1.0
}

// AttackGraphData contains the attack surface visualization for reports
type AttackGraphData struct {
	Chains           []AttackChain `json:"chains"`
	DetectedSoftware []string      `json:"detected_software"` // software identified during scan
	ReachableCVEs    []string      `json:"reachable_cves"`    // CVEs reachable from detected software
}

// Report represents a complete security report
type Report struct {
	ScanID          int64                  `json:"scan_id"`
	TargetURL       string                 `json:"target_url"`
	ScanDate        time.Time              `json:"scan_date"`
	Summary         ReportSummary          `json:"summary"`
	Vulnerabilities []*db.Finding          `json:"vulnerabilities"`
	Compliance      []*db.Finding          `json:"compliance"`
	Recommendations []string               `json:"recommendations"`
	AttackGraph     *AttackGraphData       `json:"attack_graph,omitempty"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// ReportSummary provides high-level statistics
type ReportSummary struct {
	TotalFindings   int      `json:"total_findings"`
	CriticalCount   int      `json:"critical_count"`
	HighCount       int      `json:"high_count"`
	MediumCount     int      `json:"medium_count"`
	LowCount        int      `json:"low_count"`
	InfoCount       int      `json:"info_count"`
	ComplianceScore float64  `json:"compliance_score"` // 0-100
	RiskLevel       string   `json:"risk_level"`       // Low, Medium, High, Critical
	TopRisks        []string `json:"top_risks"`
}

// Generator creates reports in various formats
type Generator struct {
	templates *template.Template // HTML templates for reports
}

// NewGenerator creates a new report generator
func NewGenerator() *Generator {
	return &Generator{}
}

// GenerateFromScan creates a report from scan findings
func (g *Generator) GenerateFromScan(scan *db.Scan, findings []*db.Finding) (*Report, error) {
	// Separate vulnerabilities from compliance findings
	var vulns, compliance []*db.Finding
	for _, f := range findings {
		if f.Category == "odpc_compliance" {
			compliance = append(compliance, f)
		} else {
			vulns = append(vulns, f)
		}
	}

	// Calculate summary statistics
	summary := g.calculateSummary(vulns, compliance)

	// Generate recommendations based on findings
	recommendations := g.generateRecommendations(findings)

	return &Report{
		ScanID:          scan.ID,
		TargetURL:       scan.TargetURL,
		ScanDate:        time.Now(),
		Summary:         summary,
		Vulnerabilities: vulns,
		Compliance:      compliance,
		Recommendations: recommendations,
		Metadata: map[string]interface{}{
			"generator": "KE-SCAN",
			"version":   "1.0.0",
		},
	}, nil
}

// calculateSummary computes statistics from findings
func (g *Generator) calculateSummary(vulns, compliance []*db.Finding) ReportSummary {
	summary := ReportSummary{}

	// Count all findings
	allFindings := append(vulns, compliance...)
	summary.TotalFindings = len(allFindings)

	// Count by severity
	for _, f := range allFindings {
		switch f.Severity {
		case "critical":
			summary.CriticalCount++
		case "high":
			summary.HighCount++
		case "medium":
			summary.MediumCount++
		case "low":
			summary.LowCount++
		default:
			summary.InfoCount++
		}
	}

	// Calculate compliance score (percentage of passed compliance checks)
	// The compliance findings represent failures only. We default to an
	// assumed total of 6 ODPC checks. In production, pass the total count.
	if len(compliance) > 0 {
		totalChecks := 6 // 6 ODPC checks are registered in odpc.go
		failedCount := len(compliance)
		passed := totalChecks - failedCount
		if passed < 0 {
			passed = 0
		}
		summary.ComplianceScore = float64(passed) / float64(totalChecks) * 100
	} else {
		// No compliance findings means all checks passed
		summary.ComplianceScore = 100.0
	}

	// Determine risk level
	if summary.CriticalCount > 0 {
		summary.RiskLevel = "Critical"
	} else if summary.HighCount > 0 {
		summary.RiskLevel = "High"
	} else if summary.MediumCount > 0 {
		summary.RiskLevel = "Medium"
	} else {
		summary.RiskLevel = "Low"
	}

	// Top risks (simplified)
	summary.TopRisks = []string{
		fmt.Sprintf("%d critical vulnerabilities found", summary.CriticalCount),
		fmt.Sprintf("%d high severity issues found", summary.HighCount),
	}

	return summary
}

// generateRecommendations creates action items from findings
func (g *Generator) generateRecommendations(findings []*db.Finding) []string {
	recommendations := make([]string, 0)
	seen := make(map[string]bool)

	for _, f := range findings {
		if f.Severity == "critical" || f.Severity == "high" {
			// Extract a short recommendation from remediation
			short := strings.Split(f.Remediation, ".")[0]
			if len(short) > 100 {
				short = short[:100] + "..."
			}

			if !seen[short] {
				recommendations = append(recommendations, short)
				seen[short] = true
			}
		}
	}

	// Limit to top 10 recommendations
	if len(recommendations) > 10 {
		recommendations = recommendations[:10]
	}

	return recommendations
}

// ToHTML converts a report to a standalone HTML page for screen display and printing
func (g *Generator) ToHTML(report *Report) (string, error) {
	// Try to parse the page template
	tmpl, err := template.ParseFiles("templates/pages/report.html")
	if err != nil {
		// Fallback to basic HTML
		return g.toBasicHTML(report), nil
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, report); err != nil {
		return g.toBasicHTML(report), nil
	}

	return buf.String(), nil
}

// toBasicHTML creates a styled HTML report as fallback
func (g *Generator) toBasicHTML(report *Report) string {
	var html strings.Builder

	riskColor := "#10b981"
	switch report.Summary.RiskLevel {
	case "Critical":
		riskColor = "#ef4444"
	case "High":
		riskColor = "#f59e0b"
	case "Medium":
		riskColor = "#3b82f6"
	}

	criticalCount := report.Summary.CriticalCount
	highCount := report.Summary.HighCount
	mediumCount := report.Summary.MediumCount
	lowCount := report.Summary.LowCount

	html.WriteString(fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>KE-SCAN Security Report</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0A0F0F; color: #E8EAED; padding: 40px; line-height: 1.6; }
  h1 { font-size: 1.8rem; margin-bottom: 8px; color: #fff; }
  h2 { font-size: 1.3rem; margin: 24px 0 12px; color: #fff; border-bottom: 1px solid #333; padding-bottom: 8px; }
  h3 { font-size: 1.1rem; margin: 16px 0 8px; color: #ccc; }
  p, li { color: #bbb; font-size: 0.95rem; }
  .meta { color: #888; margin-bottom: 24px; font-size: 0.9rem; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 16px; margin-bottom: 24px; }
  .card { background: #1a1f1f; border: 1px solid #333; border-radius: 8px; padding: 20px; text-align: center; }
  .stat { font-size: 2rem; font-weight: bold; }
  .label { font-size: 0.85rem; color: #888; margin-top: 4px; }
  .risk-badge { display: inline-block; padding: 8px 24px; border-radius: 6px; font-weight: bold; font-size: 1.1rem; margin-bottom: 16px; }
  .finding { background: #1a1f1f; border: 1px solid #333; border-radius: 8px; padding: 16px; margin-bottom: 12px; }
  .finding-title { font-weight: bold; color: #fff; margin-bottom: 6px; }
  .finding-desc { color: #999; font-size: 0.9rem; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: 600; margin-right: 6px; }
  .badge-critical { background: rgba(239,68,68,0.2); color: #ef4444; }
  .badge-high { background: rgba(245,158,11,0.2); color: #f59e0b; }
  .badge-medium { background: rgba(59,130,246,0.2); color: #3b82f6; }
  .badge-low { background: rgba(16,185,129,0.2); color: #10b981; }
  .badge-info { background: rgba(139,140,140,0.2); color: #9ca3af; }
  .badge-cat { background: rgba(139,140,140,0.2); color: #9ca3af; }
  ol, ul { padding-left: 24px; }
  ol li { margin-bottom: 8px; }
  hr { border: none; border-top: 1px solid #333; margin: 24px 0; }
  @media print { body { background: #fff; color: #000; } h1,h2,h3 { color: #000; } .card,.finding { background: #f5f5f5; border-color: #ddd; } .meta,.label,.finding-desc { color: #666; } }
</style>
</head>
<body>
<h1>KE-SCAN Security Report</h1>
<p class="meta">Target: <strong>%%s</strong> &middot; Scanned: %%s</p>
<hr>

<div class="grid">
  <div class="card"><div class="stat" style="color:#ef4444">%%d</div><div class="label">Critical</div></div>
  <div class="card"><div class="stat" style="color:#f59e0b">%%d</div><div class="label">High</div></div>
  <div class="card"><div class="stat" style="color:#3b82f6">%%d</div><div class="label">Medium</div></div>
  <div class="card"><div class="stat" style="color:#10b981">%%d</div><div class="label">Low</div></div>
  <div class="card"><div class="stat">%%d%%</div><div class="label">Compliance</div></div>
</div>

<div style="text-align:center;margin-bottom:24px;">
  <span class="risk-badge" style="background:%%s22;color:%%s;">Overall Risk: %%s</span>
</div>

<h2>Recommendations</h2>
<ol>
`, report.TargetURL, report.ScanDate.Format("January 02, 2006"),
		criticalCount, highCount, mediumCount, lowCount,
		int(report.Summary.ComplianceScore),
		riskColor, riskColor, report.Summary.RiskLevel))

	for _, rec := range report.Recommendations {
		html.WriteString(fmt.Sprintf("<li>%s</li>\n", rec))
	}
	html.WriteString("</ol>\n")

	if len(report.Vulnerabilities) > 0 {
		html.WriteString("<h2>Vulnerabilities</h2>\n")
		for _, f := range report.Vulnerabilities {
			severityClass := "badge-info"
			switch strings.ToLower(f.Severity) {
			case "critical":
				severityClass = "badge-critical"
			case "high":
				severityClass = "badge-high"
			case "medium":
				severityClass = "badge-medium"
			case "low":
				severityClass = "badge-low"
			}
			cveTag := ""
			if f.CVEID != nil && *f.CVEID != "" {
				cveTag = fmt.Sprintf(`<span class="badge badge-cat">%s</span>`, *f.CVEID)
			}
			html.WriteString(fmt.Sprintf(`<div class="finding">
  <div><span class="badge %s">%s</span><span class="badge badge-cat">%s</span>%s</div>
  <div class="finding-title">%s</div>
  <div class="finding-desc">%s</div>
</div>
`, severityClass, strings.ToUpper(f.Severity), strings.ToUpper(f.Category), cveTag, f.Title, f.Description))
		}
	}

	if len(report.Compliance) > 0 {
		html.WriteString("<h2>ODPC Compliance Issues</h2>\n")
		for _, f := range report.Compliance {
			severityClass := "badge-high"
			if strings.ToLower(f.Severity) == "medium" {
				severityClass = "badge-medium"
			}
			odpcTag := ""
			if f.ODPCSection != nil && *f.ODPCSection != "" {
				odpcTag = fmt.Sprintf(`<span class="badge badge-cat">%s</span>`, *f.ODPCSection)
			}
			html.WriteString(fmt.Sprintf(`<div class="finding">
  <div><span class="badge %s">%s</span>%s</div>
  <div class="finding-title">%s</div>
  <div class="finding-desc">%s</div>
</div>
`, severityClass, strings.ToUpper(f.Severity), odpcTag, f.Title, f.Description))
		}
	}

	// Attack Graph / Exploit Chains section
	if report.AttackGraph != nil && len(report.AttackGraph.Chains) > 0 {
		html.WriteString("<h2>Attack Surface & Exploit Chains</h2>\n")
		html.WriteString(`<p style="color:#999;font-size:0.9rem;margin-bottom:16px;">The following attack chains were identified based on discovered vulnerabilities and detected software.</p>
`)

		for i, chain := range report.AttackGraph.Chains {
			html.WriteString(fmt.Sprintf(`<div class="finding" style="border-left:3px solid %s;">
  <div class="finding-title" style="font-size:1.1rem;">Chain %d: %s</div>
  <div class="finding-desc" style="margin-bottom:8px;">Risk: %s | Exploitability: %.0f%%</div>
  <div style="font-family:monospace;font-size:0.85rem;color:#999;">
`, severityBorderColor(chain.RiskLevel), i+1, chain.Description, strings.ToUpper(chain.RiskLevel), chain.Exploitability*100))
			for j, step := range chain.Steps {
				prefix := "└── "
				if j < len(chain.Steps)-1 {
					prefix = "├── "
				}
				html.WriteString(fmt.Sprintf("    %s%s\n", prefix, step))
			}
			html.WriteString("  </div>\n</div>\n")
		}

		if len(report.AttackGraph.DetectedSoftware) > 0 {
			html.WriteString(`<div style="margin-top:12px;padding:10px;background:#1a1f1f;border-radius:6px;">
  <strong style="color:#888;font-size:0.85rem;">Detected Software: </strong>`)
			for i, s := range report.AttackGraph.DetectedSoftware {
				if i > 0 {
					html.WriteString(", ")
				}
				html.WriteString(fmt.Sprintf(`<span class="badge badge-cat">%s</span>`, s))
			}
			html.WriteString("\n</div>\n")
		}
	}

	html.WriteString("<hr>\n<p class=\"meta\" style=\"text-align:center;\">Generated by KE-SCAN v1.0.0</p>\n</body></html>")
	return html.String()
}

func severityBorderColor(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "#ef4444"
	case "high":
		return "#f59e0b"
	case "medium":
		return "#3b82f6"
	default:
		return "#10b981"
	}
}

// BuildAttackGraph constructs attack chains from scan findings.
// It uses the scanner's graph package to identify exploit paths.
func (g *Generator) BuildAttackGraph(findings []*db.Finding) *AttackGraphData {
	if len(findings) == 0 {
		return nil
	}

	data := &AttackGraphData{
		Chains: make([]AttackChain, 0),
	}

	// Track detected software from affected_component fields
	seenSoftware := make(map[string]bool)
	seenCVEs := make(map[string]bool)

	for _, f := range findings {
		// Collect detected software
		if f.AffectedComponent != "" && !seenSoftware[f.AffectedComponent] {
			seenSoftware[f.AffectedComponent] = true
			data.DetectedSoftware = append(data.DetectedSoftware, f.AffectedComponent)
		}
		// Collect reachable CVEs
		if f.CVEID != nil && *f.CVEID != "" && !seenCVEs[*f.CVEID] {
			seenCVEs[*f.CVEID] = true
			data.ReachableCVEs = append(data.ReachableCVEs, *f.CVEID)
		}
	}

	// Build exploit chains from CVE findings
	var cveFindings []*db.Finding
	for _, f := range findings {
		if f.CVEID != nil && *f.CVEID != "" {
			cveFindings = append(cveFindings, f)
		}
	}

	// Group CVEs by affected component to build multi-step chains
	componentCVEs := make(map[string][]*db.Finding)
	for _, f := range cveFindings {
		comp := f.AffectedComponent
		if comp == "" {
			comp = "Unknown Component"
		}
		componentCVEs[comp] = append(componentCVEs[comp], f)
	}

	// Build chains per component
	for comp, cves := range componentCVEs {
		if len(cves) == 0 {
			continue
		}

		// Build steps: Network Access → Software Detected → CVE Exploited → Impact
		steps := []string{
			fmt.Sprintf("Network access to target"),
			fmt.Sprintf("Software detected: %s", comp),
		}

		// Find the most severe CVE as the primary exploit
		var primary *db.Finding
		for _, f := range cves {
			if primary == nil || severityRank(f.Severity) < severityRank(primary.Severity) {
				primary = f
			}
		}

		steps = append(steps, fmt.Sprintf("Exploit %s (%s)", *primary.CVEID, strings.ToUpper(primary.Severity)))
		steps = append(steps, "Gain code execution / data access")

		// Determine chain risk based on most severe CVE
		chain := AttackChain{
			Description:    fmt.Sprintf("%s exploitation chain via %s", comp, *primary.CVEID),
			Steps:          steps,
			RiskLevel:      primary.Severity,
			Exploitability: float64(100-severityRank(primary.Severity)*20) / 100.0,
		}

		data.Chains = append(data.Chains, chain)
	}

	// Build compliance chain if there are ODPC failures
	var odpcFindings []*db.Finding
	for _, f := range findings {
		if f.Category == "odpc_compliance" {
			odpcFindings = append(odpcFindings, f)
		}
	}

	if len(odpcFindings) > 0 {
		steps := []string{
			"Data subject request received",
			"ODPC compliance check triggered",
			fmt.Sprintf("%d compliance failures detected", len(odpcFindings)),
			"Potential DPA 2019 violation — regulatory action risk",
		}
		data.Chains = append(data.Chains, AttackChain{
			Description:    "Regulatory non-compliance chain (ODPC/DPA)",
			Steps:          steps,
			RiskLevel:      "high",
			Exploitability: 0.8,
		})
	}

	if len(data.Chains) == 0 {
		return nil
	}

	return data
}

func severityRank(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

// ToJSON converts a report to JSON format
func (g *Generator) ToJSON(report *Report) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}

// ToMarkdown converts a report to Markdown format (for READMEs, documentation)
func (g *Generator) ToMarkdown(report *Report) string {
	var md strings.Builder

	md.WriteString(fmt.Sprintf("# Security Scan Report: %s\n\n", report.TargetURL))
	md.WriteString(fmt.Sprintf("**Scan Date:** %s\n\n", report.ScanDate.Format(time.RFC3339)))
	md.WriteString(fmt.Sprintf("**Risk Level:** %s\n\n", report.Summary.RiskLevel))

	md.WriteString("## Summary\n\n")
	md.WriteString(fmt.Sprintf("| Severity | Count |\n"))
	md.WriteString(fmt.Sprintf("|----------|-------|\n"))
	md.WriteString(fmt.Sprintf("| Critical | %d |\n", report.Summary.CriticalCount))
	md.WriteString(fmt.Sprintf("| High     | %d |\n", report.Summary.HighCount))
	md.WriteString(fmt.Sprintf("| Medium   | %d |\n", report.Summary.MediumCount))
	md.WriteString(fmt.Sprintf("| Low      | %d |\n\n", report.Summary.LowCount))

	if len(report.Recommendations) > 0 {
		md.WriteString("## Recommendations\n\n")
		for i, rec := range report.Recommendations {
			md.WriteString(fmt.Sprintf("%d. %s\n", i+1, rec))
		}
	}

	if len(report.Vulnerabilities) > 0 {
		md.WriteString("\n## Vulnerabilities\n\n")
		for _, f := range report.Vulnerabilities {
			md.WriteString(fmt.Sprintf("### [%s] %s\n\n", strings.ToUpper(f.Severity), f.Title))
			md.WriteString(fmt.Sprintf("%s\n\n", f.Description))
			if f.Remediation != "" {
				md.WriteString(fmt.Sprintf("**Remediation:** %s\n\n", f.Remediation))
			}
		}
	}

	if len(report.Compliance) > 0 {
		md.WriteString("\n## ODPC Compliance Issues\n\n")
		for _, f := range report.Compliance {
			md.WriteString(fmt.Sprintf("### [%s] %s\n\n", strings.ToUpper(f.Severity), f.Title))
			md.WriteString(fmt.Sprintf("%s\n\n", f.Description))
		}
	}

	return md.String()
}
