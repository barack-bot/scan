// Package reporter — PDF generation for KE-SCAN security reports.
// Produces proper PDF documents suitable for board meetings and compliance submissions.
package reporter

import (
	"fmt"
	"strings"
	"time"

	"ke-scan/internal/db"

	"github.com/jung-kurt/gofpdf/v2"
)

// PDFGenerator creates PDF security reports.
type PDFGenerator struct{}

// NewPDFGenerator creates a new PDF report generator.
func NewPDFGenerator() *PDFGenerator {
	return &PDFGenerator{}
}

// GeneratePDF creates a PDF report from a Report struct and returns the bytes.
func (g *PDFGenerator) GeneratePDF(report *Report) ([]byte, error) {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetAutoPageBreak(true, 20)

	// --- Title Page ---
	pdf.AddPage()
	pdf.SetFont("Helvetica", "B", 28)
	pdf.SetTextColor(10, 15, 15)
	pdf.Ln(40)
	pdf.CellFormat(0, 15, "KE-SCAN", "", 1, "C", false, 0, "")
	pdf.SetFont("Helvetica", "", 16)
	pdf.CellFormat(0, 10, "Security Assessment Report", "", 1, "C", false, 0, "")
	pdf.Ln(10)

	pdf.SetDrawColor(100, 100, 100)
	pdf.Line(40, pdf.GetY(), 170, pdf.GetY())
	pdf.Ln(10)

	pdf.SetFont("Helvetica", "", 12)
	pdf.SetTextColor(80, 80, 80)
	pdf.CellFormat(0, 8, fmt.Sprintf("Target: %s", report.TargetURL), "", 1, "C", false, 0, "")
	pdf.CellFormat(0, 8, fmt.Sprintf("Scan Date: %s", report.ScanDate.Format("January 2, 2006 15:04")), "", 1, "C", false, 0, "")
	pdf.CellFormat(0, 8, fmt.Sprintf("Report Generated: %s", time.Now().Format("January 2, 2006 15:04")), "", 1, "C", false, 0, "")
	pdf.Ln(10)

	// Risk level badge
	pdf.SetFont("Helvetica", "B", 14)
	riskColor := riskColorRGB(report.Summary.RiskLevel)
	pdf.SetTextColor(riskColor[0], riskColor[1], riskColor[2])
	pdf.CellFormat(0, 10, fmt.Sprintf("Overall Risk: %s", report.Summary.RiskLevel), "", 1, "C", false, 0, "")
	pdf.Ln(5)

	// Compliance score
	pdf.SetTextColor(80, 80, 80)
	pdf.SetFont("Helvetica", "", 11)
	pdf.CellFormat(0, 8, fmt.Sprintf("ODPC Compliance Score: %.0f%%", report.Summary.ComplianceScore), "", 1, "C", false, 0, "")

	// --- Executive Summary ---
	pdf.AddPage()
	pdf.SetFont("Helvetica", "B", 18)
	pdf.SetTextColor(10, 15, 15)
	pdf.CellFormat(0, 12, "1. Executive Summary", "", 1, "L", false, 0, "")
	pdf.Ln(4)

	pdf.SetFont("Helvetica", "", 11)
	pdf.SetTextColor(60, 60, 60)
	summaryText := fmt.Sprintf(
		"This report presents the findings of a security assessment conducted against %s on %s. "+
			"The scan identified %d security issues across multiple categories. "+
			"The overall risk level is assessed as %s.",
		report.TargetURL,
		report.ScanDate.Format("January 2, 2006"),
		report.Summary.TotalFindings,
		report.Summary.RiskLevel,
	)
	pdf.MultiCell(0, 6, summaryText, "", "L", false)
	pdf.Ln(6)

	// Severity summary table
	pdf.SetFont("Helvetica", "B", 11)
	pdf.SetFillColor(40, 40, 40)
	pdf.SetTextColor(255, 255, 255)
	pdf.CellFormat(45, 8, "Severity", "1", 0, "C", true, 0, "")
	pdf.CellFormat(45, 8, "Count", "1", 0, "C", true, 0, "")
	pdf.CellFormat(45, 8, "Action Required", "1", 1, "C", true, 0, "")

	pdf.SetFont("Helvetica", "", 10)
	pdf.SetTextColor(40, 40, 40)
	rows := []struct {
		sev    string
		count  int
		action string
	}{
		{"Critical", report.Summary.CriticalCount, "Immediate remediation"},
		{"High", report.Summary.HighCount, "Remediate within 7 days"},
		{"Medium", report.Summary.MediumCount, "Remediate within 30 days"},
		{"Low", report.Summary.LowCount, "Schedule for next cycle"},
		{"Info", report.Summary.InfoCount, "Informational only"},
	}
	for _, r := range rows {
		sevColor := severityColorRGB(r.sev)
		pdf.SetTextColor(sevColor[0], sevColor[1], sevColor[2])
		pdf.SetFont("Helvetica", "B", 10)
		pdf.CellFormat(45, 7, r.sev, "1", 0, "C", false, 0, "")
		pdf.SetFont("Helvetica", "", 10)
		pdf.SetTextColor(40, 40, 40)
		pdf.CellFormat(45, 7, fmt.Sprintf("%d", r.count), "1", 0, "C", false, 0, "")
		pdf.CellFormat(45, 7, r.action, "1", 1, "L", false, 0, "")
	}

	// --- Vulnerabilities ---
	if len(report.Vulnerabilities) > 0 {
		pdf.AddPage()
		pdf.SetFont("Helvetica", "B", 18)
		pdf.SetTextColor(10, 15, 15)
		pdf.CellFormat(0, 12, "2. Vulnerability Findings", "", 1, "L", false, 0, "")
		pdf.Ln(4)

		for i, f := range report.Vulnerabilities {
			drawFinding(pdf, i+1, f)
		}
	}

	// --- Compliance ---
	if len(report.Compliance) > 0 {
		pdf.AddPage()
		pdf.SetFont("Helvetica", "B", 18)
		pdf.SetTextColor(10, 15, 15)
		pdf.CellFormat(0, 12, "3. ODPC Compliance Issues", "", 1, "L", false, 0, "")
		pdf.Ln(4)

		for i, f := range report.Compliance {
			drawFinding(pdf, i+1, f)
		}
	}

	// --- Attack Graph / Exploit Chains ---
	if report.AttackGraph != nil && len(report.AttackGraph.Chains) > 0 {
		pdf.AddPage()
		pdf.SetFont("Helvetica", "B", 18)
		pdf.SetTextColor(10, 15, 15)
		pdf.CellFormat(0, 12, "4. Attack Surface & Exploit Chains", "", 1, "L", false, 0, "")
		pdf.Ln(4)

		pdf.SetFont("Helvetica", "", 10)
		pdf.SetTextColor(60, 60, 60)
		pdf.MultiCell(0, 6,
			"The following attack chains were identified based on discovered vulnerabilities and detected software. "+
				"Each chain shows a path from initial access through to impact.",
			"", "L", false)
		pdf.Ln(4)

		for i, chain := range report.AttackGraph.Chains {
			pdf.SetFont("Helvetica", "B", 12)
			pdf.SetTextColor(10, 15, 15)
			pdf.CellFormat(0, 8, fmt.Sprintf("Chain %d: %s", i+1, chain.Description), "", 1, "L", false, 0, "")
			pdf.Ln(2)

			pdf.SetFont("Helvetica", "", 9)
			pdf.SetTextColor(60, 60, 60)
			pdf.CellFormat(0, 6, fmt.Sprintf("   Risk Level: %s   |   Exploitability: %.0f%%", chain.RiskLevel, chain.Exploitability*100), "", 1, "L", false, 0, "")
			pdf.Ln(1)

			// Draw chain steps
			pdf.SetFont("Courier", "", 9)
			for j, step := range chain.Steps {
				arrow := "  └── "
				if j < len(chain.Steps)-1 {
					arrow = "  ├── "
				}
				pdf.CellFormat(0, 5, fmt.Sprintf("%s%s", arrow, step), "", 1, "L", false, 0, "")
			}
			pdf.Ln(4)
		}
	}

	// --- Recommendations ---
	if len(report.Recommendations) > 0 {
		pdf.AddPage()
		pdf.SetFont("Helvetica", "B", 18)
		pdf.SetTextColor(10, 15, 15)
		sectionNum := "5"
		if report.AttackGraph != nil && len(report.AttackGraph.Chains) > 0 {
			sectionNum = "5"
		}
		pdf.CellFormat(0, 12, fmt.Sprintf("%s. Recommendations", sectionNum), "", 1, "L", false, 0, "")
		pdf.Ln(4)

		pdf.SetFont("Helvetica", "", 11)
		pdf.SetTextColor(40, 40, 40)
		for i, rec := range report.Recommendations {
			pdf.SetFont("Helvetica", "B", 11)
			pdf.CellFormat(8, 7, fmt.Sprintf("%d.", i+1), "", 0, "L", false, 0, "")
			pdf.SetFont("Helvetica", "", 11)
			pdf.MultiCell(0, 6, rec, "", "L", false)
			pdf.Ln(2)
		}
	}

	// --- Footer page ---
	pdf.Ln(20)
	pdf.SetDrawColor(100, 100, 100)
	pdf.Line(20, pdf.GetY(), 190, pdf.GetY())
	pdf.Ln(6)
	pdf.SetFont("Helvetica", "I", 9)
	pdf.SetTextColor(120, 120, 120)
	pdf.CellFormat(0, 6, "Generated by KE-SCAN v1.0.0 — Confidential Security Assessment Report", "", 1, "C", false, 0, "")
	pdf.CellFormat(0, 6, fmt.Sprintf("Report ID: KE-SCAN-%d-%s", report.ScanID, report.ScanDate.Format("20060102-150405")), "", 1, "C", false, 0, "")

	// Write to buffer
	var buf strings.Builder
	err := pdf.Output(&buf)
	if err != nil {
		return nil, fmt.Errorf("failed to generate PDF: %w", err)
	}

	return []byte(buf.String()), nil
}

// drawFinding renders a single finding in the PDF.
func drawFinding(pdf *gofpdf.Fpdf, num int, f *db.Finding) {
	// Finding header with severity color
	sevColor := severityColorRGB(f.Severity)
	pdf.SetFillColor(sevColor[0], sevColor[1], sevColor[2])
	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont("Helvetica", "B", 10)
	pdf.CellFormat(30, 7, strings.ToUpper(f.Severity), "", 0, "C", true, 0, "")
	pdf.SetTextColor(10, 15, 15)
	pdf.SetFont("Helvetica", "B", 11)
	pdf.CellFormat(0, 7, fmt.Sprintf("  Finding %d: %s", num, f.Title), "", 1, "L", false, 0, "")
	pdf.Ln(1)

	// CVE/ODPC tags
	if f.CVEID != nil && *f.CVEID != "" {
		pdf.SetFont("Helvetica", "", 9)
		pdf.SetTextColor(59, 130, 246)
		pdf.CellFormat(0, 5, fmt.Sprintf("   CVE: %s  |  Component: %s", *f.CVEID, f.AffectedComponent), "", 1, "L", false, 0, "")
	}
	if f.ODPCSection != nil && *f.ODPCSection != "" {
		pdf.SetFont("Helvetica", "", 9)
		pdf.SetTextColor(139, 140, 140)
		pdf.CellFormat(0, 5, fmt.Sprintf("   ODPC Section: %s", *f.ODPCSection), "", 1, "L", false, 0, "")
	}

	// Description
	pdf.SetFont("Helvetica", "", 10)
	pdf.SetTextColor(60, 60, 60)
	pdf.MultiCell(0, 5, f.Description, "", "L", false)
	pdf.Ln(1)

	// Remediation
	pdf.SetFont("Helvetica", "I", 9)
	pdf.SetTextColor(16, 185, 129)
	pdf.MultiCell(0, 5, fmt.Sprintf("Remediation: %s", f.Remediation), "", "L", false)
	pdf.Ln(4)
}

func severityColorRGB(severity string) [3]int {
	switch strings.ToLower(severity) {
	case "critical":
		return [3]int{239, 68, 68}
	case "high":
		return [3]int{245, 158, 11}
	case "medium":
		return [3]int{59, 130, 246}
	case "low":
		return [3]int{16, 185, 129}
	default:
		return [3]int{156, 163, 175}
	}
}

func riskColorRGB(risk string) [3]int {
	switch strings.ToLower(risk) {
	case "critical":
		return [3]int{239, 68, 68}
	case "high":
		return [3]int{245, 158, 11}
	case "medium":
		return [3]int{59, 130, 246}
	default:
		return [3]int{16, 185, 129}
	}
}
