package api

import (
	"log"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"ke-scan/internal/db"
	"ke-scan/internal/reporter"
)

// handleReportView shows a compliance report
func (s *Server) handleReportView(w http.ResponseWriter, r *http.Request) {
	scanID, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)

	// Get scan
	scan, err := s.DB.GetScan(scanID)
	if err != nil || scan == nil {
		http.NotFound(w, r)
		return
	}

	// Get findings
	findings, err := s.DB.GetFindingsByScanID(scanID)
	if err != nil {
		findings = []*db.Finding{}
	}

	// Generate report
	gen := reporter.NewGenerator()
	report, err := gen.GenerateFromScan(scan, findings)
	if err != nil {
		http.Error(w, "Failed to generate report", http.StatusInternalServerError)
		return
	}

	// Build attack graph from findings (product differentiator)
	report.AttackGraph = gen.BuildAttackGraph(findings)

	// Render as HTML
	if r.Header.Get("HX-Request") == "true" {
		html, err := gen.ToHTML(report)
		if err != nil {
			http.Error(w, "Failed to render report", http.StatusInternalServerError)
			return
		}
		w.Write([]byte(html))
		return
	}

	// Full page
	data := map[string]interface{}{
		"Title":  "Report - KE-SCAN",
		"Report": report,
	}

	renderer, err := NewRenderer()
	if err != nil {
		http.Error(w, "Failed to load templates", http.StatusInternalServerError)
		return
	}
	renderer.Render(w, r, "report", data)
}

// handleReportDownload downloads a report in various formats
func (s *Server) handleReportDownload(w http.ResponseWriter, r *http.Request) {
	scanID, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "html"
	}

	// Get scan and findings
	scan, err := s.DB.GetScan(scanID)
	if err != nil || scan == nil {
		http.NotFound(w, r)
		return
	}

	findings, err := s.DB.GetFindingsByScanID(scanID)
	if err != nil {
		findings = []*db.Finding{}
	}

	// Generate report with attack graph
	gen := reporter.NewGenerator()
	report, err := gen.GenerateFromScan(scan, findings)
	if err != nil {
		http.Error(w, "Failed to generate report", http.StatusInternalServerError)
		return
	}
	report.AttackGraph = gen.BuildAttackGraph(findings)

	// Set content type based on format
	switch format {
	case "json":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=report.json")
		jsonData, err := gen.ToJSON(report)
		if err != nil {
			http.Error(w, "Failed to generate JSON report", http.StatusInternalServerError)
			return
		}
		w.Write(jsonData)

	case "md":
		w.Header().Set("Content-Type", "text/markdown")
		w.Header().Set("Content-Disposition", "attachment; filename=report.md")
		mdData := gen.ToMarkdown(report)
		w.Write([]byte(mdData))

	case "pdf":
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", "attachment; filename=report.pdf")
		pdfGen := reporter.NewPDFGenerator()
		pdfData, err := pdfGen.GeneratePDF(report)
		if err != nil {
			log.Printf("Failed to generate PDF report for scan %d: %v", scanID, err)
			http.Error(w, "Failed to generate PDF report", http.StatusInternalServerError)
			return
		}
		w.Write(pdfData)

	default: // html
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Disposition", "attachment; filename=report.html")
		htmlData, err := gen.ToHTML(report)
		if err != nil {
			http.Error(w, "Failed to generate HTML report", http.StatusInternalServerError)
			return
		}
		w.Write([]byte(htmlData))
	}
}
