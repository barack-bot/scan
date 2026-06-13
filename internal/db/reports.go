package db

// ScanReport provides a lightweight report summary for a scan.
type ScanReport struct {
	ScanID        int64 `json:"scan_id"`
	TotalFindings int   `json:"total_findings"`
	CriticalCount int   `json:"critical_count"`
	HighCount     int   `json:"high_count"`
}

// GetScanReport returns a simple summary report for a scan.
func (d *DB) GetScanReport(scanID int64) (*ScanReport, error) {
	findings, err := d.GetFindingsByScanID(scanID)
	if err != nil {
		return nil, err
	}

	summary := &ScanReport{
		ScanID:        scanID,
		TotalFindings: len(findings),
	}

	for _, f := range findings {
		switch f.Severity {
		case "critical":
			summary.CriticalCount++
		case "high":
			summary.HighCount++
		}
	}

	return summary, nil
}
