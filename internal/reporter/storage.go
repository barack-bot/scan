package reporter

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Storage handles saving reports to disk
type Storage struct {
	outputDir string // Directory to save reports
}

// NewStorage creates a new report storage
func NewStorage(outputDir string) *Storage {
	// Create directory if it doesn't exist
	os.MkdirAll(outputDir, 0755)
	return &Storage{outputDir: outputDir}
}

// Save saves a report to disk in multiple formats
func (s *Storage) Save(report *Report, formats []string) (map[string]string, error) {
	results := make(map[string]string)

	// Create a unique filename based on scan ID and timestamp
	baseName := fmt.Sprintf("scan_%d_%d", report.ScanID, time.Now().Unix())

	for _, format := range formats {
		var content []byte
		var extension string

		switch format {
		case "json":
			jsonData, err := (&Generator{}).ToJSON(report)
			if err != nil {
				return nil, fmt.Errorf("failed to generate JSON: %w", err)
			}
			content = jsonData
			extension = "json"

		case "html":
			htmlData, err := (&Generator{}).ToHTML(report)
			if err != nil {
				return nil, fmt.Errorf("failed to generate HTML: %w", err)
			}
			content = []byte(htmlData)
			extension = "html"

		case "md":
			mdData := (&Generator{}).ToMarkdown(report)
			content = []byte(mdData)
			extension = "md"

		default:
			continue // Skip unknown formats
		}

		// Write file
		filename := filepath.Join(s.outputDir, baseName+"."+extension)
		if err := os.WriteFile(filename, content, 0644); err != nil {
			return nil, fmt.Errorf("failed to write %s: %w", filename, err)
		}
		results[format] = filename
	}

	return results, nil
}
