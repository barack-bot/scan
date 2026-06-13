// Package loader loads CVE vulnerability data from JSON files
package loader

import (
	"bytes"
	"encoding/json" // For parsing JSON files
	"fmt"           // For formatting errors
	"log"
	"os"            // For reading files
	"path/filepath" // For walking directories
	"strings"       // For string manipulation
)

// CVE represents a Common Vulnerabilities and Exposures entry
type CVE struct {
	ID               string              `json:"id"`                // CVE-2021-41773
	Title            string              `json:"title"`             // Short description
	Description      string              `json:"description"`       // Detailed explanation
	Severity         string              `json:"severity"`          // critical, high, medium, low
	CVSSScore        float64             `json:"cvss_score"`        // 0.0 - 10.0
	AffectedSoftware []string            `json:"affected_software"` // ["apache", "httpd"]
	AffectedVersions map[string][]string `json:"affected_versions"` // {"apache": [">=2.2.0 <2.2.33", ">=2.4.0 <2.4.26"]}
	Grants           []string            `json:"grants"`            // Capabilities granted when CVE is exploited (e.g. ["rce", "file_read"])
	Remediation      string              `json:"remediation"`       // How to fix
	ExploitAvailable bool                `json:"exploit_available"` // Is there a public exploit?
	ODPCSection      string              `json:"odpc_section"`      // Related DPA section
	References       []string            `json:"references"`        // URLs for more info
}

// Loader loads CVEs from the data/cves directory
type Loader struct {
	cves       []*CVE            // All loaded CVEs
	byID       map[string]*CVE   // Index by CVE ID
	bySoftware map[string][]*CVE // Index by software name
}

// NewLoader creates a new CVE loader
func NewLoader() *Loader {
	return &Loader{
		cves:       make([]*CVE, 0),
		byID:       make(map[string]*CVE),
		bySoftware: make(map[string][]*CVE),
	}
}

// LoadAll scans the data/cves directory and loads all JSON files
func (l *Loader) LoadAll(cvesPath string) error {
	// Walk through all subdirectories
	err := filepath.Walk(cvesPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories, only process JSON files
		if info.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}

		// Load the CVE from this file
		return l.LoadFile(path)
	})

	if err != nil {
		return fmt.Errorf("failed to load CVEs: %w", err)
	}

	return nil
}

// LoadFile loads a single CVE JSON file
func (l *Loader) LoadFile(path string) error {
	// Read the file
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", path, err)
	}

	// Check for duplicate JSON keys before parsing
	if err := checkDuplicateKeys(data); err != nil {
		log.Printf("Warning: %s has duplicate JSON keys: %v", path, err)
	}

	// Parse JSON
	var cve CVE
	if err := json.Unmarshal(data, &cve); err != nil {
		return fmt.Errorf("failed to parse %s: %w", path, err)
	}

	// Validate that CVE has meaningful content
	if cve.ID == "" {
		return fmt.Errorf("empty or invalid CVE at %s: ID field is required", path)
	}

	// Add to in-memory storage
	l.cves = append(l.cves, &cve)
	l.byID[cve.ID] = &cve

	// Index by software
	for _, software := range cve.AffectedSoftware {
		software = strings.ToLower(software)
		l.bySoftware[software] = append(l.bySoftware[software], &cve)
	}

	return nil
}

// GetByID returns a CVE by its ID
func (l *Loader) GetByID(id string) *CVE {
	return l.byID[id]
}

// GetBySoftware returns all CVEs affecting a specific software
func (l *Loader) GetBySoftware(software string) []*CVE {
	software = strings.ToLower(software)
	return l.bySoftware[software]
}

// GetAll returns all loaded CVEs
func (l *Loader) GetAll() []*CVE {
	return l.cves
}

// GetCritical returns only critical severity CVEs
func (l *Loader) GetCritical() []*CVE {
	var critical []*CVE
	for _, cve := range l.cves {
		if cve.Severity == "critical" {
			critical = append(critical, cve)
		}
	}
	return critical
}

// GetBySeverity returns CVEs of a specific severity
func (l *Loader) GetBySeverity(severity string) []*CVE {
	var result []*CVE
	for _, cve := range l.cves {
		if strings.EqualFold(cve.Severity, severity) {
			result = append(result, cve)
		}
	}
	return result
}

// checkDuplicateKeys scans JSON data for duplicate keys at each object level.
// In Go's encoding/json, when duplicate keys exist, the last value wins silently.
// This function warns about duplicates so they can be fixed.
func checkDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	depth := 0
	keys := make(map[string]bool)
	for {
		tok, err := dec.Token()
		if err != nil {
			return nil // EOF or valid JSON
		}
		switch v := tok.(type) {
		case json.Delim:
			if v == '{' || v == '[' {
				depth++
			} else {
				depth--
				if depth <= 0 {
					keys = make(map[string]bool)
				}
			}
		case string:
			if depth == 1 {
				if keys[v] {
					return fmt.Errorf("duplicate key: %q", v)
				}
				keys[v] = true
			}
		}
	}
}
