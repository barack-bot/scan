// Package scanner — subdomain discovery module.
// Enumerates subdomains via DNS resolution against a common wordlist,
// identifies which ones are live, and runs existing checks against each.
package scanner

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"ke-scan/internal/db"
)

// SubdomainScanner performs wordlist-based subdomain enumeration
// and runs security checks against discovered subdomains.
type SubdomainScanner struct {
	engine *Engine
}

// NewSubdomainScanner creates a new subdomain discovery scanner.
func NewSubdomainScanner(engine *Engine) *SubdomainScanner {
	return &SubdomainScanner{engine: engine}
}

// Run scans all discovered subdomains for a given root domain.
// It finds live subdomains and runs the full scan pipeline against each.
func (s *SubdomainScanner) Run(parentScanID int64, rootDomain string) []*db.Finding {
	log.Printf("Subdomain discovery starting for %s", rootDomain)

	// Step 1: enumerate subdomains via DNS
	subdomains := s.enumerate(rootDomain)
	log.Printf("Subdomain discovery: found %d live subdomains for %s", len(subdomains), rootDomain)

	if len(subdomains) == 0 {
		return nil
	}

	// Step 2: scan each discovered subdomain
	var mu sync.Mutex
	var allFindings []*db.Finding
	var wg sync.WaitGroup

	// Limit concurrency to avoid overwhelming DNS/HTTP
	sem := make(chan struct{}, 5)

	for _, sub := range subdomains {
		wg.Add(1)
		sem <- struct{}{}

		go func(subdomain string) {
			defer wg.Done()
			defer func() { <-sem }()

			findings := s.scanSubdomain(parentScanID, subdomain)
			mu.Lock()
			allFindings = append(allFindings, findings...)
			mu.Unlock()
		}(sub)
	}

	wg.Wait()
	log.Printf("Subdomain discovery complete for %s: %d total findings", rootDomain, len(allFindings))
	return allFindings
}

// enumerate uses DNS resolution to find live subdomains from a wordlist.
func (s *SubdomainScanner) enumerate(rootDomain string) []string {
	// Common subdomain wordlist — covers the highest-value targets
	wordlist := []string{
		"www", "mail", "ftp", "localhost", "webmail", "smtp", "pop",
		"ns1", "ns2", "ns3", "dns", "dns1", "dns2",
		"api", "api2", "api3", "dev", "dev2", "staging", "stage", "test", "testing", "sandbox", "qa",
		"admin", "administrator", "portal", "login", "dashboard", "panel", "manage", "console",
		"app", "app2", "mobile", "m",
		"shop", "store", "pay", "checkout", "billing", "payment",
		"blog", "forum", "community", "wiki", "docs", "help", "support", "kb",
		"cdn", "static", "assets", "media", "images", "img", "files", "download", "downloads",
		"status", "monitor", "grafana", "prometheus", "kibana", "elastic", "sentry",
		"ci", "cd", "jenkins", "gitlab", "git", "bitbucket", "repo", "repository",
		"db", "database", "mysql", "postgres", "mongo", "redis", "elasticsearch", "sql",
		"vpn", "remote", "rdp", "ssh", "sftp", "jump",
		"old", "backup", "bak", "temp", "tmp", "archive", "legacy", "v1", "v2", "v3",
		"staging1", "staging2", "dev1", "dev2", "qa1", "qa2",
		"intranet", "internal", "corp", "private", "hidden", "secret",
		"oauth", "sso", "auth", "id", "identity",
		"webdisk", "cpanel", "whm", "plesk", "webhost",
		"calendar", "crm", "erp", "hr", "jira", "confluence", "slack",
		"s3", "aws", "cloud", "azure", "gcp",
		"mx", "mx1", "mx2", "imap", "pop3",
		"autodiscover", "autoconfig", "autoupdate",
		"search", "engine", "index",
		"new", "beta", "alpha", "demo", "preview", "canary",
		"proxy", "gateway", "load", "balancer", "edge",
		"analytics", "stats", "metrics", "log", "logs",
		"email", "smtp2", "mail2",
		"secure", "ssl", "tls", "cert",
		"raw", "socket", "ws", "wss", "socketio",
		"registry", "docker", "container", "k8s", "kubernetes",
		"backup1", "db1", "test1", "dev3", "staging3",
	}

	liveSubdomains := make(chan string, len(wordlist))
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Resolve concurrently
	sem := make(chan struct{}, 50) // DNS can handle more concurrency

	for _, word := range wordlist {
		wg.Add(1)
		sem <- struct{}{}

		go func(w string) {
			defer wg.Done()
			defer func() { <-sem }()

			fqdn := w + "." + rootDomain

			// DNS resolution
			_, err := net.LookupHost(fqdn)
			if err != nil {
				return // subdomain doesn't exist
			}

			// Verify it's actually reachable via HTTP/HTTPS
			if isReachable(fqdn) {
				liveSubdomains <- fqdn
			}
		}(word)
	}

	// Wait for all goroutines to finish
	go func() {
		wg.Wait()
		close(liveSubdomains)
	}()

	var results []string
	for sub := range liveSubdomains {
		mu.Lock()
		results = append(results, sub)
		mu.Unlock()
	}

	return results
}

// isReachable checks if a host is reachable via HTTP or HTTPS.
func isReachable(host string) bool {
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Try HTTPS first
	resp, err := client.Head("https://" + host)
	if err == nil {
		resp.Body.Close()
		return true
	}

	// Try HTTP
	resp, err = client.Head("http://" + host)
	if err == nil {
		resp.Body.Close()
		return true
	}

	return false
}

// scanSubdomain runs the existing check modules against a single subdomain.
func (s *SubdomainScanner) scanSubdomain(parentScanID int64, subdomain string) []*db.Finding {
	targetURL := "https://" + subdomain

	// Run TLS checks
	tlsFindings, _ := s.engine.runTLSChecks(parentScanID, targetURL)

	// Run header checks
	headerFindings, _ := s.engine.runHeaderChecks(parentScanID, targetURL)

	// Run CVE checks
	cveFindings, _ := s.engine.runCVEChecks(parentScanID, targetURL)

	// Tag all findings as subdomain findings
	allFindings := make([]*db.Finding, 0)
	allFindings = append(allFindings, tlsFindings...)
	allFindings = append(allFindings, headerFindings...)
	allFindings = append(allFindings, cveFindings...)

	for _, f := range allFindings {
		if f.Evidence != "" {
			f.Evidence = fmt.Sprintf("[Subdomain: %s] %s", subdomain, f.Evidence)
		}
		if f.AffectedComponent == "" {
			f.AffectedComponent = subdomain
		}
	}

	// NOTE: Findings are NOT persisted here to avoid duplicate writes.
	// The caller (RunScan via runFullScan) persists all findings returned from this function.
	// Previously, findings were written both here AND in RunScan, causing duplicates.

	return allFindings
}

// extractDomainFromURL pulls the domain from a URL.
func extractDomainFromURL(rawURL string) string {
	host := rawURL
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}
	return host
}
