package scanner

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Fingerprint holds detailed technology guesses with confidence levels
type Fingerprint struct {
	Software   string  // "apache", "nginx", "php", "unknown"
	Version    string  // Extracted version or ""
	Confidence float64 // 0.0 (none) to 1.0 (absolute certainty)
	IsHidden   bool    // True if server explicitly tried to hide its identity
}

// Fingerprinter performs advanced heuristic fingerprinting against target infrastructures
type Fingerprinter struct {
	TargetURL string
	client    *http.Client
}

// NewFingerprinter creates a new resilient fingerprint helper
func NewFingerprinter(targetURL string) *Fingerprinter {
	return &Fingerprinter{
		TargetURL: targetURL,
		client: &http.Client{
			Timeout: 8 * time.Second,
			Transport: &http.Transport{
				// InsecureSkipVerify: true is intentional here. The fingerprinter probes
				// targets that may have self-signed, expired, or otherwise invalid TLS certs
				// (e.g., internal/dev servers). We still need to read response headers/banners
				// to fingerprint the software stack regardless of TLS validity. The actual
				// certificate validation is handled separately in the TLS checker module.
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return http.ErrUseLastResponse // Don't get trapped in infinite redirect loops
				}
				return nil
			},
		},
	}
}

// Profile Target analyzes the remote system utilizing banner-grabbing and behavioral heuristics
func (f *Fingerprinter) ProfileTarget() Fingerprint {
	fp := Fingerprint{Software: "unknown", Version: "", Confidence: 0.1, IsHidden: false}

	parsed, err := url.Parse(f.TargetURL)
	if err != nil || parsed.Host == "" {
		return fp
	}

	// Probe 1: Analyze standard HEAD request response signatures
	resp, err := f.client.Head(f.TargetURL)
	if err != nil {
		// Fallback to GET if HEAD method is blocked by a firewall
		resp, err = f.client.Get(f.TargetURL)
		if err != nil {
			return fp // Host is unreachable
		}
	}
	defer resp.Body.Close()

	serverHeader := resp.Header.Get("Server")
	poweredBy := resp.Header.Get("X-Powered-By")

	// Baseline: Explicit header definitions are present
	if serverHeader != "" || poweredBy != "" {
		fp.Confidence = 0.95
		serverLower := strings.ToLower(serverHeader)
		pbLower := strings.ToLower(poweredBy)

		if strings.Contains(serverLower, "apache") || strings.Contains(serverLower, "httpd") {
			fp.Software = "apache"
			fp.Version = f.extractVersion(serverHeader, "apache")
			if fp.Version == "" {
				fp.Version = f.extractVersion(serverHeader, "httpd")
			}
			return fp
		}
		if strings.Contains(serverLower, "nginx") {
			fp.Software = "nginx"
			fp.Version = f.extractVersion(serverHeader, "nginx")
			return fp
		}
		if strings.Contains(pbLower, "php") || strings.Contains(serverLower, "php") {
			fp.Software = "php"
			fp.Version = f.extractVersion(pbLower, "php")
			if fp.Version == "" {
				fp.Version = f.extractVersion(serverLower, "php")
			}
			return fp
		}
	}

	// Probe 2: Behavioral Heuristics (Handling Hiding Servers)
	fp.IsHidden = true

	// Execute an intentional bad HTTP Request (TRACK) to observe stack error behaviors
	req, _ := http.NewRequest("TRACK", f.TargetURL, nil)
	badResp, err := f.client.Do(req)
	if err == nil {
		defer badResp.Body.Close()

		serverHint := strings.ToLower(badResp.Header.Get("Server"))

		// Apache servers typically reply with 403 Forbidden or 405 Method Not Allowed to invalid methods
		// and leave specific response artifacts like a "Keep-Alive" header configuration.
		// However, many reverse proxies (Nginx, Cloudflare, HAProxy) can produce the same response,
		// so we require corroborating signals before concluding Apache.
		if badResp.StatusCode == 403 && badResp.Header.Get("Keep-Alive") != "" {
			if strings.Contains(serverHint, "apache") || strings.Contains(serverHint, "httpd") {
				// Server header explicitly reveals Apache
				fp.Software = "apache"
				fp.Confidence = 0.65
			} else {
				// Weak signal: 403 + Keep-Alive could be any reverse proxy
				fp.Software = "apache"
				fp.Confidence = 0.35
			}
			return fp
		}

		// Nginx servers handle abnormal verbs with specific default content types or clean 405 templates
		if badResp.StatusCode == 405 && strings.Contains(strings.ToLower(badResp.Header.Get("Content-Type")), "text/html") {
			if strings.Contains(serverHint, "nginx") {
				fp.Software = "nginx"
				fp.Confidence = 0.65
			} else {
				fp.Software = "nginx"
				fp.Confidence = 0.40
			}
			return fp
		}
	}

	// Probe 3: Check for PHP residue fingerprints (PHPSESSID cookies)
	for _, cookie := range resp.Cookies() {
		if strings.Contains(strings.ToUpper(cookie.Name), "PHPSESSID") {
			fp.Software = "php"
			fp.Confidence = 0.80
			fp.IsHidden = false // App configuration leak, not actively concealed infrastructure
			return fp
		}
	}

	return fp
}

func (f *Fingerprinter) extractVersion(val, match string) string {
	idx := strings.Index(strings.ToLower(val), match)
	if idx == -1 {
		return ""
	}
	sub := val[idx+len(match):]
	sub = strings.TrimLeft(sub, "/ ")
	fields := strings.FieldsFunc(sub, func(r rune) bool {
		return r == ' ' || r == '(' || r == ';' || r == '\n'
	})
	if len(fields) > 0 {
		return fields[0]
	}
	return ""
}
