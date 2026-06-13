package api

import (
	"html/template"
	"log"
	"net/http"
	"strings"

	"ke-scan/embed"
)

type Renderer struct {
	// We no longer keep a single flat execution group for pages
}

var templateFuncMap = template.FuncMap{
	"toUpper": strings.ToUpper,
	"toLower": strings.ToLower,
	"not": func(b bool) bool {
		return !b
	},
	"truncate": func(s string, n int) string {
		if len(s) <= n {
			return s
		}
		return s[:n] + "..."
	},
	"inc": func(i int) int {
		return i + 1
	},
	"mul": func(a, b float64) float64 {
		return a * b
	},
	"sub": func(a, b int) int {
		return a - b
	},
	// len is intentionally not registered here — it's a built-in Go template function
	// that works on strings, slices, and maps.
	"slice": func(s string, start, end int) string {
		if start < 0 {
			start = 0
		}
		if end > len(s) {
			end = len(s)
		}
		if start >= end {
			return ""
		}
		return s[start:end]
	},
}

// NewRenderer is now a cheap instantiator
func NewRenderer() (*Renderer, error) {
	return &Renderer{}, nil
}

func RenderPage(w http.ResponseWriter, r *http.Request, name string, data interface{}) {
	renderer, _ := NewRenderer()
	renderer.Render(w, r, name, data)
}

func RenderPartialPage(w http.ResponseWriter, r *http.Request, name string, data interface{}) {
	renderer, _ := NewRenderer()
	renderer.RenderPartial(w, r, name, data)
}

// Render compiles the layout alongside ONLY the requested page + partials to avoid definition overwrites
func (r *Renderer) Render(w http.ResponseWriter, req *http.Request, name string, data interface{}) {
	isHTMX := req.Header.Get("HX-Request") == "true"
	enriched := enrichTemplateData(req, data)
	templatesFS := embed.GetTemplatesFS()

	// Normalize: strip .html if present — template defines use the base name
	if strings.HasSuffix(name, ".html") {
		name = strings.TrimSuffix(name, ".html")
	}

	// 1. Handle HTMX requests
	if isHTMX {
		var templatePath string

		if _, err := templatesFS.Open("templates/partials/" + name + ".html"); err == nil {
			templatePath = "templates/partials/" + name + ".html"
		} else {
			templatePath = "templates/pages/" + name + ".html"
		}

		// Also read inside partials case if a page rendered via HTMX includes sub-blocks
		tmpl, err := template.New(name).Funcs(templateFuncMap).ParseFS(templatesFS, templatePath, "templates/partials/*.html")
		if err != nil {
			log.Printf("HTMX Parse Error: %v", err)
			http.Error(w, "Template error", http.StatusInternalServerError)
			return
		}

		err = tmpl.ExecuteTemplate(w, name, enriched)
		if err != nil {
			log.Printf("HTMX Execution Error: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// 2. Handle Full Browser Requests (FIXES THE MISSING "scan_row" BUG)
	tmpl := template.New("base.html").Funcs(templateFuncMap)

	// Parse the layouts
	_, err := tmpl.ParseFS(templatesFS, "templates/layouts/*.html")
	if err != nil {
		log.Printf("Layout Parse Error: %v", err)
		http.Error(w, "Layout parsing error", http.StatusInternalServerError)
		return
	}

	// FIX: Parse BOTH the specific page AND all structural partials (*.html)
	// so dashboard.html can find "scan_row" without clashing with other pages.
	pagePath := "templates/pages/" + name + ".html"
	_, err = tmpl.ParseFS(templatesFS, pagePath, "templates/partials/*.html")
	if err != nil {
		log.Printf("Page/Partials Parse Error (%s): %v", pagePath, err)
		http.Error(w, "Page template initialization failed", http.StatusInternalServerError)
		return
	}

	// Execute base layout
	err = tmpl.ExecuteTemplate(w, "base.html", enriched)
	if err != nil {
		log.Printf("Full Page Template Execution Error: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// RenderPartial explicitly renders individual structural dashboard pieces
func (r *Renderer) RenderPartial(w http.ResponseWriter, req *http.Request, name string, data interface{}) {
	enriched := enrichTemplateData(req, data)
	templatesFS := embed.GetTemplatesFS()

	if strings.HasSuffix(name, ".html") {
		name = strings.TrimSuffix(name, ".html")
	}

	targetPath := "templates/partials/" + name + ".html"
	// Use name (without .html) to match the {{define "name"}} block in the partial file
	tmpl, err := template.New(name).Funcs(templateFuncMap).ParseFS(templatesFS, targetPath)
	if err != nil {
		log.Printf("Partial Parse Error: %v", err)
		http.Error(w, "Partial template error", http.StatusInternalServerError)
		return
	}

	err = tmpl.ExecuteTemplate(w, name, enriched)
	if err != nil {
		log.Printf("Partial Execution Error: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func enrichTemplateData(req *http.Request, data interface{}) map[string]interface{} {
	out := map[string]interface{}{}

	if data != nil {
		if m, ok := data.(map[string]interface{}); ok {
			for k, v := range m {
				out[k] = v
			}
		} else {
			out["Data"] = data
		}
	}

	if claims, ok := GetClaims(req); ok && claims != nil {
		out["IsAuthenticated"] = true
		out["UserEmail"] = claims.Email
		out["UserRole"] = claims.Role
	} else {
		out["IsAuthenticated"] = false
		out["UserEmail"] = ""
	}

	if _, exists := out["CSRFToken"]; !exists {
		out["CSRFToken"] = ""
	}

	// Default IsLandingPage to false for all pages that don't explicitly set it
	if _, exists := out["IsLandingPage"]; !exists {
		out["IsLandingPage"] = false
	}

	return out
}
