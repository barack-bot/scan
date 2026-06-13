package api

import (
	"net/http"
)

// handleHome shows the landing page
func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	// Check if user is already logged in
	if token := extractToken(r); token != "" {
		if _, err := s.JWTService.ValidateToken(token); err == nil {
			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return
		}
	}

	RenderPage(w, r, "landing", map[string]interface{}{
		"Title":         "KE-SCAN",
		"ActivePage":    "home",
		"IsLandingPage": true,
	})
}
