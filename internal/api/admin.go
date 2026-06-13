package api

import (
	"ke-scan/internal/db"
	"net/http"
)

// handleAdminDashboard shows admin overview
func (s *Server) handleAdminDashboard(w http.ResponseWriter, r *http.Request) {
	// Get stats
	totalUsers, _ := s.DB.GetTotalUsers()
	totalScans, _ := s.DB.GetTotalScans()
	totalTenants, _ := s.DB.GetTotalTenants()

	data := map[string]interface{}{
		"Title":        "Admin Dashboard - KE-SCAN",
		"TotalUsers":   totalUsers,
		"TotalScans":   totalScans,
		"TotalTenants": totalTenants,
		"ActivePage":   "admin",
	}

	RenderPage(w, r, "admin", data)
}

// handleAdminUsers lists all users
func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.DB.ListUsers(100, 0)
	if err != nil {
		users = []*db.User{}
	}

	data := map[string]interface{}{
		"Title": "Manage Users - KE-SCAN",
		"Users": users,
	}

	RenderPage(w, r, "admin_users", data)
}

// handleAdminTenants lists all tenants
func (s *Server) handleAdminTenants(w http.ResponseWriter, r *http.Request) {
	tenants, err := s.DB.ListTenants(100, 0)
	if err != nil {
		tenants = []*db.Tenant{}
	}

	data := map[string]interface{}{
		"Title":   "Manage Tenants - KE-SCAN",
		"Tenants": tenants,
	}

	RenderPage(w, r, "admin_tenants", data)
}
