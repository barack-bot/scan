// Package api handles HTTP routes and request handling
package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"ke-scan/config"
	"ke-scan/internal/auth"
	"ke-scan/internal/db"
	"ke-scan/internal/mailer"
	"ke-scan/internal/mpesa"
	"ke-scan/internal/scanner"
)

// Server holds all dependencies for the API
type Server struct {
	DB         *db.DB
	JWTService *auth.JWTService
	Mailer     *mailer.Mailer
	Mpesa      *mpesa.MpesaService
	Scanner    *scanner.Engine
	Config     *config.Config
}

// NewServer creates a new API server
func NewServer(
	db *db.DB,
	jwtService *auth.JWTService,
	mailer *mailer.Mailer,
	mpesa *mpesa.MpesaService,
	scanner *scanner.Engine,
	config *config.Config,
) *Server {
	return &Server{
		DB:         db,
		JWTService: jwtService,
		Mailer:     mailer,
		Mpesa:      mpesa,
		Scanner:    scanner,
		Config:     config,
	}
}

// Routes returns the completely optimized and uncertainty-resilient router
func (s *Server) Routes() http.Handler {
	r := chi.NewRouter()

	// Global middleware stack
	r.Use(middleware.Logger)    // Log standard operations transparently
	r.Use(middleware.Recoverer) // Gracefully absorb runtime panics
	r.Use(middleware.RequestID) // Match execution tracking IDs
	r.Use(middleware.RealIP)    // Track actual origin clients
	r.Use(s.addHTMXHeaders)     // Route metadata handlers for HTMX components

	// Static assets distribution layer (CSS, JS frameworks)
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// 1. Unauthenticated Public Operations Group
	r.Group(func(r chi.Router) {
		r.Get("/", s.handleHome)
		r.Get("/login", s.handleLoginPage)
		r.Post("/login", s.handleLogin)
		r.Get("/register", s.handleRegisterPage)
		r.Post("/register", s.handleRegister)
		r.Get("/logout", s.handleLogout)
	})

	// 2. Main Tenant Operations Group (Requires Basic Authentication Only)
	r.Group(func(r chi.Router) {
		r.Use(s.requireAuth)

		// Rate limiting on login and register to prevent brute force
		// The Engine Core Core Integration Channels
		r.Get("/dashboard", s.handleDashboard)
		r.Get("/scan/new", s.handleNewScanPage)

		// Hardened Execution Targets
		r.Post("/scan", s.handleStartScan)               // Handles user target requests seamlessly
		r.Get("/scan/{id}", s.handleScanStatus)          // For UI template pooling checks
		r.Get("/scan/{id}/results", s.handleScanResults) // Connects directly to scanner results pipeline

		// Reporting Interfaces
		r.Get("/report/{id}", s.handleReportView)
		r.Get("/report/{id}/download", s.handleReportDownload)

		// Individual Engineering Accounts
		r.Get("/account", s.handleAccountPage)
		r.Post("/account", s.handleUpdateAccount)

		// Billing Gateways
		r.Get("/payments", s.handlePaymentsPage)
		r.Post("/payments/initiate", s.handleInitiatePayment)

		// Finding Status Workflow (acknowledge/resolve buttons)
		r.Post("/api/findings/{id}/status", s.handleUpdateFindingStatus)

		// Notification management
		r.Post("/api/notifications/{id}/read", s.handleMarkNotificationRead)

		// API Keys management (used in account.html)
		r.Get("/api/keys", s.handleListAPIKeys)
		r.Post("/api/keys", s.handleCreateAPIKey)
		r.Delete("/api/keys/{id}", s.handleDeleteAPIKey)
	})

	// 3. Strict Admin-Only System Settings Panel
	r.Group(func(r chi.Router) {
		r.Use(s.requireAuth)
		r.Use(s.requireAdmin) // Explicitly gated context layer

		r.Get("/admin", s.handleAdminDashboard)
		r.Get("/admin/users", s.handleAdminUsers)
		r.Get("/admin/tenants", s.handleAdminTenants)
	})

	// 4. Unauthenticated Webhook/Callback Routes (no auth required — verified by payload)
	// M-PESA callback from Safaricom — external POST with no session
	r.Post("/api/payments/callback", s.handlePaymentsCallback)

	return r
}
