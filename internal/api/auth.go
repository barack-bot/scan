package api

import (
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

// handleLoginPage shows the login form
func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	// Already logged in? Redirect to dashboard
	if token := extractToken(r); token != "" {
		_, err := s.JWTService.ValidateToken(token)
		if err == nil {
			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return
		}
	}

	data := map[string]interface{}{
		"Title": "Login - KE-SCAN",
		"Error": r.URL.Query().Get("error"),
	}

	RenderPage(w, r, "login", data)
}

// handleLogin processes login form submission
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Parse form
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/login?error=invalid+request", http.StatusFound)
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")

	// Get user from database
	user, err := s.DB.GetUserByEmail(email)
	if err != nil {
		http.Redirect(w, r, "/login?error=invalid+credentials", http.StatusFound)
		return
	}
	if user == nil {
		http.Redirect(w, r, "/login?error=invalid+credentials", http.StatusFound)
		return
	}

	// Check password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		http.Redirect(w, r, "/login?error=invalid+credentials", http.StatusFound)
		return
	}

	// Derive tenant ID from the user record
	var tenantID int64
	if user.TenantID != nil {
		tenantID = *user.TenantID
	} else {
		// Fallback to default tenant if user has no tenant assigned
		tenantID = 1
	}

	// Generate JWT
	token, err := s.JWTService.GenerateToken(user.ID, tenantID, user.Email, user.Role)
	if err != nil {
		http.Redirect(w, r, "/login?error=internal+error", http.StatusFound)
		return
	}

	// Set cookie — MaxAge matches JWT token expiry so cookie doesn't expire before the token
	cookieMaxAge := int(s.Config.JWT.ExpiryHours * 3600)
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   !s.Config.IsDevelopment(),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   cookieMaxAge,
	})

	// HTMX response
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/dashboard")
		w.WriteHeader(http.StatusOK)
		return
	}

	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

// handleRegisterPage shows the registration form
func (s *Server) handleRegisterPage(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Title": "Register - KE-SCAN",
		"Error": r.URL.Query().Get("error"),
	}

	RenderPage(w, r, "register", data)
}

// handleRegister processes registration form submission
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/register?error=invalid+request", http.StatusFound)
		return
	}

	name := r.FormValue("name")
	email := r.FormValue("email")
	password := r.FormValue("password")
	organization := r.FormValue("organization")

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Redirect(w, r, "/register?error=internal+error", http.StatusFound)
		return
	}

	// Default organization name if not provided
	if organization == "" {
		organization = name + "'s Organization"
	}

	// Create a tenant for the new user (multi-tenant isolation)
	tenantDomain := extractDomainFromEmail(email)
	tenant, err := s.DB.CreateTenant(organization, tenantDomain, "free", "")
	if err != nil {
		// If tenant creation fails (e.g., duplicate domain), try with a unique name
		tenant, err = s.DB.CreateTenant(name+"'s Organization", email+"-tenant", "free", "")
		if err != nil {
			http.Redirect(w, r, "/register?error=registration+failed", http.StatusFound)
			return
		}
	}

	tenantID := tenant.ID

	// Create user with tenant association
	user, err := s.DB.CreateUserWithTenant(email, string(hashedPassword), name, "user", &tenantID)
	if err != nil {
		// Rollback: delete the orphaned tenant since user creation failed
		_ = s.DB.DeleteTenant(tenantID)
		http.Redirect(w, r, "/register?error=email+already+exists", http.StatusFound)
		return
	}

	// Send welcome email (only if mailer configured)
	if s.Mailer != nil {
		go s.Mailer.SendWelcomeEmail(user.Email, user.Name)
	}

	// Log them in automatically
	token, _ := s.JWTService.GenerateToken(user.ID, tenantID, user.Email, user.Role)
	cookieMaxAge := int(s.Config.JWT.ExpiryHours * 3600)
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   cookieMaxAge,
	})

	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

// handleLogout logs the user out
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Clear the auth cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	http.Redirect(w, r, "/login", http.StatusFound)
}

// extractDomainFromEmail extracts a domain string from an email address for tenant creation
func extractDomainFromEmail(email string) string {
	for i := len(email) - 1; i >= 0; i-- {
		if email[i] == '@' {
			domain := email[i+1:]
			if domain != "" {
				return domain
			}
		}
	}
	return email + "-domain"
}
