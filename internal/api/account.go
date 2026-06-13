package api

import (
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

// handleAccountPage shows account settings
func (s *Server) handleAccountPage(w http.ResponseWriter, r *http.Request) {
	userID, _ := GetUserID(r)

	user, err := s.DB.GetUserByID(userID)
	if err != nil || user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	data := map[string]interface{}{
		"Title": "Account Settings - KE-SCAN",
		"User":  user,
	}

	RenderPage(w, r, "account", data)
}

// handleUpdateAccount processes account updates
func (s *Server) handleUpdateAccount(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	userID, _ := GetUserID(r)
	name := r.FormValue("name")
	currentPassword := r.FormValue("current_password")
	newPassword := r.FormValue("new_password")
	confirmPassword := r.FormValue("confirm_password")

	// Get current user
	user, err := s.DB.GetUserByID(userID)
	if err != nil || user == nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Verify current password if changing password
	if newPassword != "" {
		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(currentPassword)); err != nil {
			http.Error(w, "Current password is incorrect", http.StatusUnauthorized)
			return
		}

		// Check if new password and confirmation match
		if newPassword != confirmPassword {
			http.Error(w, "New password and confirmation do not match", http.StatusBadRequest)
			return
		}

		// Update password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Failed to update password", http.StatusInternalServerError)
			return
		}
		if err := s.DB.UpdateUserPassword(userID, string(hashedPassword)); err != nil {
			http.Error(w, "Failed to update password", http.StatusInternalServerError)
			return
		}
	}

	// Only update name/email if this is a profile update (not a password-only change)
	action := r.FormValue("action")
	if action != "password" {
		if name != "" && name != user.Name {
			if err := s.DB.UpdateUser(userID, name, user.Role); err != nil {
				http.Error(w, "Failed to update user", http.StatusInternalServerError)
				return
			}
		}
	}

	// HTMX response
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Trigger", "showMessage")
		w.Write([]byte(`<div class="alert alert-success">Account updated successfully!</div>`))
		return
	}

	http.Redirect(w, r, "/account", http.StatusFound)
}
