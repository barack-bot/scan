package api

import (
	"net/http"
	"strconv"
)

// handlePaymentsPage shows payment options
func (s *Server) handlePaymentsPage(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Title":       "Payments - KE-SCAN",
		"Plan":        "business", // Get from tenant
		"Amount":      4500,
		"Currency":    "KES",
		"CallbackURL": s.Config.GetBaseURL() + "/payments/callback",
	}

	RenderPage(w, r, "payments", data)
}

// handleInitiatePayment starts an M-PESA payment
func (s *Server) handleInitiatePayment(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	phoneNumber := r.FormValue("phone")
	amountStr := r.FormValue("amount")
	plan := r.FormValue("plan")

	// Validate that the amount corresponds to the selected plan
	// Define valid plan amounts (in KES)
	planPrices := map[string]int{
		"free":       0,
		"starter":    1500,
		"business":   4500,
		"enterprise": 15000,
	}

	// Parse the amount to integer for comparison
	amountInt, err := strconv.Atoi(amountStr)
	if err != nil {
		http.Error(w, "Invalid payment amount", http.StatusBadRequest)
		return
	}

	// Check if the plan exists and the amount matches
	expectedPrice, planExists := planPrices[plan]
	if !planExists {
		http.Error(w, "Invalid subscription plan selected", http.StatusBadRequest)
		return
	}

	if amountInt < expectedPrice {
		http.Error(w, "Payment amount is less than the selected plan price", http.StatusBadRequest)
		return
	}

	// Generate unique account reference
	claims, _ := GetClaims(r)
	accountRef := "KE-SCAN-" + strconv.FormatInt(claims.TenantID, 10) + "-" + plan

	// Get callback URL from config
	baseURL := s.Config.GetBaseURL()
	callbackURL := baseURL + "/api/payments/callback"

	// Initiate STK push
	response, err := s.Mpesa.InitiateSTKPush(phoneNumber, amountStr, accountRef, callbackURL)
	if err != nil {
		http.Error(w, "Payment initiation failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Store checkout request ID for verification
	// In production, save to database

	// HTMX response
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Trigger", "paymentInitiated")
		w.Write([]byte(`<div class="alert info">Check your phone for M-PESA prompt. Enter PIN to complete payment.</div>`))
		return
	}

	data := map[string]interface{}{
		"CheckoutRequestID": response.CheckoutRequestID,
		"Message":           response.CustomerMessage,
	}

	RenderPage(w, r, "payment_status", data)
}
