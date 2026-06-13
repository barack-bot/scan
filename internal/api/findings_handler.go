package api

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
)

// handleUpdateFindingStatus updates a finding's status (acknowledge/resolve)
func (s *Server) handleUpdateFindingStatus(w http.ResponseWriter, r *http.Request) {
	findingID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || findingID == 0 {
		http.Error(w, "Invalid finding ID", http.StatusBadRequest)
		return
	}

	status := r.FormValue("status")
	if status == "" {
		// Support JSON body as well
		var req struct {
			Status string `json:"status"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
			status = req.Status
		}
	}

	if status != "acknowledged" && status != "resolved" {
		http.Error(w, "Invalid status. Must be 'acknowledged' or 'resolved'", http.StatusBadRequest)
		return
	}

	// Get current user ID for resolving
	userID, _ := GetUserID(r)
	var userIDPtr *int64
	if status == "resolved" {
		userIDPtr = &userID
	}

	if err := s.DB.UpdateFindingStatus(findingID, status, userIDPtr); err != nil {
		log.Printf("Error updating finding %d status to %s: %v", findingID, status, err)
		http.Error(w, "Failed to update finding status", http.StatusInternalServerError)
		return
	}

	// Return updated finding for HTMX swap
	if r.Header.Get("HX-Request") == "true" {
		// We need to re-fetch the finding to render the updated card
		// For simplicity, re-use scanFindings pattern by getting the full finding
		// Since we don't have a GetFindingByID, we redirect to refresh
		w.Header().Set("HX-Redirect", r.Header.Get("HX-Current-URL"))
		w.WriteHeader(http.StatusOK)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": status})
}

// handleMarkNotificationRead marks a notification as read
func (s *Server) handleMarkNotificationRead(w http.ResponseWriter, r *http.Request) {
	notifID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || notifID == 0 {
		http.Error(w, "Invalid notification ID", http.StatusBadRequest)
		return
	}

	if err := s.DB.MarkNotificationRead(notifID); err != nil {
		log.Printf("Error marking notification %d as read: %v", notifID, err)
		http.Error(w, "Failed to update notification", http.StatusInternalServerError)
		return
	}

	if r.Header.Get("HX-Request") == "true" {
		w.WriteHeader(http.StatusOK)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "read"})
}

// handlePaymentsCallback handles M-PESA STK push callback from Safaricom
func (s *Server) handlePaymentsCallback(w http.ResponseWriter, r *http.Request) {
	// Parse the M-PESA callback JSON body
	var callback struct {
		Body struct {
			StkCallback struct {
				MerchantRequestID string `json:"MerchantRequestID"`
				CheckoutRequestID string `json:"CheckoutRequestID"`
				ResultCode        int    `json:"ResultCode"`
				ResultDesc        string `json:"ResultDesc"`
				CallbackMetadata  *struct {
					Item []struct {
						Name  string      `json:"Name"`
						Value interface{} `json:"Value"`
					} `json:"Item"`
				} `json:"CallbackMetadata"`
			} `json:"stkCallback"`
		} `json:"Body"`
	}

	if err := json.NewDecoder(r.Body).Decode(&callback); err != nil {
		log.Printf("M-PESA callback parse error: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	stk := callback.Body.StkCallback
	log.Printf("M-PESA callback: CheckoutRequestID=%s, ResultCode=%d, ResultDesc=%s",
		stk.CheckoutRequestID, stk.ResultCode, stk.ResultDesc)

	// Extract transaction details from metadata if present
	if stk.CallbackMetadata != nil {
		for _, item := range stk.CallbackMetadata.Item {
			switch item.Name {
			case "MpesaReceiptNumber":
				if v, ok := item.Value.(string); ok {
					log.Printf("M-PESA Receipt: %s", v)
				}
			case "TransactionDate":
				log.Printf("Transaction Date: %v", item.Value)
			}
		}
	}

	// Respond with success to Safaricom
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"ResultCode": "0", "ResultDesc": "Success"})
}

// handleListAPIKeys returns API keys for the current tenant (stub)
func (s *Server) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode([]map[string]interface{}{})
}

// handleCreateAPIKey creates a new API key for the current tenant (stub)
func (s *Server) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "API key creation not yet implemented"})
}

// handleDeleteAPIKey deletes an API key (stub)
func (s *Server) handleDeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "API key deletion not yet implemented"})
}
