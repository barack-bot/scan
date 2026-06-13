// Package mpesa handles M-PESA API integration for payments
package mpesa

import (
	"bytes"           // For building request bodies
	"encoding/base64" // For basic auth encoding
	"encoding/json"   // For parsing API responses
	"fmt"             // For formatting
	"net/http"        // For HTTP requests
	"time"            // For timestamps

	"ke-scan/config" // Our config package
)

// MpesaService handles all M-PESA API operations
type MpesaService struct {
	config  *config.MpesaConfig // M-PESA configuration
	baseURL string              // API base URL (sandbox or production)
	client  *http.Client        // HTTP client for API calls
}

// STKPushRequest represents a Lipa Na M-PESA Online request
type STKPushRequest struct {
	BusinessShortCode string `json:"BusinessShortCode"` // Paybill/Till number
	Password          string `json:"Password"`          // Generated password
	Timestamp         string `json:"Timestamp"`         // Current timestamp
	TransactionType   string `json:"TransactionType"`   // CustomerPayBillOnline
	Amount            string `json:"Amount"`            // Amount to charge
	PartyA            string `json:"PartyA"`            // Customer's phone number
	PartyB            string `json:"PartyB"`            // Business shortcode
	PhoneNumber       string `json:"PhoneNumber"`       // Customer's phone number
	CallBackURL       string `json:"CallBackURL"`       // Where M-PESA sends response
	AccountReference  string `json:"AccountReference"`  // Order ID or reference
	TransactionDesc   string `json:"TransactionDesc"`   // Description of transaction
}

// STKPushResponse represents the response from STK push request
type STKPushResponse struct {
	MerchantRequestID string `json:"MerchantRequestID"`
	CheckoutRequestID string `json:"CheckoutRequestID"`
	ResponseCode      string `json:"ResponseCode"` // "0" means success
	ResponseDesc      string `json:"ResponseDescription"`
	CustomerMessage   string `json:"CustomerMessage"`
}

// TransactionStatus represents the result of a payment
type TransactionStatus struct {
	ResultCode      string `json:"ResultCode"` // "0" means success
	ResultDesc      string `json:"ResultDesc"`
	Amount          string `json:"Amount"`
	TransactionID   string `json:"TransactionID"`
	TransactionDate string `json:"TransactionDate"`
	PhoneNumber     string `json:"PhoneNumber"`
}

// NewMpesaService creates a new M-PESA service
func NewMpesaService(cfg *config.MpesaConfig) *MpesaService {
	// Determine base URL based on environment
	baseURL := "https://sandbox.safaricom.co.ke"
	if cfg.Environment == "production" {
		baseURL = "https://api.safaricom.co.ke"
	}

	return &MpesaService{
		config:  cfg,
		baseURL: baseURL,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// getAccessToken obtains an OAuth token from M-PESA
func (s *MpesaService) getAccessToken() (string, error) {
	// Create basic auth string (consumer key:consumer secret)
	auth := base64.StdEncoding.EncodeToString([]byte(
		s.config.ConsumerKey + ":" + s.config.ConsumerSecret,
	))

	// Create request to M-PESA OAuth endpoint
	url := s.baseURL + "/oauth/v1/generate?grant_type=client_credentials"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Add authorization header
	req.Header.Set("Authorization", "Basic "+auth)

	// Execute request
	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get token: %w", err)
	}
	defer resp.Body.Close()

	// Parse response
	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to parse token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("no access token received")
	}

	return tokenResp.AccessToken, nil
}

// generatePassword creates the password for STK push
func (s *MpesaService) generatePassword(timestamp string) string {
	// Password = base64(Shortcode + Passkey + Timestamp)
	data := s.config.Shortcode + s.config.Passkey + timestamp
	return base64.StdEncoding.EncodeToString([]byte(data))
}

// InitiateSTKPush sends a payment request to customer's phone
func (s *MpesaService) InitiateSTKPush(phoneNumber, amount, accountRef, callbackURL string) (*STKPushResponse, error) {
	// Format phone number (remove leading 0 or +254)
	phoneNumber = formatPhoneNumber(phoneNumber)

	// Get access token for API authentication
	token, err := s.getAccessToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get access token: %w", err)
	}

	// Generate timestamp and password
	timestamp := time.Now().Format("20060102150405")
	password := s.generatePassword(timestamp)

	// Build request body
	request := STKPushRequest{
		BusinessShortCode: s.config.Shortcode,
		Password:          password,
		Timestamp:         timestamp,
		TransactionType:   "CustomerPayBillOnline",
		Amount:            amount,
		PartyA:            phoneNumber,
		PartyB:            s.config.Shortcode,
		PhoneNumber:       phoneNumber,
		CallBackURL:       callbackURL,
		AccountReference:  accountRef,
		TransactionDesc:   "KE-SCAN Payment",
	}

	// Convert request to JSON
	jsonBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	url := s.baseURL + "/mpesa/stkpush/v1/processrequest"
	req, err := http.NewRequest("POST", url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add headers
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	// Execute request
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send STK push: %w", err)
	}
	defer resp.Body.Close()

	// Parse response
	var stkResponse STKPushResponse
	if err := json.NewDecoder(resp.Body).Decode(&stkResponse); err != nil {
		return nil, fmt.Errorf("failed to parse STK response: %w", err)
	}

	// Check if request was successful
	if stkResponse.ResponseCode != "0" {
		return nil, fmt.Errorf("STK push failed: %s", stkResponse.ResponseDesc)
	}

	return &stkResponse, nil
}

// formatPhoneNumber converts phone numbers to format required by M-PESA
func formatPhoneNumber(phone string) string {
	// Remove any non-digit characters
	digits := ""
	for _, c := range phone {
		if c >= '0' && c <= '9' {
			digits += string(c)
		}
	}

	// Remove leading 0 or 254
	if len(digits) == 10 && digits[0] == '0' {
		digits = "254" + digits[1:]
	} else if len(digits) == 12 && digits[:3] == "254" {
		digits = digits // Already correct format
	} else if len(digits) == 9 {
		digits = "254" + digits
	}

	return digits
}

// QueryTransactionStatus checks the status of a payment
func (s *MpesaService) QueryTransactionStatus(checkoutRequestID string) (*TransactionStatus, error) {
	// Get access token
	token, err := s.getAccessToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get access token: %w", err)
	}

	// Build query request
	queryReq := map[string]string{
		"BusinessShortCode": s.config.Shortcode,
		"Password":          s.generatePassword(time.Now().Format("20060102150405")),
		"Timestamp":         time.Now().Format("20060102150405"),
		"CheckoutRequestID": checkoutRequestID,
	}

	jsonBody, err := json.Marshal(queryReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal query: %w", err)
	}

	// Create request
	url := s.baseURL + "/mpesa/stkpushquery/v1/query"
	req, err := http.NewRequest("POST", url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create query request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	// Execute request
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to query status: %w", err)
	}
	defer resp.Body.Close()

	// Parse response
	var status TransactionStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("failed to parse status response: %w", err)
	}

	return &status, nil
}
