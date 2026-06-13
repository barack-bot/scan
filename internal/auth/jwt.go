// Package auth handles JWT (JSON Web Token) authentication
package auth

import (
	"errors" // For creating error messages
	"fmt"    // For formatting strings
	"time"   // For token expiry times

	"ke-scan/config" // Our config package

	"github.com/golang-jwt/jwt/v5" // JWT library for Go
)

// Claims represents the data stored inside a JWT token
type Claims struct {
	UserID               int64  `json:"user_id"`   // User's database ID
	Email                string `json:"email"`     // User's email address
	Role                 string `json:"role"`      // User's role (admin, user, enterprise)
	TenantID             int64  `json:"tenant_id"` // Which organization they belong to
	jwt.RegisteredClaims        // Standard JWT fields (exp, iat, etc.)
}

// JWTService handles JWT creation and validation
type JWTService struct {
	secret      []byte // Secret key for signing tokens (bytes, not string)
	expiryHours int64  // How long tokens remain valid, in hours
}

// NewJWTService creates a new JWT service from config
func NewJWTService(cfg *config.JWTConfig) *JWTService {
	return &JWTService{
		secret:      []byte(cfg.Secret), // Convert secret string to bytes
		expiryHours: cfg.ExpiryHours,
	}
}

// GenerateToken creates a new JWT token for a user
func (s *JWTService) GenerateToken(userID, tenantID int64, email, role string) (string, error) {
	// Calculate expiry time (now + configured hours)
	expiresAt := time.Now().Add(time.Duration(s.expiryHours) * time.Hour)

	// Create the claims (payload) for the token
	claims := Claims{
		UserID:   userID,
		Email:    email,
		Role:     role,
		TenantID: tenantID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),  // When token expires
			IssuedAt:  jwt.NewNumericDate(time.Now()), // When token was created
			Issuer:    "ke-scan",                      // Who issued the token
			Subject:   fmt.Sprintf("user:%d", userID), // Token subject (user identifier)
		},
	}

	// Create a new token with HS256 signing algorithm
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token with our secret key
	tokenString, err := token.SignedString(s.secret)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// ValidateToken verifies a JWT token and returns the claims
func (s *JWTService) ValidateToken(tokenString string) (*Claims, error) {
	// Parse and validate the token
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing algorithm is HS256
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.secret, nil // Return the secret key for verification
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Extract the claims if token is valid
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

// RefreshToken generates a new token from an existing valid token
func (s *JWTService) RefreshToken(oldTokenString string) (string, error) {
	// First validate the old token
	claims, err := s.ValidateToken(oldTokenString)
	if err != nil {
		return "", fmt.Errorf("invalid token for refresh: %w", err)
	}

	// Generate a new token with the same user info
	return s.GenerateToken(claims.UserID, claims.TenantID, claims.Email, claims.Role)
}
