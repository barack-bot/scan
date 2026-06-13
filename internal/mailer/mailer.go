// Package mailer handles sending emails (notifications, reports, password reset)
package mailer

import (
	"bytes"         // For buffering email templates
	"fmt"           // For formatting strings
	"html/template" // For rendering HTML email templates
	"net/smtp"      // SMTP protocol for sending emails
	"path/filepath" // For handling file paths

	"ke-scan/config" // Our config package
)

// Mailer represents an email sending service
type Mailer struct {
	config *config.SMTPConfig // SMTP configuration
	from   string             // From email address (cached for convenience)
}

// EmailData contains data for rendering email templates
type EmailData struct {
	ToName   string      // Recipient's name
	ToEmail  string      // Recipient's email address
	Subject  string      // Email subject line
	Data     interface{} // Arbitrary data for the template (e.g., scan results)
	Template string      // Template name (e.g., "welcome", "scan_complete")
}

// EmailTemplateData provides common fields used across all email templates
type EmailTemplateData struct {
	Name          string
	Email         string
	Year          int
	BaseURL       string
	Domain        string
	FindingCount  int
	ScanID        int64
	CriticalCount int
	HighCount     int
	MediumCount   int
	LowCount      int
	ResetLink     string
}

// NewMailer creates a new mailer service from config
func NewMailer(cfg *config.SMTPConfig) *Mailer {
	return &Mailer{
		config: cfg,
		from:   cfg.From,
	}
}

// Send sends an email using the configured SMTP server
func (m *Mailer) Send(data EmailData) error {
	// Render the HTML template (you'll create these templates later)
	htmlBody, err := m.renderTemplate(data.Template, data.Data)
	if err != nil {
		return fmt.Errorf("failed to render template: %w", err)
	}

	// Build the email message (MIME format)
	message := m.buildMessage(data.Subject, htmlBody)

	// SMTP server address (host:port)
	addr := fmt.Sprintf("%s:%d", m.config.Host, m.config.Port)

	// Authentication (plain auth for most SMTP servers)
	auth := smtp.PlainAuth("", m.config.Username, m.config.Password, m.config.Host)

	// Send the email
	err = smtp.SendMail(addr, auth, m.from, []string{data.ToEmail}, message)
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

// buildMessage constructs a MIME-compliant email message
func (m *Mailer) buildMessage(subject, htmlBody string) []byte {
	// Email headers
	headers := make(map[string]string)
	headers["From"] = m.from
	headers["To"] = m.from // Will be overridden by SendMail's recipient parameter
	headers["Subject"] = subject
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = "text/html; charset=UTF-8"

	// Build the message as a string
	message := ""
	for k, v := range headers {
		message += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	message += "\r\n" + htmlBody // Empty line separates headers from body

	return []byte(message)
}

// renderTemplate loads and executes an HTML template
func (m *Mailer) renderTemplate(templateName string, data interface{}) (string, error) {
	// Path to email templates (you'll create these)
	templatePath := filepath.Join("templates", "emails", templateName+".html")

	// Parse the template file
	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	// Execute the template with the provided data
	var buf bytes.Buffer
	err = tmpl.Execute(&buf, data)
	if err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}

// SendWelcomeEmail sends a welcome email to new users
func (m *Mailer) SendWelcomeEmail(email, name string) error {
	baseURL := "https://ke-scan.com"
	return m.Send(EmailData{
		ToName:   name,
		ToEmail:  email,
		Subject:  "Welcome to KE-SCAN - Your Security Compliance Platform",
		Template: "welcome",
		Data: EmailTemplateData{
			Name:    name,
			Email:   email,
			Year:    2026,
			BaseURL: baseURL,
		},
	})
}

// SendScanCompleteEmail notifies user when a scan finishes
func (m *Mailer) SendScanCompleteEmail(email, name, domain string, findingCount int) error {
	baseURL := "https://ke-scan.com"
	return m.Send(EmailData{
		ToName:   name,
		ToEmail:  email,
		Subject:  fmt.Sprintf("Scan Complete: %s - %d findings", domain, findingCount),
		Template: "scan_complete",
		Data: EmailTemplateData{
			Name:         name,
			Email:        email,
			Domain:       domain,
			FindingCount: findingCount,
			Year:         2026,
			BaseURL:      baseURL,
		},
	})
}

// SendPasswordResetEmail sends a password reset link
func (m *Mailer) SendPasswordResetEmail(email, name, resetToken, baseURL string) error {
	resetLink := fmt.Sprintf("%s/reset-password?token=%s", baseURL, resetToken)
	return m.Send(EmailData{
		ToName:   name,
		ToEmail:  email,
		Subject:  "Reset Your KE-SCAN Password",
		Template: "password_reset",
		Data: EmailTemplateData{
			Name:      name,
			Email:     email,
			ResetLink: resetLink,
			Year:      2026,
			BaseURL:   baseURL,
		},
	})
}
