// KE-SCAN - A monolithic web vulnerability scanner with ODPC compliance reporting
package main

import (
	"bufio"
	"log"
	"net/http"
	"os"
	"strings"

	"ke-scan/config"
	"ke-scan/internal/api"
	"ke-scan/internal/auth"
	"ke-scan/internal/db"
	"ke-scan/internal/mailer"
	"ke-scan/internal/mpesa"
	"ke-scan/internal/scanner"
)

func loadEnvFile(path string) {
	f, err := os.Open(path)
	if err != nil {
		return // .env file is optional
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key != "" && value != "" {
			// Only set if not already set (env vars from shell take precedence)
			if os.Getenv(key) == "" {
				os.Setenv(key, value)
			}
		}
	}
}

func main() {
	log.Println("Starting KE-SCAN...")

	// Load .env file if present (variables from the shell environment take precedence)
	loadEnvFile(".env")

	// Load configuration
	cfg, err := config.Load("config/config.json")
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	log.Printf("Running in %s mode", cfg.App.Env)

	// Initialize database
	database, err := db.New(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer database.Close()
	log.Println("Database connected")

	// Initialize JWT service
	jwtService := auth.NewJWTService(&cfg.JWT)

	// Initialize mailer (optional)
	var mailerService *mailer.Mailer
	if cfg.SMTP.Host != "" && cfg.SMTP.Password != "" && cfg.SMTP.Password != "your-app-password" {
		mailerService = mailer.NewMailer(&cfg.SMTP)
		log.Println("Mailer initialized")
	} else {
		log.Println("Mailer not configured — email features disabled")
	}

	// Initialize M-PESA service (optional)
	var mpesaService *mpesa.MpesaService
	if cfg.Mpesa.ConsumerKey != "" && cfg.Mpesa.ConsumerKey != "your-mpesa-consumer-key" {
		mpesaService = mpesa.NewMpesaService(&cfg.Mpesa)
		log.Println("M-PESA service initialized")
	} else {
		log.Println("M-PESA not configured — payment features disabled")
	}

	// Initialize scanner engine
	scannerEngine, err := scanner.NewEngine(database, cfg)
	if err != nil {
		log.Fatalf("Failed to initialize scanner: %v", err)
	}
	log.Println("Scanner engine initialized")

	// Initialize API server
	server := api.NewServer(
		database,
		jwtService,
		mailerService,
		mpesaService,
		scannerEngine,
		cfg,
	)

	// Setup routes
	router := server.Routes()

	// Start server
	addr := cfg.Server.Address()
	log.Printf("Server starting on %s", addr)
	log.Printf("Visit http://localhost%s", addr)

	if err := http.ListenAndServe(addr, router); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
