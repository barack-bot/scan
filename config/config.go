package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

type Duration time.Duration

func (d *Duration) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		*d = 0
		return nil
	}

	if data[0] == '"' {
		var value string
		if err := json.Unmarshal(data, &value); err != nil {
			return err
		}
		dur, err := time.ParseDuration(value)
		if err != nil {
			return err
		}
		*d = Duration(dur)
		return nil
	}

	var seconds int64
	if err := json.Unmarshal(data, &seconds); err != nil {
		return err
	}

	*d = Duration(time.Duration(seconds) * time.Second)
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}

type Config struct {
	Server   ServerConfig   `json:"server"`
	Database DatabaseConfig `json:"database"`
	JWT      JWTConfig      `json:"jwt"`
	Mpesa    MpesaConfig    `json:"mpesa"`
	SMTP     SMTPConfig     `json:"smtp"`
	App      AppConfig      `json:"app"`
}

type ServerConfig struct {
	Port         string   `json:"port"`
	ReadTimeout  Duration `json:"read_timeout"`
	WriteTimeout Duration `json:"write_timeout"`
	IdleTimeout  Duration `json:"idle_timeout"`
}

type DatabaseConfig struct {
	Path            string   `json:"path"`
	MaxOpenConns    int      `json:"max_open_conns"`
	MaxIdleConns    int      `json:"max_idle_conns"`
	ConnMaxLifetime Duration `json:"conn_max_lifetime"`
}

type JWTConfig struct {
	Secret      string `json:"secret"`
	ExpiryHours int64  `json:"expiry_hours"`
}

type MpesaConfig struct {
	ConsumerKey    string `json:"consumer_key"`
	ConsumerSecret string `json:"consumer_secret"`
	Shortcode      string `json:"shortcode"`
	Passkey        string `json:"passkey"`
	Environment    string `json:"environment"`
}

type SMTPConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	From     string `json:"from"`
}

type AppConfig struct {
	Name    string `json:"name"`
	Env     string `json:"env"`
	BaseURL string `json:"base_url"`
}

func (s *ServerConfig) Address() string {
	port := strings.TrimPrefix(s.Port, ":")
	if port == "" {
		port = "8080"
	}
	return ":" + port
}

func Load(configPath string) (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			Port:         "8080",
			ReadTimeout:  Duration(5 * time.Second),
			WriteTimeout: Duration(10 * time.Second),
			IdleTimeout:  Duration(120 * time.Second),
		},
		Database: DatabaseConfig{
			Path:         "./data/ke-scan.db",
			MaxOpenConns: 25,
			MaxIdleConns: 5,
		},
		JWT: JWTConfig{
			Secret:      "", // No default — must be set via env or file
			ExpiryHours: 24,
		},
		App: AppConfig{
			Name:    "KeScan",
			Env:     "development",
			BaseURL: "http://localhost:8080",
		},
	}

	if configPath != "" {
		if err := loadFromFile(configPath, cfg); err != nil {
			if !os.IsNotExist(err) {
				return nil, err
			}
		}
	}

	overrideFromEnv(cfg)

	// Validate that JWT secret is not a default or committed placeholder
	// This also catches the original hardcoded secret that was committed to the repo
	if cfg.JWT.Secret == "" || cfg.JWT.Secret == "your_secret_key" || cfg.JWT.Secret == "your-super-secret-jwt-key-change-this" || cfg.JWT.Secret == "SET_VIA_ENVIRONMENT_VARIABLE_JWT_SECRET" || cfg.JWT.Secret == "dLihlini3INTsiMkhMfldi2+X9Lb7FYJwcv7J+yUrPA=" {
		return nil, fmt.Errorf("FATAL: JWT_SECRET must be set via environment variable (JWT_SECRET). " +
			"The config.json placeholder and previously committed secrets are not allowed for security reasons. " +
			"Generate a secure random key (e.g., openssl rand -base64 32) and set JWT_SECRET environment variable.")
	}

	return cfg, nil
}

func loadFromFile(path string, cfg *Config) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, cfg)
}

func overrideFromEnv(cfg *Config) {
	if port := os.Getenv("SERVER_PORT"); port != "" {
		cfg.Server.Port = port
	}
	if dbPath := os.Getenv("DATABASE_PATH"); dbPath != "" {
		cfg.Database.Path = dbPath
	}
	if jwtSecret := os.Getenv("JWT_SECRET"); jwtSecret != "" {
		cfg.JWT.Secret = jwtSecret
	}
	if mpesaConsumerKey := os.Getenv("MPESA_CONSUMER_KEY"); mpesaConsumerKey != "" {
		cfg.Mpesa.ConsumerKey = mpesaConsumerKey
	}
	if mpesaConsumerSecret := os.Getenv("MPESA_CONSUMER_SECRET"); mpesaConsumerSecret != "" {
		cfg.Mpesa.ConsumerSecret = mpesaConsumerSecret
	}
	if appEnv := os.Getenv("APP_ENV"); appEnv != "" {
		cfg.App.Env = appEnv
	}
	if baseURL := os.Getenv("APP_BASE_URL"); baseURL != "" {
		cfg.App.BaseURL = baseURL
	}
}

func (c *Config) IsDevelopment() bool {
	return c.App.Env == "development"
}

func (c *Config) IsProduction() bool {
	return c.App.Env == "production"
}

func (c *Config) GetDSN() string {
	return c.Database.Path
}

func (c *Config) GetBaseURL() string {
	return c.App.BaseURL
}
