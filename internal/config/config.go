package config

import (
	"authorization_flow_keycloak/internal/auth"
	"log"
	"os"
	"path/filepath"

	"github.com/joho/godotenv"
)

type Config struct {
	Auth *auth.Config
}

func LoadFromEnv() (*Config, error) {
	// Get the absolute path of the current working directory
	currentDir, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	// Construct path to .env file in ../cmd/.env
	envPath := filepath.Join(currentDir, "..", ".env")
	err = godotenv.Load(envPath)

	if err != nil {
		log.Fatal("Error loading .env file", err)
	}
	return &Config{
		Auth: &auth.Config{
			BaseURL:      os.Getenv("KEYCLOAK_URL"),
			ClientID:     os.Getenv("KEYCLOAK_CLIENT_ID"),
			Realm:        os.Getenv("KEYCLOAK_REALM"),
			ClientSecret: os.Getenv("KEYCLOAK_CLIENT_SECRET"),
			RedirectURL:  os.Getenv("REDIRECT_URL"),
		},
	}, nil
}
