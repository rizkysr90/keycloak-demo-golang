package config

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"

	"authorization_flow_keycloak/internal/auth"

	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
)

type Config struct {
	App         *AppConfig
	Auth        *auth.Config
	RedisClient *redis.Options
}
type AppConfig struct {
	Port string
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
	redisDB, err := strconv.Atoi(requireEnv("REDIS_DATABASE"))
	if err != nil {
		log.Fatal("failed to convert redis db")
	}
	return &Config{
		App: &AppConfig{
			Port: requireEnv("APP_PORT"),
		},
		Auth: &auth.Config{
			BaseURL:      requireEnv("KEYCLOAK_URL"),
			ClientID:     requireEnv("KEYCLOAK_CLIENT_ID"),
			Realm:        requireEnv("KEYCLOAK_REALM"),
			ClientSecret: requireEnv("KEYCLOAK_CLIENT_SECRET"),
			RedirectURL:  requireEnv("KEYCLOAK_REDIRECT_URL"),
		},
		RedisClient: &redis.Options{
			Addr:     fmt.Sprintf("%s:%s", requireEnv("REDIS_HOST"), requireEnv("REDIS_PORT")),
			Username: requireEnv("REDIS_USERNAME"),
			Password: requireEnv("REDIS_PASSWORD"),
			DB:       redisDB,
		},
	}, nil
}

func requireEnv(key string) string {
	value := os.Getenv(key)
	if value == "" {
		panic(fmt.Sprintf("%s is required", key))
	}
	return value
}
