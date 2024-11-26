package main

import (
	"context"
	"log"

	"authorization_flow_keycloak/internal/auth"
	"authorization_flow_keycloak/internal/config"
	"authorization_flow_keycloak/internal/server"

	"github.com/redis/go-redis/v9"
)

func main() {
	ctx := context.Background()

	config, err := config.LoadFromEnv()
	if err != nil {
		log.Fatalf("failed to load env file config : %v", err)
		return
	}
	// Use configuration values
	log.Printf("Starting server on port %s", config.App.Port)

	authClient, err := auth.New(ctx, config.Auth)
	if err != nil {
		log.Fatalf("failed to initialize auth client : %v", err)
	}

	// initialize redis client
	rdb := redis.NewClient(config.RedisClient)

	// Create and start server
	srv := server.NewServer(ctx, config, authClient, rdb)
	if err := srv.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
