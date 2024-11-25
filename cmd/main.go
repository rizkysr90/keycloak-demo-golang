package main

import (
	"log"

	"authorization_flow_keycloak/internal/config"
	"authorization_flow_keycloak/internal/server"
)

func main() {
	config, err := config.LoadFromEnv()
	if err != nil {
		log.Fatalf("failed to load env file config : %v", err)
		return
	}
	// Use configuration values
	log.Printf("Starting server on port %s", config.App.Port)

	// Create and start server
	srv := server.NewServer(config)
	if err := srv.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
