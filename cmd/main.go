package main

import (
	"log"

	"authorization_flow_keycloak/internal/config"
)

func main() {
	config, err := config.LoadFromEnv()
	if err != nil {
		log.Fatalf("failed to load env file config : %v", err)
		return
	}
	// Use configuration values
	log.Printf("Starting server on port %s", config.App.Port)
}
