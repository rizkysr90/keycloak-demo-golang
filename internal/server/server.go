package server

import (
	"context"

	"authorization_flow_keycloak/internal/auth"
	"authorization_flow_keycloak/internal/config"
	"authorization_flow_keycloak/internal/handlers"
	"authorization_flow_keycloak/internal/store"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

type Server struct {
	router      *gin.Engine
	config      *config.Config
	authHandler *handlers.AuthHandler
}

func NewServer(ctx context.Context,
	cfg *config.Config,
	authClient *auth.Client,
	redisClient *redis.Client,
) *Server {
	router := gin.Default()
	// / Load HTML templates
	router.LoadHTMLGlob("templates/*.html") // Make sure to create a templates directory

	authStore := store.NewAuthRedisManager(redisClient)
	authHandler := handlers.NewAuthHandler(authClient, authStore)

	server := &Server{
		router:      router,
		config:      cfg,
		authHandler: authHandler,
	}

	server.setupRoutes()
	return server
}

func (s *Server) setupRoutes() {
	// Health check
	s.router.GET("/health", s.healthCheck)

	// Serve login page
	s.router.GET("/", s.authHandler.ShowLoginPage)

	// Auth routes will be added later
	auth := s.router.Group("/auth")
	{
		auth.GET("/login", s.authHandler.LoginHandler)
		auth.GET("/callback", s.handleCallback)
	}

}

func (s *Server) healthCheck(c *gin.Context) {
	c.JSON(200, gin.H{
		"status": "ok",
	})
}

func (s *Server) Start() error {
	return s.router.Run(s.config.App.Port)
}
