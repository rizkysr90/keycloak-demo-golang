package server

import (
	"authorization_flow_keycloak/internal/config"

	"github.com/gin-gonic/gin"
)

type Server struct {
	router *gin.Engine
	config *config.Config
}

func NewServer(config *config.Config) *Server {
	server := &Server{
		router: gin.Default(),
		config: config,
	}

	server.setupRoutes()
	return server
}

func (s *Server) setupRoutes() {
	// Health check
	s.router.GET("/health", s.healthCheck)

	// Auth routes will be added later
	auth := s.router.Group("/auth")
	{
		auth.GET("/login", s.handleLogin)
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
