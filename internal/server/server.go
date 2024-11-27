package server

import (
	"context"
	"net/http"

	"authorization_flow_keycloak/internal/auth"
	"authorization_flow_keycloak/internal/config"
	"authorization_flow_keycloak/internal/handlers"
	"authorization_flow_keycloak/internal/middleware"
	"authorization_flow_keycloak/internal/store"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

type Server struct {
	router      *gin.Engine
	config      *config.Config
	authHandler *handlers.AuthHandler
}

func NewServer(c context.Context,
	cfg *config.Config,
	authClient *auth.Client,
	redisClient *redis.Client,
) *Server {
	router := gin.Default()
	// / Load HTML templates
	router.LoadHTMLGlob("../internal/templates/*.*")

	// r.LoadHTMLGlob("../internal/templates/*/*.tmpl")
	authStore := store.NewAuthRedisManager(redisClient)
	sessionStore := store.NewSessionRedisManager(redisClient)

	authHandler := handlers.NewAuthHandler(authClient, authStore, sessionStore)
	// Initialize the auth middleware with your Keycloak configuration
	authMiddleware := middleware.NewAuthMiddleware(
		c,
		authClient,
		sessionStore,
	)
	server := &Server{
		router:      router,
		config:      cfg,
		authHandler: authHandler,
	}

	server.setupRoutes(authMiddleware)
	return server
}

func (s *Server) setupRoutes(authMiddleware *middleware.AuthMiddleware) {

	// Health check
	s.router.GET("/health", s.healthCheck)

	// Serve login page
	s.router.GET("/", s.authHandler.ShowLoginPage)

	// Auth routes will be added later
	auth := s.router.Group("/auth")
	{
		auth.GET("/login", s.authHandler.LoginHandler)
		auth.GET("/callback", s.authHandler.CallbackHandler)
	}

	// Protected routes
	protected := s.router.Group("/dashboard")
	protected.Use(authMiddleware.RequireAuth())
	{
		protected.GET("/", showDashboard)
	}
}
func showDashboard(c *gin.Context) {
	// Get session data with safe type assertion
	rawSession, exists := c.Get("user_session")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "No session found"})
		return
	}
	// Perform type assertion with error checking
	sessionData, ok := rawSession.(*store.SessionData)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid session data type"})
		return
	}
	// Now you can safely use the properly typed sessionData
	c.HTML(http.StatusOK, "dashboard.tmpl", gin.H{
		"username": sessionData.UserInfo.Username,
		"email":    sessionData.UserInfo.Email,
		"created":  sessionData.CreatedAt,
	})
}
func (s *Server) healthCheck(c *gin.Context) {
	c.JSON(200, gin.H{
		"status": "ok",
	})
}

func (s *Server) Start() error {
	return s.router.Run(s.config.App.Port)
}
