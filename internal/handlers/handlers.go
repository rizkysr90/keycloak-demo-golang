package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

type AuthHandler struct {
	oauth2Config *oauth2.Config
}

func NewAuthHandler(config *oauth2.Config) *AuthHandler {
	return &AuthHandler{
		oauth2Config: config,
	}
}

// generateState creates a random state parameter to prevent CSRF attacks
func generateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// LoginHandler initiates the OAuth2 login flow
func (h *AuthHandler) LoginHandler(c *gin.Context) {
	state, err := generateState()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate state"})
		return
	}

	// Store state in session for later verification
	session := sessions.Default(c)
	session.Set("oauth2_state", state)
	if err := session.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save session"})
		return
	}

	// Build authentication URL
	authURL := h.oauth2Config.AuthCodeURL(
		state,
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("prompt", "consent"),
	)

	// Redirect to Keycloak login page
	c.Redirect(http.StatusTemporaryRedirect, authURL)
}
