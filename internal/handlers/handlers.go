package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"

	"authorization_flow_keycloak/internal/auth"
	"authorization_flow_keycloak/internal/store"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

type AuthHandler struct {
	authClient *auth.Client
	authStore  store.AuthStore
}

func NewAuthHandler(authClient *auth.Client, authStore store.AuthStore) *AuthHandler {
	return &AuthHandler{
		authClient: authClient,
		authStore:  authStore,
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

// LoginHandler initiates the OAuth2 authorization code flow with Keycloak.
// It generates a secure state parameter to prevent CSRF attacks and stores it
// in Redis for later verification during the callback phase.
//
// Returns:
// - 302: Redirects to Keycloak login page
// - 500: Internal Server Error if state generation or storage fails
func (a *AuthHandler) LoginHandler(c *gin.Context) {
	state, err := generateState()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate state"})
		return
	}

	// Store state in session for later verification
	if err = a.authStore.SetState(c, state); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save session"})
		return
	}
	// Build authentication URL
	authURL := a.authClient.Oauth.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("response_type", "code"),
		oauth2.SetAuthURLParam("scope", "openid profile email"),
	)

	// Redirect to Keycloak login page
	c.Redirect(http.StatusTemporaryRedirect, authURL)
}
