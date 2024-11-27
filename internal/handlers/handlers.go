package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
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

// Add this method to server.go
func (a *AuthHandler) ShowLoginPage(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", nil)
}
func (a *AuthHandler) CallbackHandler(c *gin.Context) {
	if err := a.validateStateSession(c); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to validate state session"})
		return
	}
	oauthToken, err := a.tokenExchange(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to exchange token"})
		return
	}
	oidcClaims, err := a.validateAndGetClaimsIDToken(c, oauthToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError,
			gin.H{"error": "Failed to validate and get claims id token"})
		return
	}
}
func (a *AuthHandler) validateStateSession(c *gin.Context) error {
	// Get state from callback parameters
	stateParam := c.Query("state")
	if stateParam == "" {
		return errors.New("missing state parameter in callback")
	}

	// Retrieve stored state from Redis
	storedState, err := a.authStore.GetState(c, stateParam)
	if err != nil {
		return fmt.Errorf("failed to retrieve stored state: %w", err)
	}

	// Validate state match
	if storedState != stateParam {
		return errors.New("state parameter mismatch")
	}

	// Clean up used state from store
	if err = a.authStore.DeleteState(c, storedState); err != nil {
		log.Printf("Warning: failed to delete used state: %v", err)
	}

	return nil
}
func (a *AuthHandler) tokenExchange(c *gin.Context) (*oauth2.Token, error) {
	authorizationCode := c.Query("code")
	if authorizationCode == "" {
		return nil, errors.New("authorizationCode is required")
	}
	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("grant_type", "authorization_code"),
	}
	oauth2Token, err := a.authClient.Oauth.Exchange(c, authorizationCode, opts...)
	if err != nil {
		return nil, err
	}
	return oauth2Token, nil
}

type oidcClaims struct {
	Email    string `json:"email"`
	Username string `json:"preferred_username"`
}

// ValidateIDToken verifies the id token from the oauth2token
func (a *AuthHandler) validateAndGetClaimsIDToken(
	c *gin.Context, oauth2Token *oauth2.Token) (*oidcClaims, error) {
	// Get and validate the ID token - this proves the user's identity
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("No ID token found")
	}
	// Verify the ID token
	idToken, err := a.authClient.OIDC.Verify(c.Request.Context(), rawIDToken)
	if err != nil {
		return nil, errors.New("Failed to verify ID token")
	}
	claims := oidcClaims{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, errors.New("Failed to get user info")
	}
	return &claims, nil
}
