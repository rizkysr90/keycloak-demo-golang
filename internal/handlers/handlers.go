package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"authorization_flow_keycloak/internal/auth"
	"authorization_flow_keycloak/internal/constant"
	"authorization_flow_keycloak/internal/store"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

type AuthHandler struct {
	authClient   *auth.Client
	authStore    store.AuthStore
	sessionStore store.SessionStore
}

func NewAuthHandler(
	authClient *auth.Client,
	authStore store.AuthStore,
	sessionStore store.SessionStore,
) *AuthHandler {
	return &AuthHandler{
		authClient:   authClient,
		authStore:    authStore,
		sessionStore: sessionStore,
	}
}

// generateRandomSecureString creates a random secure string
func generateRandomSecureString() (string, error) {
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
	state, err := generateRandomSecureString()
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
	userInfo, err := a.validateAndGetClaimsIDToken(c, oauthToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError,
			gin.H{"error": "Failed to validate and get claims id token"})
		return
	}
	sessionID, err := generateRandomSecureString()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate session ID"})
		return
	}
	// Create session data
	sessionData := store.SessionData{
		AccessToken: oauthToken.AccessToken, // From Keycloak
		UserInfo: store.UserInfo{
			Username: userInfo.Username,
			Email:    userInfo.Email,
		},
		CreatedAt: time.Now(),
	}
	// Store session
	if err := a.sessionStore.Set(c, sessionID, sessionData); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store session"})
		return
	}
	// Note: Gin handles SameSite through the Config struct
	c.SetSameSite(http.SameSiteStrictMode)
	// Set secure session cookie using Gin's methods
	c.SetCookie(
		"session_id",                  // name
		sessionID,                     // value
		int(constant.SessionDuration), // maxAge in seconds
		"/",                           // path
		"",                            // domain (empty means default to current domain)
		true,                          // Set secure to false for HTTP development
		true,                          // httpOnly (prevents JavaScript access)
	)

	// Redirect to dashboard using Gin's redirect method
	c.Redirect(http.StatusTemporaryRedirect, "/dashboard")
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
		return nil, errors.New("no ID token found")
	}
	// Verify the ID token
	idToken, err := a.authClient.OIDC.Verify(c.Request.Context(), rawIDToken)
	if err != nil {
		return nil, errors.New("failed to verify ID token")
	}
	claims := oidcClaims{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, errors.New("failed to get user info")
	}
	return &claims, nil
}
