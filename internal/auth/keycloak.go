package auth

type Config struct {
	BaseURL      string // Authorization base url
	ClientID     string // client id oauth
	RedirectURL  string // valid redirect url
	ClientSecret string
	Realm        string // keycloak realm
}
