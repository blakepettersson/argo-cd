package repository

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/argoproj/argo-cd/v3/util/workloadidentity/v2/identity"
)

// BasicAuthenticator uses the identity token as a password with a configured username
// This is the simplest authenticator - no exchange, just format the credentials
type BasicAuthenticator struct{}

// NewBasicAuthenticator creates a new basic auth authenticator
func NewBasicAuthenticator() *BasicAuthenticator {
	return &BasicAuthenticator{}
}

// Name returns the authenticator identifier
func (a *BasicAuthenticator) Name() string {
	return "basic"
}

// Authenticate returns credentials using the token as password
func (a *BasicAuthenticator) Authenticate(ctx context.Context, token *identity.Token, repoURL string, config *Config) (*Credentials, error) {
	if token.Type != identity.TokenTypeBearer {
		return nil, fmt.Errorf("basic authenticator requires a bearer token, got %s", token.Type)
	}

	if token.Token == "" {
		return nil, fmt.Errorf("empty bearer token")
	}

	username := config.Username
	if username == "" {
		username = "oauth2accesstoken" // sensible default for OAuth tokens
	}

	log.WithField("username", username).Info("Basic: using bearer token as password (passthrough)")

	return &Credentials{
		Username: username,
		Password: token.Token,
	}, nil
}

// Ensure BasicAuthenticator implements Authenticator
var _ Authenticator = (*BasicAuthenticator)(nil)
