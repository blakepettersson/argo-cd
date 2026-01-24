package repository

import (
	"context"

	"github.com/argoproj/argo-cd/v3/util/workloadidentity/v2/identity"
)

// Credentials holds resolved username and password for repository access
type Credentials struct {
	Username string
	Password string
}

// Config holds registry-specific configuration
type Config struct {
	// AuthURL is the registry's authentication endpoint
	// e.g., "https://quay.io/v2/auth" or "https://registry.example.com/v2/token"
	// If not set, Docker authenticator will try to discover it via WWW-Authenticate
	AuthURL string

	// Service is the registry service name (for Docker token auth)
	// e.g., "registry.docker.io"
	// If not set, defaults to the registry hostname
	Service string

	// Scope defines the access scope for Docker v2 token auth
	// Format: "repository:namespace/repo:pull,push"
	// Multiple scopes can be space-separated
	// If not set, registry grants default access (usually pull-only)
	Scope string

	// Username for basic auth (when using token as password)
	// e.g., "oauth2accesstoken" for GCR, "$oauthtoken" for Quay
	Username string

	// Insecure skips TLS certificate verification
	Insecure bool
}

// Authenticator converts identity tokens to registry credentials
type Authenticator interface {
	// Authenticate exchanges an identity token for registry credentials
	//
	// Parameters:
	//   - ctx: Context for cancellation
	//   - token: The identity token from an IdentityProvider
	//   - repoURL: The repository URL (for extracting registry host, region, etc.)
	//   - config: Authenticator configuration
	//
	// Returns credentials that can be used to access the registry
	Authenticate(ctx context.Context, token *identity.Token, repoURL string, config *Config) (*Credentials, error)
}
