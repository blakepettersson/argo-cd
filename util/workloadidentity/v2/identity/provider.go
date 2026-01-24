package identity

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
)

// TokenType indicates the format of the identity token
type TokenType string

const (
	// TokenTypeBearer is a bearer token (JWT, OAuth access token)
	TokenTypeBearer TokenType = "bearer"
	// TokenTypeAWS is AWS credentials for SigV4 signing
	TokenTypeAWS TokenType = "aws"
)

// Token represents a token from an identity provider
type Token struct {
	// Type indicates the token format
	Type TokenType

	// Token holds the bearer token value (for TokenTypeBearer)
	Token string

	// AWSCredentials holds AWS credentials (for TokenTypeAWS)
	AWSCredentials *AWSCredentials
}

// AWSCredentials holds AWS temporary credentials
type AWSCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Region          string
	Expiration      *time.Time
}

// Config holds identity provider configuration
type Config struct {
	// Audience for the token request
	Audience string

	// TokenURL is a custom token endpoint (overrides provider default)
	TokenURL string

	// Insecure skips TLS certificate verification
	Insecure bool
}

// Provider acquires identity tokens from a platform
type Provider interface {
	NeedsK8sToken() bool

	GetAudience(*corev1.ServiceAccount) string

	// GetToken exchanges K8s SA context for a platform identity token
	//
	// Parameters:
	//   - ctx: Context for cancellation
	//   - sa: The Kubernetes service account (for annotations)
	//   - k8sToken: A K8s service account JWT (may be empty if not needed)
	//   - config: Provider configuration
	//
	// Returns an identity token that can be used by a RegistryAuthenticator
	GetToken(ctx context.Context, sa *corev1.ServiceAccount, k8sToken string, config *Config) (*Token, error)
}
