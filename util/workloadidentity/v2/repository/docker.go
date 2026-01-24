package repository

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/argoproj/argo-cd/v3/util/workloadidentity/v2/identity"
)

// DockerAuthenticator implements Docker Registry v2 token authentication
// This is a standard protocol supported by many registries:
// - Quay.io
// - Harbor
// - GitHub Container Registry (ghcr.io)
// - GitLab Container Registry
// - Docker Hub
// - And many others
//
// The flow is:
// 1. Present bearer token to the auth endpoint
// 2. Receive an access token in response
// 3. Use access token for registry operations
//
// See: https://docs.docker.com/registry/spec/auth/token/
type DockerAuthenticator struct {
	// HTTPClient allows injecting a custom client for testing
	HTTPClient *http.Client
}

// NewDockerAuthenticator creates a new Docker v2 token authenticator
func NewDockerAuthenticator() *DockerAuthenticator {
	return &DockerAuthenticator{}
}

// Name returns the authenticator identifier
func (a *DockerAuthenticator) Name() string {
	return "docker"
}

// Authenticate exchanges an identity token for a Docker registry token
func (a *DockerAuthenticator) Authenticate(ctx context.Context, token *identity.Token, repoURL string, config *Config) (*Credentials, error) {
	if token.Type != identity.TokenTypeBearer {
		return nil, fmt.Errorf("docker authenticator requires a bearer token, got %s", token.Type)
	}

	if token.Token == "" {
		return nil, fmt.Errorf("empty bearer token")
	}

	registry := extractRegistryHost(repoURL)
	log.WithField("registry", registry).Info("Docker: exchanging bearer token for registry token")

	// Auth URL is required - either from config or discovered via WWW-Authenticate
	authURL := config.AuthURL
	if authURL == "" {
		// Try to discover from registry
		log.WithField("registry", registry).Debug("Docker: auth URL not configured, discovering via WWW-Authenticate")
		discovered, err := a.discoverAuthURL(ctx, repoURL, config.Insecure)
		if err != nil {
			return nil, fmt.Errorf("auth URL not configured and discovery failed: %w", err)
		}
		authURL = discovered
		log.WithField("authURL", authURL).Debug("Docker: discovered auth URL")
	}

	// Build token request
	reqURL, err := url.Parse(authURL)
	if err != nil {
		return nil, fmt.Errorf("invalid auth URL: %w", err)
	}

	q := reqURL.Query()

	// Service name (required by most registries)
	service := config.Service
	if service != "" {
		q.Set("service", service)
	} else {
		// Default to registry host
		service = extractRegistryHost(repoURL)
		q.Set("service", service)
	}

	// Scope for fine-grained access control
	// Format: repository:namespace/repo:pull,push
	// Multiple scopes can be space-separated
	if config.Scope != "" {
		// Docker v2 spec allows multiple scope params
		for _, scope := range strings.Split(config.Scope, " ") {
			scope = strings.TrimSpace(scope)
			if scope != "" {
				q.Add("scope", scope)
			}
		}
	}

	reqURL.RawQuery = q.Encode()

	log.WithFields(log.Fields{
		"authURL": authURL,
		"service": service,
	}).Debug("Docker: requesting registry token")

	// Create request with bearer auth
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token.Token)

	// Get HTTP client
	client := a.getHTTPClient(config.Insecure)

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		log.WithError(err).Error("Docker: token request failed")
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		log.WithFields(log.Fields{
			"registry":   registry,
			"statusCode": resp.StatusCode,
		}).Error("Docker: token request failed")
		return nil, fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response - Docker v2 spec allows either "token" or "access_token"
	var tokenResp struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	accessToken := tokenResp.Token
	if accessToken == "" {
		accessToken = tokenResp.AccessToken
	}
	if accessToken == "" {
		return nil, fmt.Errorf("no token in response")
	}

	// Determine username for credentials
	username := config.Username
	if username == "" {
		// Common conventions:
		// - "$oauthtoken" for OAuth tokens (Quay)
		// - "oauth2accesstoken" for OAuth (GCR-style)
		// - "<token>" for some registries
		// Default to a generic one that works with most
		username = "$oauthtoken"
	}

	log.WithFields(log.Fields{
		"registry": registry,
		"username": username,
	}).Info("Docker: successfully obtained registry token")

	return &Credentials{
		Username: username,
		Password: accessToken,
	}, nil
}

// discoverAuthURL discovers the auth endpoint from the registry's 401 response
func (a *DockerAuthenticator) discoverAuthURL(ctx context.Context, repoURL string, insecure bool) (string, error) {
	// Extract registry host
	host := extractRegistryHost(repoURL)
	if host == "" {
		return "", fmt.Errorf("could not extract registry host from URL")
	}

	// Try to access /v2/ to get WWW-Authenticate header
	scheme := "https"
	if insecure {
		scheme = "http"
	}
	pingURL := fmt.Sprintf("%s://%s/v2/", scheme, host)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pingURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create ping request: %w", err)
	}

	client := a.getHTTPClient(insecure)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("ping request failed: %w", err)
	}
	defer resp.Body.Close()

	// We expect a 401 with WWW-Authenticate header
	if resp.StatusCode != http.StatusUnauthorized {
		return "", fmt.Errorf("expected 401, got %d", resp.StatusCode)
	}

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if wwwAuth == "" {
		return "", fmt.Errorf("no WWW-Authenticate header in 401 response")
	}

	// Parse WWW-Authenticate header
	// Format: Bearer realm="https://auth.example.com/token",service="registry.example.com"
	realm := parseWWWAuthenticateRealm(wwwAuth)
	if realm == "" {
		return "", fmt.Errorf("could not parse realm from WWW-Authenticate: %s", wwwAuth)
	}

	return realm, nil
}

// parseWWWAuthenticateRealm extracts the realm URL from a WWW-Authenticate header
func parseWWWAuthenticateRealm(header string) string {
	// Simple parser for: Bearer realm="URL",...
	if !strings.HasPrefix(header, "Bearer ") {
		return ""
	}

	parts := strings.Split(header[7:], ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "realm=") {
			realm := strings.TrimPrefix(part, "realm=")
			// Remove quotes
			realm = strings.Trim(realm, "\"")
			return realm
		}
	}
	return ""
}

// extractRegistryHost extracts the host from a repository URL
func extractRegistryHost(repoURL string) string {
	u := strings.TrimPrefix(repoURL, "oci://")

	if parsed, err := url.Parse("https://" + u); err == nil {
		return parsed.Host
	}

	// Fallback: take everything before first /
	if idx := strings.Index(u, "/"); idx != -1 {
		return u[:idx]
	}
	return u
}

func (a *DockerAuthenticator) getHTTPClient(insecure bool) *http.Client {
	if a.HTTPClient != nil {
		return a.HTTPClient
	}

	client := &http.Client{}
	if insecure {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	return client
}

// Ensure DockerAuthenticator implements Authenticator
var _ Authenticator = (*DockerAuthenticator)(nil)
