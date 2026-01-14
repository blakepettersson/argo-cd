package workloadidentity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// resolveGeneric resolves credentials for custom registries using RFC 8693 token exchange
// This is a two-step process:
// 1. Exchange K8s JWT for an identity token (e.g., SPIFFE JWT)
// 2. Exchange identity token for registry credentials (e.g., Harbor token)
func (r *Resolver) resolveGeneric(ctx context.Context, sa *corev1.ServiceAccount, k8sToken, repoURL string, config *ProviderConfig) (*Credentials, error) {
	// Step 1: Get identity token URL (required) from repository config
	tokenURL := config.TokenURL
	if tokenURL == "" {
		return nil, fmt.Errorf("workloadIdentityTokenURL not specified for generic provider")
	}

	// Get audience for identity token exchange from repository config
	audience := config.Audience
	if audience == "" {
		return nil, fmt.Errorf("workloadIdentityAudience not specified for generic provider")
	}

	// Exchange K8s JWT for identity token (e.g., SPIFFE JWT from SPIRE)
	identityToken, err := r.exchangeGenericToken(ctx, tokenURL, k8sToken, audience)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange token: %w", err)
	}

	// Step 2: Check if registry auth URL is configured (optional, for Docker Registry Token Auth)
	registryAuthURL := config.RegistryAuthURL
	if registryAuthURL != "" {
		// Exchange identity token for registry credentials
		return r.exchangeRegistryToken(ctx, config, identityToken, repoURL)
	}

	// If no registry auth URL, use the identity token directly as password
	// This works for some registries that accept Bearer tokens directly
	return &Credentials{
		Username: "",
		Password: identityToken,
	}, nil
}

// exchangeGenericToken performs RFC 8693 OAuth 2.0 Token Exchange
func (r *Resolver) exchangeGenericToken(ctx context.Context, tokenURL, subjectToken, audience string) (string, error) {
	// Prepare RFC 8693 token exchange request
	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	data.Set("subject_token", subjectToken)
	data.Set("subject_token_type", "urn:ietf:params:oauth:token-type:jwt")
	data.Set("requested_token_type", "urn:ietf:params:oauth:token-type:access_token")
	data.Set("audience", audience)

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create token exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Execute request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute token exchange: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse token response
	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}

	return tokenResp.AccessToken, nil
}

// exchangeRegistryToken exchanges an identity token for registry-specific credentials
// This implements Docker Registry Token Authentication (RFC 7235)
func (r *Resolver) exchangeRegistryToken(ctx context.Context, config *ProviderConfig, identityToken, repoURL string) (*Credentials, error) {
	registryAuthURL := config.RegistryAuthURL
	registryService := config.RegistryService

	if registryService == "" {
		// Try to extract service from repo URL
		registryService = extractRegistryHost(repoURL)
	}

	// Build registry token URL with service and scope parameters
	// Example: https://harbor.example.com/service/token?service=harbor.example.com&scope=repository:project/repo:pull
	scope := buildRegistryScope(repoURL)
	tokenURL := fmt.Sprintf("%s?service=%s&scope=%s", registryAuthURL, registryService, url.QueryEscape(scope))

	// Create HTTP request with identity token as Bearer authorization
	req, err := http.NewRequestWithContext(ctx, "GET", tokenURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create registry token request: %w", err)
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", identityToken))

	// Execute request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute registry token request: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("registry token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse registry token response
	var registryResp struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"` // Some registries use this field
		ExpiresIn   int64  `json:"expires_in"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&registryResp); err != nil {
		return nil, fmt.Errorf("failed to decode registry token response: %w", err)
	}

	// Use token or access_token, whichever is present
	token := registryResp.Token
	if token == "" {
		token = registryResp.AccessToken
	}

	if token == "" {
		return nil, fmt.Errorf("registry token response missing token field")
	}

	// For Docker Registry Token Authentication, username is typically empty
	return &Credentials{
		Username: "",
		Password: token,
	}, nil
}

// extractRegistryHost extracts the registry hostname from a repository URL
// Example: oci://harbor.example.com/project/repo → harbor.example.com
func extractRegistryHost(repoURL string) string {
	// Remove oci:// prefix
	repoURL = strings.TrimPrefix(repoURL, "oci://")

	// Take the hostname part (before the first slash)
	parts := strings.Split(repoURL, "/")
	if len(parts) > 0 {
		return parts[0]
	}

	return repoURL
}

// buildRegistryScope builds the Docker Registry scope string
// Example: harbor.example.com/project/repo → repository:project/repo:pull
func buildRegistryScope(repoURL string) string {
	// Remove oci:// prefix and registry host
	repoURL = strings.TrimPrefix(repoURL, "oci://")
	parts := strings.SplitN(repoURL, "/", 2)

	if len(parts) < 2 {
		return "repository:*:pull"
	}

	// Format: repository:<repository>:pull
	return fmt.Sprintf("repository:%s:pull", parts[1])
}