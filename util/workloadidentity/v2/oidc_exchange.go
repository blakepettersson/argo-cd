package v2

// # OIDC Exchange Provider
//
// This file implements RFC 8693 OAuth 2.0 Token Exchange for OIDC-based authentication
// with container registries like Harbor, Quay (with K8s OIDC), GitLab, and others.
//
// The provider is configured via workloadIdentityProvider: "oidc" in repository secrets.
//
// For SPIFFE/SPIRE workload identity, use the dedicated "spiffe" provider instead,
// which uses the SPIFFE Workload API directly with delegated identity support.
//
// ## Authentication Modes
//
// The OIDC provider supports two modes:
//
// 1. Direct K8s OIDC: K8s token → Registry (registry trusts K8s OIDC issuer)
//    - Requires: registryAuthURL
//    - Simplest setup, no intermediate IdP
//
// 2. Token Exchange: K8s token → Token Exchange → Registry
//    - Requires: tokenURL, audience, registryAuthURL
//    - For custom OIDC providers implementing RFC 8693
//
// ## Example: Harbor with K8s OIDC
//
// Configure Harbor to trust your Kubernetes cluster's OIDC issuer, then:
//
//	apiVersion: v1
//	kind: Secret
//	metadata:
//	  name: harbor-repo
//	  namespace: argocd
//	  labels:
//	    argocd.argoproj.io/secret-type: repository
//	stringData:
//	  type: helm
//	  url: oci://harbor.example.org/project/charts
//	  project: default
//	  useWorkloadIdentity: "true"
//	  workloadIdentityProvider: "oidc"
//	  workloadIdentityAudience: "harbor"
//	  workloadIdentityRegistryAuthURL: "https://harbor.example.org/service/token"
//	  workloadIdentityRegistryService: "harbor-registry"
//
// See docs/operator-manual/workload-identity-oidc-exchange.md for full documentation.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// httpClient returns an HTTP client configured based on the insecure flag
func httpClient(insecure bool) *http.Client {
	if insecure {
		return &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
	}
	return http.DefaultClient
}

// resolveOIDC resolves credentials using OIDC token exchange (RFC 8693) for custom registries.
//
// It supports two modes:
//
// 1. Direct K8s OIDC: K8s token → Registry
//   - Requires: registryAuthURL (tokenURL not set)
//   - K8s token is used directly with registry auth endpoint
//
// 2. Token Exchange: K8s token → Token Exchange → Registry
//   - Requires: tokenURL, audience, registryAuthURL
//   - For custom OIDC providers implementing RFC 8693
func (r *Resolver) resolveOIDC(ctx context.Context, sa *corev1.ServiceAccount, k8sToken, repoURL string, config *ProviderConfig) (*Credentials, error) {
	tokenURL := config.TokenURL
	registryAuthURL := config.RegistryAuthURL

	// Determine the identity token to use
	var identityToken string
	var err error

	if tokenURL != "" {
		// Mode 1: Exchange K8s token for identity token via RFC 8693
		audience := config.Audience
		if audience == "" {
			return nil, fmt.Errorf("workloadIdentityAudience not specified for oidc provider with tokenURL")
		}

		// Exchange K8s JWT for identity token
		identityToken, err = r.exchangeOIDCToken(ctx, tokenURL, k8sToken, audience, config.Insecure)
		if err != nil {
			return nil, fmt.Errorf("failed to exchange token: %w", err)
		}
	} else {
		// Mode 2: Use K8s token directly (direct K8s OIDC to registry)
		identityToken = k8sToken
	}

	// Check if registry auth URL is configured
	if registryAuthURL != "" {
		// Exchange identity token for registry credentials
		return r.exchangeRegistryToken(ctx, config, identityToken, repoURL)
	}

	// No registry auth URL - need at least tokenURL for single-step exchange
	if tokenURL == "" {
		return nil, fmt.Errorf("either workloadIdentityTokenURL or workloadIdentityRegistryAuthURL must be specified for oidc provider")
	}

	// Use the exchanged token directly as password
	// This works for some registries that accept Bearer tokens directly
	return &Credentials{
		Username: "",
		Password: identityToken,
	}, nil
}

// exchangeOIDCToken performs RFC 8693 OAuth 2.0 Token Exchange
func (r *Resolver) exchangeOIDCToken(ctx context.Context, tokenURL, subjectToken, audience string, insecure bool) (string, error) {
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
	resp, err := httpClient(insecure).Do(req)
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
//
// Two auth modes are supported:
//   - Basic Auth: When RegistryUsername is set (e.g., Quay robot account federation)
//     Uses username:token as Basic Auth credentials
//   - Bearer Auth: When RegistryUsername is empty (standard Docker registry auth)
//     Sends token as Bearer header
func (r *Resolver) exchangeRegistryToken(ctx context.Context, config *ProviderConfig, identityToken, repoURL string) (*Credentials, error) {
	registryAuthURL := config.RegistryAuthURL
	registryService := config.RegistryService
	registryUsername := config.RegistryUsername

	if registryService == "" {
		// Try to extract service from repo URL
		registryService = extractRegistryHost(repoURL)
	}

	// Build registry token URL with service and scope parameters
	// Example: https://harbor.example.com/service/token?service=harbor.example.com&scope=repository:project/repo:pull
	scope := buildRegistryScope(repoURL)
	tokenURL := fmt.Sprintf("%s?service=%s&scope=%s", registryAuthURL, registryService, url.QueryEscape(scope))

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "GET", tokenURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create registry token request: %w", err)
	}

	// Set authorization header based on whether username is provided
	if registryUsername != "" {
		// Basic Auth mode (e.g., Quay robot account federation)
		// Format: username:JWT_token as Basic Auth
		req.SetBasicAuth(registryUsername, identityToken)
	} else {
		// Bearer Auth mode (standard Docker registry)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", identityToken))
	}

	// Execute request
	resp, err := httpClient(config.Insecure).Do(req)
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

	// Return the registry username with the token
	// This allows the OCI client to authenticate at /v2/auth if needed
	return &Credentials{
		Username: registryUsername,
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
