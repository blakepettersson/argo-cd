package workloadidentity

// # Generic Workload Identity Provider
//
// This file implements RFC 8693 OAuth 2.0 Token Exchange for custom identity providers
// and registries. It supports a flexible two-step authentication flow that can be
// configured for various identity systems including SPIFFE/SPIRE and container registries
// like Quay, Harbor, and others.
//
// ## Authentication Flow
//
// The generic provider supports two modes:
//
// 1. Single-step: Exchange K8s token for registry credentials directly
//    - K8s JWT → Token Exchange Endpoint → Registry credentials
//
// 2. Two-step: Exchange K8s token for identity token, then for registry credentials
//    - K8s JWT → Identity Provider (e.g., SPIRE) → Identity Token
//    - Identity Token → Registry Auth Endpoint → Registry credentials
//
// ---
//
// # Option A: SPIFFE/SPIRE + Quay Setup
//
// This setup uses SPIRE as an intermediate identity provider with OIDC federation.
// SPIRE provides workload attestation and issues SPIFFE JWT-SVIDs that Quay trusts.
//
// ## Architecture
//
//	┌─────────────────┐     ┌──────────────────┐     ┌─────────────┐
//	│ ArgoCD (K8s SA) │────▶│ SPIRE OIDC Proxy │────▶│    Quay     │
//	│    Token        │     │  (Token Exchange)│     │ (Registry)  │
//	└─────────────────┘     └──────────────────┘     └─────────────┘
//	                               │
//	                               ▼
//	                        SPIRE Server
//	                        (OIDC Provider)
//
// ## Prerequisites
//
// 1. SPIRE server deployed with OIDC Discovery Provider enabled
// 2. SPIRE OIDC token exchange proxy (handles K8s token → SPIFFE JWT conversion)
// 3. Quay configured to trust SPIRE's OIDC issuer
//
// ## Step 1: Deploy SPIRE Server with OIDC Discovery Provider
//
// Configure SPIRE server with OIDC Discovery Provider in server.conf:
//
//	server {
//	    trust_domain = "example.org"
//	    # ... other config
//	}
//
//	plugins {
//	    KeyManager "disk" {
//	        plugin_data {
//	            keys_path = "/run/spire/data/keys.json"
//	        }
//	    }
//	}
//
//	# Enable OIDC Discovery Provider
//	oidc_discovery {
//	    # Public URL where SPIRE's OIDC endpoints are accessible
//	    issuer = "https://spire.example.org"
//
//	    # Allowed audiences for JWT-SVIDs
//	    audiences = ["quay.example.org"]
//	}
//
// ## Step 2: Deploy SPIRE OIDC Token Exchange Proxy
//
// You need a service that accepts K8s tokens and exchanges them for SPIFFE JWT-SVIDs.
// This proxy should:
//   - Validate incoming K8s service account tokens against the cluster's OIDC issuer
//   - Map K8s service accounts to SPIFFE IDs
//   - Call SPIRE's Workload API to obtain JWT-SVIDs
//   - Return the JWT-SVID in RFC 8693 token exchange response format
//
// Example SPIFFE ID mapping:
//
//	K8s SA: system:serviceaccount:argocd:argocd-project-default
//	     ↓
//	SPIFFE ID: spiffe://example.org/ns/argocd/sa/argocd-project-default
//
// The proxy should expose an endpoint like:
//
//	POST /token
//	Content-Type: application/x-www-form-urlencoded
//
//	grant_type=urn:ietf:params:oauth:grant-type:token-exchange
//	&subject_token=<k8s-jwt>
//	&subject_token_type=urn:ietf:params:oauth:token-type:jwt
//	&audience=quay.example.org
//
// Response:
//
//	{
//	    "access_token": "<spiffe-jwt-svid>",
//	    "token_type": "Bearer",
//	    "expires_in": 3600
//	}
//
// ## Step 3: Configure Quay to Trust SPIRE OIDC
//
// In Quay's config.yaml, add SPIRE as an external OIDC provider:
//
//	FEATURE_DIRECT_LOGIN: true
//	FEATURE_TEAM_SYNCING: true
//
//	# External OIDC configuration
//	SPIRE_LOGIN_CONFIG:
//	    CLIENT_ID: "quay.example.org"
//	    CLIENT_SECRET: ""  # Not needed for JWT validation
//	    OIDC_SERVER: "https://spire.example.org"
//	    SERVICE_NAME: "SPIRE"
//	    PREFERRED_USERNAME_CLAIM_NAME: "sub"
//
// For robot account mapping, configure Quay to map SPIFFE IDs to robot accounts
// or use team sync with SPIFFE ID claims.
//
// ## Step 4: Create Kubernetes ServiceAccount
//
//	apiVersion: v1
//	kind: ServiceAccount
//	metadata:
//	  name: argocd-project-default
//	  namespace: argocd
//	  annotations:
//	    # SPIFFE ID that SPIRE will issue for this SA
//	    spiffe.io/spiffe-id: "spiffe://example.org/ns/argocd/sa/argocd-project-default"
//
// ## Step 5: Create Repository Secret
//
//	apiVersion: v1
//	kind: Secret
//	metadata:
//	  name: quay-repo
//	  namespace: argocd
//	  labels:
//	    argocd.argoproj.io/secret-type: repository
//	stringData:
//	  type: helm
//	  url: oci://quay.example.org/myorg/charts
//	  project: default
//	  useWorkloadIdentity: "true"
//	  workloadIdentityProvider: "generic"
//	  workloadIdentityTokenURL: "https://spire-proxy.example.org/token"
//	  workloadIdentityAudience: "quay.example.org"
//	  workloadIdentityRegistryAuthURL: "https://quay.example.org/v2/auth"
//	  workloadIdentityRegistryService: "quay.example.org"
//
// ---
//
// # Option B: Direct K8s OIDC + Quay Setup (Simpler)
//
// This setup configures Quay to trust the Kubernetes cluster's OIDC issuer directly,
// eliminating the need for SPIRE. Simpler to set up but without workload attestation.
//
// ## Architecture
//
//	┌─────────────────┐     ┌─────────────┐
//	│ ArgoCD (K8s SA) │────▶│    Quay     │
//	│    Token        │     │ (Registry)  │
//	└─────────────────┘     └─────────────┘
//	                               │
//	                               ▼
//	                        K8s OIDC Issuer
//	                        (Token Validation)
//
// ## Step 1: Get Your Kubernetes OIDC Issuer URL
//
// For EKS:
//
//	aws eks describe-cluster --name $CLUSTER_NAME \
//	    --query "cluster.identity.oidc.issuer" --output text
//
// For GKE:
//
//	# GKE clusters use this format:
//	https://container.googleapis.com/v1/projects/<PROJECT>/locations/<LOCATION>/clusters/<CLUSTER>
//
// For self-managed clusters (kind, k3s, kubeadm):
//
//	kubectl get --raw /.well-known/openid-configuration | jq -r '.issuer'
//
// ## Step 2: Configure Quay to Trust K8s OIDC
//
// In Quay's config.yaml:
//
//	FEATURE_DIRECT_LOGIN: true
//
//	# Kubernetes OIDC configuration
//	K8S_LOGIN_CONFIG:
//	    CLIENT_ID: "<your-k8s-oidc-audience>"  # Often the cluster URL or custom audience
//	    CLIENT_SECRET: ""
//	    OIDC_SERVER: "<k8s-oidc-issuer-url>"
//	    SERVICE_NAME: "Kubernetes"
//	    PREFERRED_USERNAME_CLAIM_NAME: "sub"
//	    # Map K8s SA subject to Quay identity
//	    # Subject format: system:serviceaccount:<namespace>:<name>
//
// ## Step 3: Create Kubernetes ServiceAccount
//
//	apiVersion: v1
//	kind: ServiceAccount
//	metadata:
//	  name: argocd-project-default
//	  namespace: argocd
//
// ## Step 4: Create Repository Secret
//
//	apiVersion: v1
//	kind: Secret
//	metadata:
//	  name: quay-repo
//	  namespace: argocd
//	  labels:
//	    argocd.argoproj.io/secret-type: repository
//	stringData:
//	  type: helm
//	  url: oci://quay.example.org/myorg/charts
//	  project: default
//	  useWorkloadIdentity: "true"
//	  workloadIdentityProvider: "generic"
//	  # No tokenURL needed - K8s token goes directly to registry
//	  workloadIdentityAudience: "quay.example.org"
//	  workloadIdentityRegistryAuthURL: "https://quay.example.org/v2/auth"
//	  workloadIdentityRegistryService: "quay.example.org"
//
// Note: For Option B without tokenURL, the K8s token is used directly with the
// registry auth endpoint. This requires Quay to validate the K8s token against
// the cluster's OIDC issuer.
//
// ---
//
// # Harbor Setup (Alternative Registry)
//
// Harbor also supports OIDC authentication and can be configured similarly:
//
// ## Configure Harbor OIDC
//
// In Harbor's Administration > Configuration > Authentication:
//   - Auth Mode: OIDC
//   - OIDC Provider Name: Kubernetes (or SPIRE)
//   - OIDC Endpoint: <oidc-issuer-url>
//   - OIDC Client ID: harbor
//   - OIDC Scope: openid
//   - Verify Certificate: true
//   - Automatic Onboarding: true
//   - Username Claim: sub
//
// ## Repository Secret for Harbor
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
//	  workloadIdentityProvider: "generic"
//	  workloadIdentityAudience: "harbor"
//	  workloadIdentityRegistryAuthURL: "https://harbor.example.org/service/token"
//	  workloadIdentityRegistryService: "harbor-registry"

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

// resolveGeneric resolves credentials for custom registries using RFC 8693 token exchange.
//
// It supports three modes:
//
// 1. Two-step (SPIFFE/SPIRE): K8s token → Identity Provider → Registry
//   - Requires: tokenURL, audience, registryAuthURL
//
// 2. Single-step with token exchange: K8s token → Token Exchange → Credentials
//   - Requires: tokenURL, audience
//   - The exchanged token is used directly as password
//
// 3. Direct registry auth (Option B): K8s token → Registry directly
//   - Requires: registryAuthURL (tokenURL not set)
//   - K8s token is used directly with registry auth endpoint
func (r *Resolver) resolveGeneric(ctx context.Context, sa *corev1.ServiceAccount, k8sToken, repoURL string, config *ProviderConfig) (*Credentials, error) {
	tokenURL := config.TokenURL
	registryAuthURL := config.RegistryAuthURL

	// Determine the identity token to use
	var identityToken string
	var err error

	if tokenURL != "" {
		// Mode 1 or 2: Exchange K8s token for identity token first
		audience := config.Audience
		if audience == "" {
			return nil, fmt.Errorf("workloadIdentityAudience not specified for generic provider with tokenURL")
		}

		// Exchange K8s JWT for identity token (e.g., SPIFFE JWT from SPIRE)
		identityToken, err = r.exchangeGenericToken(ctx, tokenURL, k8sToken, audience)
		if err != nil {
			return nil, fmt.Errorf("failed to exchange token: %w", err)
		}
	} else {
		// Mode 3: Use K8s token directly (Option B - direct K8s OIDC to registry)
		identityToken = k8sToken
	}

	// Check if registry auth URL is configured
	if registryAuthURL != "" {
		// Exchange identity token for registry credentials
		return r.exchangeRegistryToken(ctx, config, identityToken, repoURL)
	}

	// No registry auth URL - need at least tokenURL for single-step exchange
	if tokenURL == "" {
		return nil, fmt.Errorf("either workloadIdentityTokenURL or workloadIdentityRegistryAuthURL must be specified for generic provider")
	}

	// Use the exchanged token directly as password
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
