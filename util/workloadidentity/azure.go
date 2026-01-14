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

// resolveAzure resolves Azure ACR credentials using Azure Workload Identity
func (r *Resolver) resolveAzure(ctx context.Context, sa *corev1.ServiceAccount, k8sToken, repoURL string, config *ProviderConfig) (*Credentials, error) {
	// Get Azure client ID and tenant ID from standard Azure Workload Identity annotations on service account
	clientID := sa.Annotations[AnnotationAzureClientID]
	if clientID == "" {
		return nil, fmt.Errorf("service account %s missing %s annotation", sa.Name, AnnotationAzureClientID)
	}

	tenantID := sa.Annotations[AnnotationAzureTenantID]
	if tenantID == "" {
		return nil, fmt.Errorf("service account %s missing %s annotation", sa.Name, AnnotationAzureTenantID)
	}

	// Get OAuth endpoint (allow override for sovereign clouds) from repository config
	tokenURL := config.TokenURL
	if tokenURL == "" {
		tokenURL = fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantID)
	} else {
		// Replace {tenantID} placeholder in custom endpoint
		tokenURL = strings.ReplaceAll(tokenURL, "{tenantID}", tenantID)
	}

	// Step 1: Exchange K8s JWT for Azure access token using client credentials flow
	azureToken, err := r.getAzureAccessToken(ctx, tokenURL, clientID, k8sToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get Azure access token: %w", err)
	}

	// Step 2: Exchange Azure access token for ACR refresh token
	acrToken, err := r.getACRRefreshToken(ctx, repoURL, azureToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get ACR refresh token: %w", err)
	}

	// ACR uses a special username format with the refresh token as password
	return &Credentials{
		Username: "00000000-0000-0000-0000-000000000000", // ACR service principal ID
		Password: acrToken,
	}, nil
}

// getAzureAccessToken exchanges a K8s JWT for an Azure access token
func (r *Resolver) getAzureAccessToken(ctx context.Context, tokenURL, clientID, k8sToken string) (string, error) {
	// Prepare OAuth 2.0 client credentials request with JWT bearer assertion
	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	data.Set("client_assertion", k8sToken)
	data.Set("scope", "https://management.azure.com/.default")
	data.Set("grant_type", "client_credentials")

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Execute request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return tokenResp.AccessToken, nil
}

// getACRRefreshToken exchanges an Azure access token for an ACR refresh token
func (r *Resolver) getACRRefreshToken(ctx context.Context, repoURL, azureAccessToken string) (string, error) {
	// Extract registry hostname from repo URL
	registry := extractACRRegistry(repoURL)

	// ACR token exchange endpoint
	exchangeURL := fmt.Sprintf("https://%s/oauth2/exchange", registry)

	// Prepare exchange request
	data := url.Values{}
	data.Set("grant_type", "access_token")
	data.Set("service", registry)
	data.Set("access_token", azureAccessToken)

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", exchangeURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create ACR exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Execute request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute ACR exchange request: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("ACR exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var acrResp struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&acrResp); err != nil {
		return "", fmt.Errorf("failed to decode ACR response: %w", err)
	}

	return acrResp.RefreshToken, nil
}

// extractACRRegistry extracts the registry hostname from an ACR repository URL
// Example: myregistry.azurecr.io/charts → myregistry.azurecr.io
func extractACRRegistry(repoURL string) string {
	// Remove oci:// prefix if present
	repoURL = strings.TrimPrefix(repoURL, "oci://")

	// Take the hostname part (before the first slash)
	parts := strings.Split(repoURL, "/")
	if len(parts) > 0 {
		return parts[0]
	}

	return repoURL
}