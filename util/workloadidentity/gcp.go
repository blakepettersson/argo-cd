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

const (
	DefaultGCPSTSURL = "https://sts.googleapis.com/v1/token"
)

// resolveGCP resolves GCP Artifact Registry/GCR credentials using Workload Identity
func (r *Resolver) resolveGCP(ctx context.Context, sa *corev1.ServiceAccount, k8sToken string, config *ProviderConfig) (*Credentials, error) {
	// Get GCP service account from standard GKE annotation on service account
	gcpSA := sa.Annotations[AnnotationGCPSA]
	if gcpSA == "" {
		return nil, fmt.Errorf("service account %s missing %s annotation", sa.Name, AnnotationGCPSA)
	}

	// Get STS endpoint (allow override for custom environments) from repository config
	tokenURL := config.TokenURL
	if tokenURL == "" {
		tokenURL = DefaultGCPSTSURL
	}

	// Prepare RFC 8693 token exchange request
	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	data.Set("subject_token", k8sToken)
	data.Set("subject_token_type", "urn:ietf:params:oauth:token-type:jwt")
	data.Set("requested_token_type", "urn:ietf:params:oauth:token-type:access_token")
	data.Set("audience", fmt.Sprintf("//iam.googleapis.com/%s", gcpSA))
	data.Set("scope", "https://www.googleapis.com/auth/cloud-platform")

	// Create HTTP request for token exchange
	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Execute token exchange
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange token: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse token response
	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	// For GCR/Artifact Registry, the username is always "oauth2accesstoken"
	// and the GCP access token is used as the password
	return &Credentials{
		Username: "oauth2accesstoken",
		Password: tokenResp.AccessToken,
	}, nil
}