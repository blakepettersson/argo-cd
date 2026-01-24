package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/argoproj/argo-cd/v3/util/workloadidentity/v2/identity"
)

// ACRAuthenticator exchanges Azure credentials for ACR authorization tokens
type ACRAuthenticator struct{}

// NewACRAuthenticator creates a new ACR authenticator
func NewACRAuthenticator() *ACRAuthenticator {
	return &ACRAuthenticator{}
}

// Authenticate exchanges Azure credentials for ACR authorization tokens
func (a *ACRAuthenticator) Authenticate(ctx context.Context, token *identity.Token, repoURL string, cfg *Config) (*Credentials, error) {
	registry := extractACRRegistry(repoURL)
	log.WithField("registry", registry).Info("ACR: exchanging Azure token for ACR refresh token")

	// Step 2: Exchange Azure access token for ACR refresh token
	acrToken, err := a.getACRRefreshToken(ctx, repoURL, token.Token)
	if err != nil {
		log.WithFields(log.Fields{
			"registry": registry,
			"error":    err.Error(),
		}).Error("ACR: failed to get refresh token")
		return nil, fmt.Errorf("failed to get ACR refresh token: %w", err)
	}

	log.WithField("registry", registry).Info("ACR: successfully obtained refresh token")

	return &Credentials{
		Username: "00000000-0000-0000-0000-000000000000", // ACR service principal ID
		Password: acrToken,
	}, nil
}

// getACRRefreshToken exchanges an Azure access token for an ACR refresh token
func (a *ACRAuthenticator) getACRRefreshToken(ctx context.Context, repoURL, azureAccessToken string) (string, error) {
	// Extract registry hostname from repo URL
	registry := extractACRRegistry(repoURL)

	// ACR token exchange endpoint
	exchangeURL := fmt.Sprintf("https://%s/oauth2/exchange", registry)

	log.WithFields(log.Fields{
		"registry":    registry,
		"exchangeURL": exchangeURL,
	}).Debug("ACR: calling token exchange endpoint")

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

// Ensure ACRAuthenticator implements Authenticator
var _ Authenticator = (*ACRAuthenticator)(nil)
