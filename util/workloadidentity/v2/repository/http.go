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

// HTTPAuthenticator exchanges an identity token for registry credentials via HTTP.
// It supports both Bearer and Basic auth modes, making it suitable for registries
// that accept JWT tokens through either mechanism:
//
//   - Basic Auth: When Username is configured, sends username:token as Basic Auth.
//     Used by Quay robot account federation, where the JWT is sent as the password.
//
//   - Bearer Auth: When Username is not set, sends the token as a Bearer header.
//     Used by registries that accept OIDC/JWT tokens directly as Bearer credentials.
//
// The auth URL can be configured explicitly or discovered via WWW-Authenticate.
type HTTPAuthenticator struct {
	HTTPClient *http.Client
}

func NewHTTPAuthenticator() *HTTPAuthenticator {
	return &HTTPAuthenticator{}
}

func (a *HTTPAuthenticator) Name() string {
	return "http"
}

func (a *HTTPAuthenticator) Authenticate(ctx context.Context, token *identity.Token, repoURL string, config *Config) (*Credentials, error) {
	if token.Type != identity.TokenTypeBearer {
		return nil, fmt.Errorf("http authenticator requires a bearer token, got %s", token.Type)
	}
	if token.Token == "" {
		return nil, fmt.Errorf("empty bearer token")
	}

	registry := extractRegistryHost(repoURL)

	// Resolve auth URL
	authURL := config.AuthURL
	if authURL == "" {
		log.WithField("registry", registry).Debug("HTTP: auth URL not configured, discovering via WWW-Authenticate")
		discovered, err := discoverAuthURL(ctx, repoURL, a.getHTTPClient(config.Insecure), config.Insecure)
		if err != nil {
			return nil, fmt.Errorf("auth URL not configured and discovery failed: %w", err)
		}
		authURL = discovered
		log.WithField("authURL", authURL).Debug("HTTP: discovered auth URL")
	}

	// Build request URL with query params
	reqURL, err := url.Parse(authURL)
	if err != nil {
		return nil, fmt.Errorf("invalid auth URL: %w", err)
	}

	q := reqURL.Query()

	service := config.Service
	if service == "" {
		service = registry
	}
	q.Set("service", service)

	if config.Scope != "" {
		for _, scope := range strings.Split(config.Scope, " ") {
			scope = strings.TrimSpace(scope)
			if scope != "" {
				q.Add("scope", scope)
			}
		}
	} else {
		// Build default scope from repo URL
		scope := buildRegistryScope(repoURL)
		if scope != "" {
			q.Add("scope", scope)
		}
	}

	reqURL.RawQuery = q.Encode()

	log.WithFields(log.Fields{
		"url":      reqURL.String(),
		"insecure": config.Insecure,
	}).Info("HTTP: requesting token from auth endpoint")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set auth header based on whether username is configured
	if config.Username != "" {
		// Basic Auth: username + JWT as password (e.g., Quay robot account federation)
		req.SetBasicAuth(config.Username, token.Token)
		log.WithFields(log.Fields{
			"registry":    registry,
			"username":    config.Username,
			"tokenLength": len(token.Token),
		}).Info("HTTP: using Basic Auth with identity token as password")
	} else {
		// Bearer Auth: send JWT directly
		req.Header.Set("Authorization", "Bearer "+token.Token)
		log.WithField("registry", registry).Info("HTTP: using Bearer Auth with identity token")
	}

	client := a.getHTTPClient(config.Insecure)
	resp, err := client.Do(req)
	if err != nil {
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
		}).Error("HTTP: token request failed")
		return nil, fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response — Docker v2 spec uses "token" or "access_token"
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

	// Use the configured username for the returned credentials, or fall back to $oauthtoken
	username := config.Username
	if username == "" {
		username = "$oauthtoken"
	}

	log.WithFields(log.Fields{
		"registry": registry,
		"username": username,
	}).Info("HTTP: successfully obtained registry token")

	return &Credentials{
		Username: username,
		Password: accessToken,
	}, nil
}

func (a *HTTPAuthenticator) getHTTPClient(insecure bool) *http.Client {
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

// buildRegistryScope builds a Docker v2 scope string from a repository URL.
// Example: oci://registry.example.com/namespace/repo → repository:namespace/repo:pull
func buildRegistryScope(repoURL string) string {
	u := strings.TrimPrefix(repoURL, "oci://")
	parts := strings.SplitN(u, "/", 2)
	if len(parts) < 2 {
		return ""
	}
	return fmt.Sprintf("repository:%s:pull", parts[1])
}

// discoverAuthURL discovers the auth endpoint from the registry's 401 WWW-Authenticate header.
func discoverAuthURL(ctx context.Context, repoURL string, client *http.Client, insecure bool) (string, error) {
	host := extractRegistryHost(repoURL)
	if host == "" {
		return "", fmt.Errorf("could not extract registry host from URL")
	}

	scheme := "https"
	if insecure {
		scheme = "http"
	}
	pingURL := fmt.Sprintf("%s://%s/v2/", scheme, host)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pingURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create ping request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("ping request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		return "", fmt.Errorf("expected 401 from %s, got %d", pingURL, resp.StatusCode)
	}

	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if wwwAuth == "" {
		return "", fmt.Errorf("no WWW-Authenticate header in 401 response")
	}

	realm := parseWWWAuthenticateRealm(wwwAuth)
	if realm == "" {
		return "", fmt.Errorf("could not parse realm from WWW-Authenticate: %s", wwwAuth)
	}

	return realm, nil
}

var _ Authenticator = (*HTTPAuthenticator)(nil)
