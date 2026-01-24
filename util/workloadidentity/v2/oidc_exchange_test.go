package v2

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestExtractRegistryHost(t *testing.T) {
	tests := []struct {
		name     string
		repoURL  string
		expected string
	}{
		{
			name:     "standard registry URL",
			repoURL:  "harbor.example.com/project/repo",
			expected: "harbor.example.com",
		},
		{
			name:     "registry URL with oci:// prefix",
			repoURL:  "oci://harbor.example.com/charts",
			expected: "harbor.example.com",
		},
		{
			name:     "registry URL with nested path",
			repoURL:  "registry.example.org/team/project/app",
			expected: "registry.example.org",
		},
		{
			name:     "registry URL without path",
			repoURL:  "registry.example.org",
			expected: "registry.example.org",
		},
		{
			name:     "registry with port",
			repoURL:  "registry.example.org:5000/repo",
			expected: "registry.example.org:5000",
		},
		{
			name:     "quay.io",
			repoURL:  "quay.io/myorg/myrepo",
			expected: "quay.io",
		},
		{
			name:     "ghcr.io",
			repoURL:  "oci://ghcr.io/owner/package",
			expected: "ghcr.io",
		},
		{
			name:     "empty URL",
			repoURL:  "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractRegistryHost(tt.repoURL)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildRegistryScope(t *testing.T) {
	tests := []struct {
		name     string
		repoURL  string
		expected string
	}{
		{
			name:     "simple repository",
			repoURL:  "harbor.example.com/project/repo",
			expected: "repository:project/repo:pull",
		},
		{
			name:     "repository with oci:// prefix",
			repoURL:  "oci://harbor.example.com/charts/mychart",
			expected: "repository:charts/mychart:pull",
		},
		{
			name:     "nested repository path",
			repoURL:  "registry.example.org/team/project/app",
			expected: "repository:team/project/app:pull",
		},
		{
			name:     "URL without path returns wildcard",
			repoURL:  "registry.example.org",
			expected: "repository:*:pull",
		},
		{
			name:     "oci:// URL without path returns wildcard",
			repoURL:  "oci://registry.example.org",
			expected: "repository:*:pull",
		},
		{
			name:     "single path segment",
			repoURL:  "quay.io/myrepo",
			expected: "repository:myrepo:pull",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildRegistryScope(tt.repoURL)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHttpClient(t *testing.T) {
	t.Run("secure client", func(t *testing.T) {
		client := httpClient(false)
		assert.Equal(t, http.DefaultClient, client)
	})

	t.Run("insecure client", func(t *testing.T) {
		client := httpClient(true)
		assert.NotNil(t, client)
		assert.NotEqual(t, http.DefaultClient, client)
		// Verify it has a custom transport
		transport, ok := client.Transport.(*http.Transport)
		require.True(t, ok)
		assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)
	})
}

func TestResolveOIDC_NoConfigurationError(t *testing.T) {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "argocd-project-default",
			Namespace: "argocd",
		},
	}

	clientset := fake.NewSimpleClientset(sa)
	resolver := NewResolver(clientset, "argocd")

	// Config with neither tokenURL nor registryAuthURL
	config := &ProviderConfig{}

	_, err := resolver.resolveOIDC(context.Background(), sa, "k8s-token", "oci://registry.example.com/repo", config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "workloadIdentityTokenURL or workloadIdentityRegistryAuthURL must be specified")
}

func TestResolveOIDC_TokenExchangeMissingAudience(t *testing.T) {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "argocd-project-default",
			Namespace: "argocd",
		},
	}

	clientset := fake.NewSimpleClientset(sa)
	resolver := NewResolver(clientset, "argocd")

	// Config with tokenURL but no audience
	config := &ProviderConfig{
		TokenURL: "https://token.example.com",
		// Missing Audience
	}

	_, err := resolver.resolveOIDC(context.Background(), sa, "k8s-token", "oci://registry.example.com/repo", config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "workloadIdentityAudience not specified")
}

func TestExchangeOIDCToken_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

		err := r.ParseForm()
		require.NoError(t, err)

		assert.Equal(t, "urn:ietf:params:oauth:grant-type:token-exchange", r.FormValue("grant_type"))
		assert.Equal(t, "test-subject-token", r.FormValue("subject_token"))
		assert.Equal(t, "urn:ietf:params:oauth:token-type:jwt", r.FormValue("subject_token_type"))
		assert.Equal(t, "urn:ietf:params:oauth:token-type:access_token", r.FormValue("requested_token_type"))
		assert.Equal(t, "test-audience", r.FormValue("audience"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "exchanged-token-123",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	clientset := fake.NewSimpleClientset()
	resolver := NewResolver(clientset, "argocd")

	token, err := resolver.exchangeOIDCToken(context.Background(), server.URL, "test-subject-token", "test-audience", false)
	require.NoError(t, err)
	assert.Equal(t, "exchanged-token-123", token)
}

func TestExchangeOIDCToken_ErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error": "invalid_token"}`))
	}))
	defer server.Close()

	clientset := fake.NewSimpleClientset()
	resolver := NewResolver(clientset, "argocd")

	_, err := resolver.exchangeOIDCToken(context.Background(), server.URL, "test-token", "test-audience", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
}

func TestExchangeRegistryToken_BearerAuth_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)

		// Verify Bearer auth is used when no username is configured
		authHeader := r.Header.Get("Authorization")
		assert.Equal(t, "Bearer test-identity-token", authHeader)

		// Verify query parameters
		assert.Contains(t, r.URL.RawQuery, "service=")
		assert.Contains(t, r.URL.RawQuery, "scope=")

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"token":      "registry-token-456",
			"expires_in": 300,
		})
	}))
	defer server.Close()

	clientset := fake.NewSimpleClientset()
	resolver := NewResolver(clientset, "argocd")

	config := &ProviderConfig{
		RegistryAuthURL: server.URL,
		RegistryService: "test-registry",
		// No RegistryUsername - should use Bearer auth
	}

	creds, err := resolver.exchangeRegistryToken(context.Background(), config, "test-identity-token", "oci://test-registry/project/repo")
	require.NoError(t, err)
	assert.Equal(t, "", creds.Username)
	assert.Equal(t, "registry-token-456", creds.Password)
}

func TestExchangeRegistryToken_BasicAuth_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)

		// Verify Basic auth is used when username is configured
		username, password, ok := r.BasicAuth()
		assert.True(t, ok)
		assert.Equal(t, "robot+myorg", username)
		assert.Equal(t, "test-jwt-token", password)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"token":      "quay-registry-token-789",
			"expires_in": 300,
		})
	}))
	defer server.Close()

	clientset := fake.NewSimpleClientset()
	resolver := NewResolver(clientset, "argocd")

	config := &ProviderConfig{
		RegistryAuthURL:  server.URL,
		RegistryService:  "quay.io",
		RegistryUsername: "robot+myorg",
	}

	creds, err := resolver.exchangeRegistryToken(context.Background(), config, "test-jwt-token", "oci://quay.io/myorg/repo")
	require.NoError(t, err)
	assert.Equal(t, "robot+myorg", creds.Username)
	assert.Equal(t, "quay-registry-token-789", creds.Password)
}

func TestExchangeRegistryToken_AccessTokenField(t *testing.T) {
	// Some registries return access_token instead of token
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "access-token-field",
			"expires_in":   300,
		})
	}))
	defer server.Close()

	clientset := fake.NewSimpleClientset()
	resolver := NewResolver(clientset, "argocd")

	config := &ProviderConfig{
		RegistryAuthURL: server.URL,
	}

	creds, err := resolver.exchangeRegistryToken(context.Background(), config, "test-token", "oci://registry.example.com/repo")
	require.NoError(t, err)
	assert.Equal(t, "access-token-field", creds.Password)
}

func TestExchangeRegistryToken_MissingToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			// No token or access_token field
			"expires_in": 300,
		})
	}))
	defer server.Close()

	clientset := fake.NewSimpleClientset()
	resolver := NewResolver(clientset, "argocd")

	config := &ProviderConfig{
		RegistryAuthURL: server.URL,
	}

	_, err := resolver.exchangeRegistryToken(context.Background(), config, "test-token", "oci://registry.example.com/repo")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing token field")
}

func TestExchangeRegistryToken_ErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error": "access_denied"}`))
	}))
	defer server.Close()

	clientset := fake.NewSimpleClientset()
	resolver := NewResolver(clientset, "argocd")

	config := &ProviderConfig{
		RegistryAuthURL: server.URL,
	}

	_, err := resolver.exchangeRegistryToken(context.Background(), config, "test-token", "oci://registry.example.com/repo")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}

func TestExchangeRegistryToken_ServiceFromRepoURL(t *testing.T) {
	var capturedService string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedService = r.URL.Query().Get("service")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"token": "test-token",
		})
	}))
	defer server.Close()

	clientset := fake.NewSimpleClientset()
	resolver := NewResolver(clientset, "argocd")

	config := &ProviderConfig{
		RegistryAuthURL: server.URL,
		// No RegistryService - should extract from repoURL
	}

	_, err := resolver.exchangeRegistryToken(context.Background(), config, "test-token", "oci://my-registry.example.com/project/repo")
	require.NoError(t, err)
	assert.Equal(t, "my-registry.example.com", capturedService)
}

func TestResolveOIDC_DirectK8sToken(t *testing.T) {
	// Test the direct K8s OIDC mode (no tokenURL, just registryAuthURL)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the K8s token is passed directly
		authHeader := r.Header.Get("Authorization")
		assert.Equal(t, "Bearer direct-k8s-token", authHeader)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"token": "registry-token",
		})
	}))
	defer server.Close()

	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "argocd-project-default",
			Namespace: "argocd",
		},
	}

	clientset := fake.NewSimpleClientset(sa)
	resolver := NewResolver(clientset, "argocd")

	config := &ProviderConfig{
		// No TokenURL - direct K8s OIDC mode
		RegistryAuthURL: server.URL,
	}

	creds, err := resolver.resolveOIDC(context.Background(), sa, "direct-k8s-token", "oci://registry.example.com/repo", config)
	require.NoError(t, err)
	assert.Equal(t, "registry-token", creds.Password)
}

func TestResolveOIDC_TokenExchangeOnly(t *testing.T) {
	// Test token exchange without registry auth (token used directly as password)
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "exchanged-access-token",
		})
	}))
	defer tokenServer.Close()

	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "argocd-project-default",
			Namespace: "argocd",
		},
	}

	clientset := fake.NewSimpleClientset(sa)
	resolver := NewResolver(clientset, "argocd")

	config := &ProviderConfig{
		TokenURL: tokenServer.URL,
		Audience: "test-audience",
		// No RegistryAuthURL - token used directly
	}

	creds, err := resolver.resolveOIDC(context.Background(), sa, "k8s-token", "oci://registry.example.com/repo", config)
	require.NoError(t, err)
	assert.Equal(t, "", creds.Username)
	assert.Equal(t, "exchanged-access-token", creds.Password)
}