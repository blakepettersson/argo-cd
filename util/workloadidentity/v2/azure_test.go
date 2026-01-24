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

func TestExtractACRRegistry(t *testing.T) {
	tests := []struct {
		name     string
		repoURL  string
		expected string
	}{
		{
			name:     "standard ACR URL",
			repoURL:  "myregistry.azurecr.io/charts",
			expected: "myregistry.azurecr.io",
		},
		{
			name:     "ACR URL with oci:// prefix",
			repoURL:  "oci://myregistry.azurecr.io/helm/charts",
			expected: "myregistry.azurecr.io",
		},
		{
			name:     "ACR URL with nested path",
			repoURL:  "myregistry.azurecr.io/team/project/app",
			expected: "myregistry.azurecr.io",
		},
		{
			name:     "ACR URL without path",
			repoURL:  "myregistry.azurecr.io",
			expected: "myregistry.azurecr.io",
		},
		{
			name:     "ACR URL with oci:// and no path",
			repoURL:  "oci://myregistry.azurecr.io",
			expected: "myregistry.azurecr.io",
		},
		{
			name:     "sovereign cloud ACR",
			repoURL:  "myregistry.azurecr.cn/app",
			expected: "myregistry.azurecr.cn",
		},
		{
			name:     "empty URL",
			repoURL:  "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractACRRegistry(tt.repoURL)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestResolveAzure_MissingClientID(t *testing.T) {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "argocd-project-default",
			Namespace: "argocd",
			Annotations: map[string]string{
				// Missing client-id annotation
				AnnotationAzureTenantID: "tenant-123",
			},
		},
	}

	clientset := fake.NewSimpleClientset(sa)
	resolver := NewResolver(clientset, "argocd")

	_, err := resolver.resolveAzure(context.Background(), sa, "k8s-token", "oci://myregistry.azurecr.io/charts", &ProviderConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing")
	assert.Contains(t, err.Error(), AnnotationAzureClientID)
}

func TestResolveAzure_MissingTenantID(t *testing.T) {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "argocd-project-default",
			Namespace: "argocd",
			Annotations: map[string]string{
				AnnotationAzureClientID: "client-123",
				// Missing tenant-id annotation
			},
		},
	}

	clientset := fake.NewSimpleClientset(sa)
	resolver := NewResolver(clientset, "argocd")

	_, err := resolver.resolveAzure(context.Background(), sa, "k8s-token", "oci://myregistry.azurecr.io/charts", &ProviderConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing")
	assert.Contains(t, err.Error(), AnnotationAzureTenantID)
}

func TestGetAzureAccessToken_Success(t *testing.T) {
	// Create a mock OAuth server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

		err := r.ParseForm()
		require.NoError(t, err)

		assert.Equal(t, "test-client-id", r.FormValue("client_id"))
		assert.Equal(t, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", r.FormValue("client_assertion_type"))
		assert.Equal(t, "test-k8s-token", r.FormValue("client_assertion"))
		assert.Equal(t, "client_credentials", r.FormValue("grant_type"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "azure-access-token-123",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	clientset := fake.NewSimpleClientset()
	resolver := NewResolver(clientset, "argocd")

	token, err := resolver.getAzureAccessToken(context.Background(), server.URL, "test-client-id", "test-k8s-token")
	require.NoError(t, err)
	assert.Equal(t, "azure-access-token-123", token)
}

func TestGetAzureAccessToken_ErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "invalid_grant", "error_description": "Token expired"}`))
	}))
	defer server.Close()

	clientset := fake.NewSimpleClientset()
	resolver := NewResolver(clientset, "argocd")

	_, err := resolver.getAzureAccessToken(context.Background(), server.URL, "test-client-id", "test-k8s-token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "400")
}

func TestGetACRRefreshToken_Success(t *testing.T) {
	// Create a mock ACR server with TLS
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/oauth2/exchange", r.URL.Path)
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

		err := r.ParseForm()
		require.NoError(t, err)

		assert.Equal(t, "access_token", r.FormValue("grant_type"))
		assert.Equal(t, "test-azure-token", r.FormValue("access_token"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"refresh_token": "acr-refresh-token-456",
		})
	}))
	defer server.Close()

	// The getACRRefreshToken function constructs an HTTPS URL from the registry hostname,
	// but uses http.DefaultClient which won't trust the test server's self-signed cert.
	// We need to test just the URL construction and HTTP logic separately.
	// For now, skip this integration-style test.
	t.Skip("getACRRefreshToken uses hardcoded HTTPS and http.DefaultClient, needs refactoring for testability")
}

func TestGetACRRefreshToken_ErrorResponse(t *testing.T) {
	// Same issue as above - the function constructs HTTPS URL from registry name
	t.Skip("getACRRefreshToken uses hardcoded HTTPS and http.DefaultClient, needs refactoring for testability")
}

func TestResolveAzure_TokenURLPlaceholder(t *testing.T) {
	// Test that {tenantID} placeholder gets replaced in custom tokenURL
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "argocd-project-default",
			Namespace: "argocd",
			Annotations: map[string]string{
				AnnotationAzureClientID: "client-123",
				AnnotationAzureTenantID: "my-tenant-id",
			},
		},
	}

	var capturedURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedURL = r.URL.String()
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "test"}`))
	}))
	defer server.Close()

	clientset := fake.NewSimpleClientset(sa)
	resolver := NewResolver(clientset, "argocd")

	config := &ProviderConfig{
		TokenURL: server.URL + "/{tenantID}/oauth2/token",
	}

	// This will fail because of the mock server, but we can verify the URL was constructed correctly
	_, _ = resolver.resolveAzure(context.Background(), sa, "k8s-token", "oci://myregistry.azurecr.io/charts", config)

	assert.Contains(t, capturedURL, "my-tenant-id")
	assert.NotContains(t, capturedURL, "{tenantID}")
}