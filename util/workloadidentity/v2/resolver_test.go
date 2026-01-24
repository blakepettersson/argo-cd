package v2

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/argoproj/argo-cd/v3/util/workloadidentity/v2/mocks"
)

func TestGetServiceAccountName(t *testing.T) {
	tests := []struct {
		name        string
		projectName string
		expected    string
	}{
		{
			name:        "empty project returns global SA",
			projectName: "",
			expected:    "argocd-global",
		},
		{
			name:        "default project",
			projectName: "default",
			expected:    "argocd-project-default",
		},
		{
			name:        "custom project",
			projectName: "my-project",
			expected:    "argocd-project-my-project",
		},
		{
			name:        "project with hyphens",
			projectName: "team-a-prod",
			expected:    "argocd-project-team-a-prod",
		},
		{
			name:        "project with numbers",
			projectName: "project123",
			expected:    "argocd-project-project123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetServiceAccountName(tt.projectName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNewResolver(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	namespace := "argocd"

	resolver := NewResolver(clientset, namespace)

	require.NotNil(t, resolver)
	assert.NotNil(t, resolver.serviceAccounts)
}

func TestResolveCredentials_NilConfig(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	resolver := NewResolver(clientset, "argocd")

	_, err := resolver.ResolveCredentials(context.Background(), "default", "https://example.com", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "workload identity provider not specified")
}

func TestResolveCredentials_EmptyProvider(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	resolver := NewResolver(clientset, "argocd")

	config := &ProviderConfig{
		Provider: "",
	}

	_, err := resolver.ResolveCredentials(context.Background(), "default", "https://example.com", config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "workload identity provider not specified")
}

func TestResolveCredentials_ServiceAccountNotFound(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	resolver := NewResolver(clientset, "argocd")

	config := &ProviderConfig{
		Provider: "aws",
	}

	_, err := resolver.ResolveCredentials(context.Background(), "nonexistent", "https://example.com", config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get service account")
}

func TestResolveCredentials_WithMock_UnsupportedProvider(t *testing.T) {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "argocd-project-default",
			Namespace: "argocd",
		},
	}

	mock := &mocks.ServiceAccountInterface{
		GetFunc: func(ctx context.Context, name string, opts metav1.GetOptions) (*corev1.ServiceAccount, error) {
			if name == "argocd-project-default" {
				return sa, nil
			}
			return nil, apierrors.NewNotFound(schema.GroupResource{Group: "", Resource: "serviceaccounts"}, name)
		},
		CreateTokenFunc: func(ctx context.Context, serviceAccountName string, tokenRequest *authv1.TokenRequest, opts metav1.CreateOptions) (*authv1.TokenRequest, error) {
			return &authv1.TokenRequest{
				Status: authv1.TokenRequestStatus{
					Token: "test-k8s-token",
				},
			}, nil
		},
	}

	resolver := &Resolver{serviceAccounts: mock}

	config := &ProviderConfig{
		Provider: "unsupported",
	}

	_, err := resolver.ResolveCredentials(context.Background(), "default", "https://example.com", config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported workload identity provider: unsupported")
}

func TestResolveCredentials_WithMock_TokenRequestFails(t *testing.T) {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "argocd-project-default",
			Namespace: "argocd",
		},
	}

	mock := &mocks.ServiceAccountInterface{
		GetFunc: func(ctx context.Context, name string, opts metav1.GetOptions) (*corev1.ServiceAccount, error) {
			return sa, nil
		},
		CreateTokenFunc: func(ctx context.Context, serviceAccountName string, tokenRequest *authv1.TokenRequest, opts metav1.CreateOptions) (*authv1.TokenRequest, error) {
			return nil, errors.New("token request denied")
		},
	}

	resolver := &Resolver{serviceAccounts: mock}

	config := &ProviderConfig{
		Provider: "aws",
	}

	_, err := resolver.ResolveCredentials(context.Background(), "default", "https://example.com", config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to request k8s token")
	assert.Contains(t, err.Error(), "token request denied")
}

func TestResolveCredentials_WithMock_AWSMissingRoleAnnotation(t *testing.T) {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "argocd-project-default",
			Namespace: "argocd",
			// Missing eks.amazonaws.com/role-arn annotation
		},
	}

	mock := &mocks.ServiceAccountInterface{
		GetFunc: func(ctx context.Context, name string, opts metav1.GetOptions) (*corev1.ServiceAccount, error) {
			return sa, nil
		},
		CreateTokenFunc: func(ctx context.Context, serviceAccountName string, tokenRequest *authv1.TokenRequest, opts metav1.CreateOptions) (*authv1.TokenRequest, error) {
			return &authv1.TokenRequest{
				Status: authv1.TokenRequestStatus{
					Token: "test-k8s-token",
				},
			}, nil
		},
	}

	resolver := &Resolver{serviceAccounts: mock}

	config := &ProviderConfig{
		Provider: "aws",
	}

	_, err := resolver.ResolveCredentials(context.Background(), "default", "oci://123456789012.dkr.ecr.us-west-2.amazonaws.com/repo", config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing")
	assert.Contains(t, err.Error(), AnnotationAWSRoleARN)
}

func TestResolveCredentials_WithMock_GlobalServiceAccount(t *testing.T) {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "argocd-global",
			Namespace: "argocd",
		},
	}

	var capturedSAName string
	mock := &mocks.ServiceAccountInterface{
		GetFunc: func(ctx context.Context, name string, opts metav1.GetOptions) (*corev1.ServiceAccount, error) {
			capturedSAName = name
			if name == "argocd-global" {
				return sa, nil
			}
			return nil, apierrors.NewNotFound(schema.GroupResource{Group: "", Resource: "serviceaccounts"}, name)
		},
		CreateTokenFunc: func(ctx context.Context, serviceAccountName string, tokenRequest *authv1.TokenRequest, opts metav1.CreateOptions) (*authv1.TokenRequest, error) {
			return &authv1.TokenRequest{
				Status: authv1.TokenRequestStatus{
					Token: "test-k8s-token",
				},
			}, nil
		},
	}

	resolver := &Resolver{serviceAccounts: mock}

	config := &ProviderConfig{
		Provider: "unsupported", // Will fail, but we can verify the SA name
	}

	_, _ = resolver.ResolveCredentials(context.Background(), "", "https://example.com", config)
	assert.Equal(t, "argocd-global", capturedSAName)
}

func TestResolveCredentials_WithMock_TokenAudience(t *testing.T) {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "argocd-project-default",
			Namespace: "argocd",
		},
	}

	var capturedAudiences []string
	mock := &mocks.ServiceAccountInterface{
		GetFunc: func(ctx context.Context, name string, opts metav1.GetOptions) (*corev1.ServiceAccount, error) {
			return sa, nil
		},
		CreateTokenFunc: func(ctx context.Context, serviceAccountName string, tokenRequest *authv1.TokenRequest, opts metav1.CreateOptions) (*authv1.TokenRequest, error) {
			capturedAudiences = tokenRequest.Spec.Audiences
			return &authv1.TokenRequest{
				Status: authv1.TokenRequestStatus{
					Token: "test-k8s-token",
				},
			}, nil
		},
	}

	resolver := &Resolver{serviceAccounts: mock}

	config := &ProviderConfig{
		Provider: "aws",
		Audience: "custom-audience",
	}

	_, _ = resolver.ResolveCredentials(context.Background(), "default", "https://example.com", config)
	require.Len(t, capturedAudiences, 1)
	assert.Equal(t, "custom-audience", capturedAudiences[0])
}

func TestProviderConfig_Fields(t *testing.T) {
	config := &ProviderConfig{
		Provider:         "oidc",
		TokenURL:         "https://token.example.com",
		Audience:         "my-audience",
		RegistryAuthURL:  "https://registry.example.com/auth",
		RegistryService:  "my-registry",
		RegistryUsername: "robot+user",
		Insecure:         true,
	}

	assert.Equal(t, "oidc", config.Provider)
	assert.Equal(t, "https://token.example.com", config.TokenURL)
	assert.Equal(t, "my-audience", config.Audience)
	assert.Equal(t, "https://registry.example.com/auth", config.RegistryAuthURL)
	assert.Equal(t, "my-registry", config.RegistryService)
	assert.Equal(t, "robot+user", config.RegistryUsername)
	assert.True(t, config.Insecure)
}

func TestCredentials_Fields(t *testing.T) {
	creds := &Credentials{
		Username: "myuser",
		Password: "mypassword",
	}

	assert.Equal(t, "myuser", creds.Username)
	assert.Equal(t, "mypassword", creds.Password)
}

func TestConstants(t *testing.T) {
	// Verify the constant values are as expected
	assert.Equal(t, "workloadIdentityProvider", FieldProvider)
	assert.Equal(t, "workloadIdentityTokenURL", FieldTokenURL)
	assert.Equal(t, "workloadIdentityAudience", FieldAudience)
	assert.Equal(t, "workloadIdentityRegistryAuthURL", FieldRegistryAuthURL)
	assert.Equal(t, "workloadIdentityRegistryService", FieldRegistryService)
	assert.Equal(t, "workloadIdentityRegistryUsername", FieldRegistryUsername)

	assert.Equal(t, "eks.amazonaws.com/role-arn", AnnotationAWSRoleARN)
	assert.Equal(t, "iam.gke.io/gcp-service-account", AnnotationGCPSA)
	assert.Equal(t, "azure.workload.identity/client-id", AnnotationAzureClientID)
	assert.Equal(t, "azure.workload.identity/tenant-id", AnnotationAzureTenantID)
}