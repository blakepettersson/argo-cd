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

	"github.com/argoproj/argo-cd/v3/pkg/apis/application/v1alpha1"
	"github.com/argoproj/argo-cd/v3/util/workloadidentity/v2/identity"
	"github.com/argoproj/argo-cd/v3/util/workloadidentity/v2/mocks"
	"github.com/argoproj/argo-cd/v3/util/workloadidentity/v2/repository"
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
			result := getServiceAccountName(tt.projectName)
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

func TestNewIdentityProvider(t *testing.T) {
	tests := []struct {
		name    string
		repo    *v1alpha1.Repository
		wantNil bool
	}{
		{name: "k8s provider", repo: &v1alpha1.Repository{Repo: "", WorkloadIdentityProvider: "k8s"}, wantNil: false},
		{name: "aws provider", repo: &v1alpha1.Repository{Repo: "oci://123456789012.dkr.ecr.us-west-2.amazonaws.com/repo", WorkloadIdentityProvider: "aws"}, wantNil: false},
		{name: "gcp provider", repo: &v1alpha1.Repository{Repo: "oci://us-docker.pkg.dev/project/repo", WorkloadIdentityProvider: "gcp"}, wantNil: false},
		{name: "azure provider", repo: &v1alpha1.Repository{Repo: "oci://myregistry.azurecr.io/repo", WorkloadIdentityProvider: "azure"}, wantNil: false},
		{name: "spiffe provider", repo: &v1alpha1.Repository{Repo: "", WorkloadIdentityProvider: "spiffe"}, wantNil: false},
		{name: "unknown provider", repo: &v1alpha1.Repository{WorkloadIdentityProvider: "unknown"}, wantNil: true},
		{name: "empty provider", repo: &v1alpha1.Repository{}, wantNil: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewIdentityProvider(tt.repo)
			if tt.wantNil {
				assert.Nil(t, provider)
			} else {
				assert.NotNil(t, provider)
			}
		})
	}
}

func TestNewAuthenticator(t *testing.T) {
	tests := []struct {
		name          string
		authenticator string
		wantNil       bool
	}{
		{name: "ecr authenticator", authenticator: "ecr", wantNil: false},
		{name: "passthrough authenticator", authenticator: "passthrough", wantNil: false},
		{name: "acr authenticator", authenticator: "acr", wantNil: false},
		{name: "http authenticator", authenticator: "http", wantNil: false},
		{name: "codecommit authenticator", authenticator: "codecommit", wantNil: false},
		{name: "unknown authenticator", authenticator: "unknown", wantNil: true},
		{name: "empty authenticator", authenticator: "", wantNil: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := NewAuthenticator(tt.authenticator)
			if tt.wantNil {
				assert.Nil(t, auth)
			} else {
				assert.NotNil(t, auth)
			}
		})
	}
}

func TestResolveCredentials_NilProvider(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	resolver := NewResolver(clientset, "argocd")

	repo := &v1alpha1.Repository{
		Repo:                     "https://example.com",
		Project:                  "default",
		WorkloadIdentityProvider: "aws",
	}
	repoAuth := repository.NewECRAuthenticator()
	_, err := resolver.ResolveCredentials(context.Background(), nil, repoAuth, repo)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "identity provider is required")
}

func TestResolveCredentials_NilAuthenticator(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	resolver := NewResolver(clientset, "argocd")

	provider := identity.NewK8sProvider()
	repo := &v1alpha1.Repository{
		Repo:                     "https://example.com",
		Project:                  "default",
		WorkloadIdentityProvider: "k8s",
	}
	_, err := resolver.ResolveCredentials(context.Background(), provider, nil, repo)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "repository authenticator is required")
}

func TestResolveCredentials_NilRepo(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	resolver := NewResolver(clientset, "argocd")

	provider := identity.NewK8sProvider()
	repoAuth := repository.NewHTTPTemplateAuthenticator()
	_, err := resolver.ResolveCredentials(context.Background(), provider, repoAuth, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "repository is required")
}

func TestResolveCredentials_ServiceAccountNotFound(t *testing.T) {
	clientset := fake.NewSimpleClientset()
	resolver := NewResolver(clientset, "argocd")

	provider := identity.NewAWSProvider("oci://123456789012.dkr.ecr.us-west-2.amazonaws.com/repo")
	repoAuth := repository.NewECRAuthenticator()
	repo := &v1alpha1.Repository{
		Repo:                     "oci://123456789012.dkr.ecr.us-west-2.amazonaws.com/repo",
		Project:                  "nonexistent",
		WorkloadIdentityProvider: "aws",
	}

	_, err := resolver.ResolveCredentials(context.Background(), provider, repoAuth, repo)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get service account")
}

func TestResolveCredentials_WithMock_TokenRequestFails(t *testing.T) {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "argocd-project-default",
			Namespace: "argocd",
			Annotations: map[string]string{
				AnnotationAWSRoleARN: "arn:aws:iam::123456789012:role/test-role",
			},
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

	provider := identity.NewAWSProvider("https://example.com")
	repoAuth := repository.NewECRAuthenticator()
	repo := &v1alpha1.Repository{
		Repo:                     "https://example.com",
		Project:                  "default",
		WorkloadIdentityProvider: "aws",
	}

	_, err := resolver.ResolveCredentials(context.Background(), provider, repoAuth, repo)
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

	provider := identity.NewAWSProvider("oci://123456789012.dkr.ecr.us-west-2.amazonaws.com/repo")
	repoAuth := repository.NewECRAuthenticator()
	repo := &v1alpha1.Repository{
		Repo:                     "oci://123456789012.dkr.ecr.us-west-2.amazonaws.com/repo",
		Project:                  "default",
		WorkloadIdentityProvider: "aws",
	}

	_, err := resolver.ResolveCredentials(context.Background(), provider, repoAuth, repo)
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

	// Use a provider that will fail (missing annotation) but we can still verify SA name lookup
	provider := identity.NewAWSProvider("https://example.com")
	repoAuth := repository.NewECRAuthenticator()
	repo := &v1alpha1.Repository{
		Repo:                     "https://example.com",
		Project:                  "", // Empty project should use global SA
		WorkloadIdentityProvider: "aws",
	}

	_, _ = resolver.ResolveCredentials(context.Background(), provider, repoAuth, repo)
	assert.Equal(t, "argocd-global", capturedSAName)
}

func TestResolveCredentials_WithMock_TokenAudience(t *testing.T) {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "argocd-project-default",
			Namespace: "argocd",
			Annotations: map[string]string{
				AnnotationAWSRoleARN: "arn:aws:iam::123456789012:role/test-role",
			},
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

	provider := identity.NewAWSProvider("https://example.com")
	repoAuth := repository.NewECRAuthenticator()
	repo := &v1alpha1.Repository{
		Repo:                     "https://example.com",
		Project:                  "default",
		WorkloadIdentityProvider: "aws",
		WorkloadIdentityAudience: "custom-audience",
	}

	_, _ = resolver.ResolveCredentials(context.Background(), provider, repoAuth, repo)
	require.Len(t, capturedAudiences, 1)
	assert.Equal(t, "custom-audience", capturedAudiences[0])
}
