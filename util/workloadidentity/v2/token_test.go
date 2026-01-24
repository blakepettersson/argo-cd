package v2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestGetDefaultAudience(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		expected string
	}{
		{
			name:     "AWS provider",
			provider: "aws",
			expected: "sts.amazonaws.com",
		},
		{
			name:     "Azure provider",
			provider: "azure",
			expected: "api://AzureADTokenExchange",
		},
		{
			name:     "GCP provider defaults to argocd",
			provider: "gcp",
			expected: "argocd",
		},
		{
			name:     "OIDC provider defaults to argocd",
			provider: "oidc",
			expected: "argocd",
		},
		{
			name:     "SPIFFE provider defaults to argocd",
			provider: "spiffe",
			expected: "argocd",
		},
		{
			name:     "unknown provider defaults to argocd",
			provider: "unknown",
			expected: "argocd",
		},
		{
			name:     "empty provider defaults to argocd",
			provider: "",
			expected: "argocd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getDefaultAudience(tt.provider)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetAudience_ConfigOverride(t *testing.T) {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-sa",
			Namespace: "argocd",
			Annotations: map[string]string{
				AnnotationGCPWorkloadIdentity: "annotation-audience",
			},
		},
	}

	config := &ProviderConfig{
		Provider: "gcp",
		Audience: "config-audience",
	}

	result := getAudience(sa, config)
	assert.Equal(t, "config-audience", result)
}

func TestGetAudience_GCPAnnotation(t *testing.T) {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-sa",
			Namespace: "argocd",
			Annotations: map[string]string{
				AnnotationGCPWorkloadIdentity: "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider",
			},
		},
	}

	config := &ProviderConfig{
		Provider: "gcp",
		// No Audience in config
	}

	result := getAudience(sa, config)
	assert.Equal(t, "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider", result)
}

func TestGetAudience_GCPAnnotationIgnoredForOtherProviders(t *testing.T) {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-sa",
			Namespace: "argocd",
			Annotations: map[string]string{
				AnnotationGCPWorkloadIdentity: "gcp-annotation-audience",
			},
		},
	}

	// For AWS provider, the GCP annotation should be ignored
	config := &ProviderConfig{
		Provider: "aws",
		// No Audience in config
	}

	result := getAudience(sa, config)
	// Should return AWS default, not the GCP annotation
	assert.Equal(t, "sts.amazonaws.com", result)
}

func TestGetAudience_FallbackToDefault(t *testing.T) {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-sa",
			Namespace: "argocd",
			// No annotations
		},
	}

	tests := []struct {
		name     string
		provider string
		expected string
	}{
		{
			name:     "AWS falls back to default",
			provider: "aws",
			expected: "sts.amazonaws.com",
		},
		{
			name:     "Azure falls back to default",
			provider: "azure",
			expected: "api://AzureADTokenExchange",
		},
		{
			name:     "GCP falls back to default",
			provider: "gcp",
			expected: "argocd",
		},
		{
			name:     "OIDC falls back to default",
			provider: "oidc",
			expected: "argocd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &ProviderConfig{
				Provider: tt.provider,
			}
			result := getAudience(sa, config)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetAudience_EmptyAnnotation(t *testing.T) {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-sa",
			Namespace: "argocd",
			Annotations: map[string]string{
				AnnotationGCPWorkloadIdentity: "", // Empty annotation
			},
		},
	}

	config := &ProviderConfig{
		Provider: "gcp",
	}

	result := getAudience(sa, config)
	// Empty annotation should fall back to default
	assert.Equal(t, "argocd", result)
}

func TestGetAudience_NilAnnotations(t *testing.T) {
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-sa",
			Namespace: "argocd",
			// Annotations is nil
		},
	}

	config := &ProviderConfig{
		Provider: "gcp",
	}

	result := getAudience(sa, config)
	assert.Equal(t, "argocd", result)
}

func TestGetAudience_Priority(t *testing.T) {
	// Test that config.Audience has highest priority
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-sa",
			Namespace: "argocd",
			Annotations: map[string]string{
				AnnotationGCPWorkloadIdentity: "annotation-audience",
			},
		},
	}

	// With config audience set
	config := &ProviderConfig{
		Provider: "gcp",
		Audience: "config-audience",
	}

	result := getAudience(sa, config)
	assert.Equal(t, "config-audience", result)

	// Without config audience - falls back to annotation
	config2 := &ProviderConfig{
		Provider: "gcp",
	}

	result2 := getAudience(sa, config2)
	assert.Equal(t, "annotation-audience", result2)

	// Without config audience and without annotation - falls back to default
	sa2 := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-sa",
			Namespace: "argocd",
		},
	}

	result3 := getAudience(sa2, config2)
	assert.Equal(t, "argocd", result3)
}