package v2

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"
	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// requestToken requests a Kubernetes service account token via the TokenRequest API
func (r *Resolver) requestToken(ctx context.Context, sa *corev1.ServiceAccount, config *ProviderConfig) (string, error) {
	// Get audience from config, service account annotation, or provider-specific default
	audience := getAudience(sa, config)
	log.Infof("requestToken: SA=%s/%s, audience=%q, provider=%q", sa.Namespace, sa.Name, audience, config.Provider)

	// Request token with 1 hour expiration
	duration := int64(3600)
	tokenRequest := &authv1.TokenRequest{
		Spec: authv1.TokenRequestSpec{
			Audiences:         []string{audience},
			ExpirationSeconds: &duration,
		},
	}

	resp, err := r.serviceAccounts.CreateToken(
		ctx,
		sa.Name,
		tokenRequest,
		metav1.CreateOptions{},
	)
	if err != nil {
		return "", fmt.Errorf("failed to create token for service account %s: %w", sa.Name, err)
	}

	return resp.Status.Token, nil
}

// getAudience determines the audience for the token request
// Priority: 1. Repository config, 2. Service account annotation (for GCP), 3. Provider default
func getAudience(sa *corev1.ServiceAccount, config *ProviderConfig) string {
	// First, check repository config
	if config.Audience != "" {
		return config.Audience
	}

	// For GCP, check the workload identity provider annotation on the service account
	if config.Provider == "gcp" {
		if audience := sa.Annotations[AnnotationGCPWorkloadIdentity]; audience != "" {
			return audience
		}
	}

	// Fall back to provider-specific defaults
	return getDefaultAudience(config.Provider)
}

// getDefaultAudience returns the default audience for a given provider
func getDefaultAudience(provider string) string {
	switch provider {
	case "aws":
		return "sts.amazonaws.com"
	case "azure":
		return "api://AzureADTokenExchange"
	default:
		return "argocd"
	}
}
