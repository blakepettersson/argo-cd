package v2

import (
	"context"
	"fmt"

	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// requestToken requests a Kubernetes service account token via the TokenRequest API
func (r *Resolver) requestToken(ctx context.Context, sa *corev1.ServiceAccount, audience string) (string, error) {
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
