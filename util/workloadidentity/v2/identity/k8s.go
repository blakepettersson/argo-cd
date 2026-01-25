package identity

import (
	"context"
	"fmt"

	"github.com/argoproj/argo-cd/v3/util/workloadidentity/v2/repository"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
)

// K8sProvider passes through the K8s service account JWT directly.
// Use this when the target service can validate K8s JWTs directly via OIDC federation.
//
// If no audience is configured, defaults to "kubernetes.default.svc".
type K8sProvider struct{}

func (p *K8sProvider) DefaultRepositoryAuthenticator() repository.Authenticator {
	return repository.NewHTTPTemplateAuthenticator()
}

// NewK8sProvider creates a new K8s passthrough provider
func NewK8sProvider() *K8sProvider {
	return &K8sProvider{}
}

// GetToken requests a K8s token with the configured audience and returns it directly
func (p *K8sProvider) GetToken(ctx context.Context, sa *corev1.ServiceAccount, requestToken TokenRequester, config *Config) (*repository.Token, error) {
	audience := config.Audience
	if audience == "" {
		// Default to the Kubernetes API server audience
		audience = "kubernetes.default.svc"
	}

	log.WithFields(log.Fields{
		"serviceAccount": sa.Name,
		"audience":       audience,
	}).Info("K8s provider: requesting token for OIDC federation")

	k8sToken, err := requestToken(ctx, audience)
	if err != nil {
		return nil, fmt.Errorf("failed to request K8s token: %w", err)
	}

	return &repository.Token{
		Type:  repository.TokenTypeBearer,
		Token: k8sToken,
	}, nil
}

// Ensure K8sProvider implements Provider
var _ Provider = (*K8sProvider)(nil)
