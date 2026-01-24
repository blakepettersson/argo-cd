package identity

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
)

// K8sProvider passes through the K8s service account JWT directly
// Use this when the registry can validate K8s JWTs directly
type K8sProvider struct{}

func (p *K8sProvider) GetAudience(sa *corev1.ServiceAccount) string {
	// For K8s tokens, the audience should be explicitly configured in the repo secret
	// Return empty to require explicit configuration
	return ""
}

func (p *K8sProvider) NeedsK8sToken() bool {
	return true
}

// NewK8sProvider creates a new K8s passthrough provider
func NewK8sProvider() *K8sProvider {
	return &K8sProvider{}
}

// Name returns the provider identifier
func (p *K8sProvider) Name() string {
	return "k8s"
}

// GetToken returns the K8s token as-is
func (p *K8sProvider) GetToken(ctx context.Context, sa *corev1.ServiceAccount, k8sToken string, config *Config) (*Token, error) {
	log.WithField("serviceAccount", sa.Name).Info("K8s provider: using K8s service account token directly (passthrough)")

	if k8sToken == "" {
		return nil, fmt.Errorf("k8s provider requires a kubernetes service account token")
	}

	log.WithField("serviceAccount", sa.Name).Debug("K8s provider: token passthrough complete")
	return &Token{
		Type:  TokenTypeBearer,
		Token: k8sToken,
	}, nil
}
