package identity

import (
	"context"
	"fmt"

	"github.com/argoproj/argo-cd/v3/util/workloadidentity/v2/repository"
	log "github.com/sirupsen/logrus"
	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
)

// K8sProvider passes through the K8s service account JWT directly.
// Use this when the target service can validate K8s JWTs directly via OIDC federation.
//
// If no audience is configured, defaults to "kubernetes.default.svc".
type K8sProvider struct {
	sa              *corev1.ServiceAccount
	serviceAccounts v1.ServiceAccountInterface
}

func (p *K8sProvider) DefaultRepositoryAuthenticator() repository.Authenticator {
	return repository.NewHTTPTemplateAuthenticator()
}

// NewK8sProvider creates a new K8s passthrough provider
func NewK8sProvider(clientset kubernetes.Interface, namespace string, sa *corev1.ServiceAccount) *K8sProvider {
	serviceAccounts := clientset.CoreV1().ServiceAccounts(namespace)
	return &K8sProvider{
		serviceAccounts: serviceAccounts,
		sa:              sa,
	}
}

// GetToken requests a K8s token with the configured audience and returns it directly
func (p *K8sProvider) GetToken(ctx context.Context, audience, _ string) (*repository.Token, error) {
	saName := p.sa.Name
	if audience == "" {
		// Default to the Kubernetes API server audience
		audience = "kubernetes.default.svc"
	}

	log.WithFields(log.Fields{
		"serviceAccount": saName,
		"audience":       audience,
	}).Info("K8s provider: requesting token for OIDC federation")

	// Request token with 1 hour expiration
	duration := int64(3600)
	tokenRequest := &authv1.TokenRequest{
		Spec: authv1.TokenRequestSpec{
			Audiences:         []string{audience},
			ExpirationSeconds: &duration,
		},
	}

	resp, err := p.serviceAccounts.CreateToken(
		ctx,
		saName,
		tokenRequest,
		metav1.CreateOptions{},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create token for service account %s: %w", saName, err)
	}

	return &repository.Token{
		Type:  repository.TokenTypeBearer,
		Token: resp.Status.Token,
	}, nil
}

// Ensure K8sProvider implements Provider
var _ Provider = (*K8sProvider)(nil)
