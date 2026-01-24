package v2

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/argoproj/argo-cd/v3/util/workloadidentity/v2/identity"
	"github.com/argoproj/argo-cd/v3/util/workloadidentity/v2/repository"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
)

// Repository field names for workload identity configuration
// These are stored in the Repository secret's data/stringData fields
const (
	// Standard cloud provider annotation fields (on service accounts)
	AnnotationAWSRoleARN = "eks.amazonaws.com/role-arn"
)

// Resolver resolves workload identity credentials from Kubernetes service accounts
type Resolver struct {
	serviceAccounts v1.ServiceAccountInterface
}

// NewResolver creates a new workload identity resolver
func NewResolver(clientset kubernetes.Interface, namespace string) *Resolver {
	return &Resolver{
		serviceAccounts: clientset.CoreV1().ServiceAccounts(namespace),
	}
}

// ProviderConfig holds workload identity provider configuration from the repository
type ProviderConfig struct {
	// Identity Provider configuration
	Provider string // "aws", "gcp", "azure", "spiffe", "oidc", "k8s"
	TokenURL string // Optional: override default token endpoint
	Audience string // Optional: custom audience for token

	// Repository Authenticator configuration
	RepoAuth     string // "ecr", "acr", "basic", "docker"
	RepoAuthURL  string // Optional: repository auth endpoint (for docker auth)
	RepoService  string // Optional: service name (for docker auth)
	RepoScope    string // Optional: access scope e.g. "repository:foo/bar:pull" (for docker auth)
	RepoUsername string // Optional: username for basic auth

	// Shared
	Insecure bool // Skip TLS verification

	RegistryAuthURL  string
	RegistryService  string
	RegistryUsername string
}

func (r *Resolver) resolveIdentityProvider(provider, repoURL string) identity.Provider {
	switch provider {
	case "k8s":
		return identity.NewK8sProvider()
	case "aws":
		return identity.NewAWSProvider(repoURL)
	case "spiffe":
		return identity.NewSPIFFEProvider()
	default:
		return nil
	}
}

func (r *Resolver) resolveAuthProvider(provider string) repository.Authenticator {
	switch provider {
	case "ecr":
		return repository.NewECRAuthenticator()
	// TODO: Basic should be called passthrough or similar
	case "basic":
		return repository.NewBasicAuthenticator()
	case "acr":
		return repository.NewACRAuthenticator()
	case "docker":
		return repository.NewDockerAuthenticator()
	case "http":
		return repository.NewHTTPAuthenticator()
	default:
		return nil
	}
}

func defaultRepoAuth(provider string) string {
	switch provider {
	case "aws":
		return "ecr"
	case "gcp":
		// GCR/GAR accept OAuth tokens directly with username "oauth2accesstoken"
		return "basic"
	case "azure":
		return "acr"
	case "spiffe", "oidc", "k8s":
		// Token-based identity — supports both Bearer and Basic auth
		return "http"
	default:
		return "basic"
	}
}

// ResolveCredentials resolves workload identity credentials for a repository
// It determines the service account from the project name, reads provider configuration
// from the repository, and exchanges a Kubernetes JWT for repository credentials.
//
// The process is:
// 1. Get K8s service account token via TokenRequest API
// 2. Exchange token using the provider specified in the repository config
// 3. If registry auth URL is set, do second exchange (for oidc provider)
// 4. Return username/password for repo-server to use
//
// This works for any repository type (Git, Helm, OCI) as long as the token exchange
// service returns credentials in a format the repository understands.
func (r *Resolver) ResolveCredentials(ctx context.Context, projectName, repoURL string, config *ProviderConfig) (*repository.Credentials, error) {
	if config == nil || config.Provider == "" {
		return nil, fmt.Errorf("workload identity provider not specified in repository configuration")
	}

	log.WithFields(log.Fields{
		"project":  projectName,
		"repoURL":  repoURL,
		"provider": config.Provider,
	}).Info("resolving workload identity credentials")

	// Determine service account name from project
	saName := getServiceAccountName(projectName)
	log.WithField("serviceAccount", saName).Debug("using service account for workload identity")

	// Get service account (for its identity and cloud provider role annotations)
	sa, err := r.serviceAccounts.Get(ctx, saName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get service account %s: %w", saName, err)
	}
	log.WithField("serviceAccount", saName).Debug("fetched service account")

	// Get identity provider
	idProvider := r.resolveIdentityProvider(config.Provider, repoURL)
	if idProvider == nil {
		return nil, fmt.Errorf("unknown identity provider: %s", config.Provider)
	}
	log.WithField("identityProvider", config.Provider).Debug("resolved identity provider")

	// Get K8s token if needed by the identity provider
	var k8sToken string
	if idProvider.NeedsK8sToken() {
		audience := config.Audience
		if audience == "" {
			audience = idProvider.GetAudience(sa)
		}
		log.WithField("audience", audience).Debug("requesting K8s service account token")

		k8sToken, err = r.requestToken(ctx, sa, audience)
		if err != nil {
			return nil, fmt.Errorf("failed to request k8s token: %w", err)
		}
		log.Debug("obtained K8s service account token")
	} else {
		log.Debug("identity provider does not require K8s token")
	}

	log.WithField("identityProvider", config.Provider).Info("exchanging credentials with identity provider")
	idToken, err := idProvider.GetToken(ctx, sa, k8sToken, &identity.Config{
		Audience: config.Audience,
		TokenURL: config.TokenURL,
		Insecure: config.Insecure,
	})
	if err != nil {
		return nil, fmt.Errorf("identity provider %s failed: %w", config.Provider, err)
	}
	log.WithFields(log.Fields{
		"identityProvider": config.Provider,
		"tokenType":        idToken.Type,
	}).Info("obtained identity token")

	// Determine repository authenticator
	repoAuthType := config.RepoAuth
	if repoAuthType == "" {
		repoAuthType = defaultRepoAuth(config.Provider)
	}
	log.WithField("repoAuthenticator", repoAuthType).Debug("using repository authenticator")

	authProvider := r.resolveAuthProvider(repoAuthType)
	if authProvider == nil {
		return nil, fmt.Errorf("unknown auth provider: %s", authProvider)
	}

	log.WithFields(log.Fields{
		"repoAuthenticator": repoAuthType,
		"repoURL":           repoURL,
	}).Info("authenticating to repository")
	creds, err := authProvider.Authenticate(ctx, idToken, repoURL, &repository.Config{
		AuthURL:  config.RegistryAuthURL,
		Service:  config.RegistryService,
		Scope:    config.RepoScope,
		Username: config.RegistryUsername,
		Insecure: config.Insecure,
	})
	if err != nil {
		return nil, err
	}

	log.WithFields(log.Fields{
		"project": projectName,
		"repoURL": repoURL,
	}).Info("successfully resolved workload identity credentials")
	return creds, nil
}

// getServiceAccountName returns the service account name for a given project
// If projectName is empty, it returns the global service account name
func getServiceAccountName(projectName string) string {
	if projectName == "" {
		return "argocd-global"
	}
	return fmt.Sprintf("argocd-project-%s", projectName)
}
