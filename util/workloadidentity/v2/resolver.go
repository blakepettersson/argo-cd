package v2

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/argoproj/argo-cd/v3/pkg/apis/application/v1alpha1"
	"github.com/argoproj/argo-cd/v3/util/workloadidentity/v2/identity"
	"github.com/argoproj/argo-cd/v3/util/workloadidentity/v2/repository"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	v1 "k8s.io/client-go/kubernetes/typed/core/v1"
)

// Standard cloud provider annotation fields (on service accounts)
const (
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

// NewIdentityProvider creates an identity provider based on the provider name.
// This is a convenience function for callers who don't want to manage provider instantiation.
func NewIdentityProvider(repository *v1alpha1.Repository) identity.Provider {
	switch repository.WorkloadIdentityProvider {
	case "k8s":
		return identity.NewK8sProvider()
	case "aws":
		return identity.NewAWSProvider(repository)
	case "gcp":
		return identity.NewGCPProvider(repository.Repo)
	case "azure":
		return identity.NewAzureProvider(repository)
	case "spiffe":
		return identity.NewSPIFFEProvider(repository.Repo)
	default:
		return nil
	}
}

// NewAuthenticator creates a repository authenticator based on the authenticator name.
// This is a convenience function for callers who don't want to manage authenticator instantiation.
func NewAuthenticator(authenticator string) repository.Authenticator {
	switch authenticator {
	case "ecr":
		return repository.NewECRAuthenticator()
	case "passthrough":
		return repository.NewPassthroughAuthenticator()
	case "acr":
		return repository.NewACRAuthenticator()
	case "http":
		return repository.NewHTTPTemplateAuthenticator()
	case "codecommit":
		return repository.NewCodeCommitAuthenticator()
	default:
		return nil
	}
}

// ResolveCredentials resolves workload identity credentials for a repository.
//
// Parameters:
//   - idProvider: The identity provider to use for token exchange (use NewIdentityProvider to create one)
//   - repoAuth: The repository authenticator to use (use NewAuthenticator to create one)
//   - repo: The repository containing workload identity configuration
//
// The process is:
// 1. Get K8s service account token via TokenRequest API
// 2. Exchange token using the provided identity provider
// 3. Authenticate to the repository using the provided authenticator
// 4. Return username/password for repo-server to use
func (r *Resolver) ResolveCredentials(ctx context.Context, idProvider identity.Provider, repoAuth repository.Authenticator, repo *v1alpha1.Repository) (*repository.Credentials, error) {
	if idProvider == nil {
		return nil, fmt.Errorf("identity provider is required")
	}
	if repoAuth == nil {
		return nil, fmt.Errorf("repository authenticator is required")
	}
	if repo == nil {
		return nil, fmt.Errorf("repository is required")
	}

	log.WithFields(log.Fields{
		"project": repo.Project,
		"repoURL": repo.Repo,
	}).Info("resolving workload identity credentials")

	// Determine service account name from project
	saName := getServiceAccountName(repo.Project)
	log.WithField("serviceAccount", saName).Debug("using service account for workload identity")

	// Get service account (for its identity and cloud provider role annotations)
	sa, err := r.serviceAccounts.Get(ctx, saName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get service account %s: %w", saName, err)
	}
	log.WithField("serviceAccount", saName).Debug("fetched service account")

	// Create a token requester that providers can use to request K8s tokens with specific audiences
	tokenRequester := func(ctx context.Context, audience string) (string, error) {
		log.WithField("audience", audience).Debug("requesting K8s service account token")
		token, err := r.requestToken(ctx, sa, audience)
		if err != nil {
			return "", fmt.Errorf("failed to request k8s token: %w", err)
		}
		log.Debug("obtained K8s service account token")
		return token, nil
	}

	log.Info("exchanging credentials with identity provider")
	idToken, err := idProvider.GetToken(ctx, sa, tokenRequester, &identity.Config{
		Audience: repo.WorkloadIdentityAudience,
		TokenURL: repo.WorkloadIdentityTokenURL,
		Insecure: repo.Insecure,
	})
	if err != nil {
		return nil, fmt.Errorf("identity provider failed: %w", err)
	}
	log.WithField("tokenType", idToken.Type).Info("obtained identity token")

	log.WithField("repoURL", repo.Repo).Info("authenticating to repository")
	creds, err := repoAuth.Authenticate(ctx, idToken, repo.Repo, &repository.Config{
		Username:           repo.WorkloadIdentityUsername,
		Insecure:           repo.Insecure,
		AuthHost:           repo.WorkloadIdentityAuthHost,
		Method:             repo.WorkloadIdentityMethod,
		PathTemplate:       repo.WorkloadIdentityPathTemplate,
		BodyTemplate:       repo.WorkloadIdentityBodyTemplate,
		AuthType:           repo.WorkloadIdentityAuthType,
		Params:             repo.WorkloadIdentityParams,
		ResponseTokenField: repo.WorkloadIdentityResponseTokenField,
	})
	if err != nil {
		return nil, err
	}

	log.WithFields(log.Fields{
		"project": repo.Project,
		"repoURL": repo.Repo,
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
