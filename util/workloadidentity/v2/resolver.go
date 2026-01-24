package v2

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Repository field names for workload identity configuration
// These are stored in the Repository secret's data/stringData fields
const (
	FieldProvider         = "workloadIdentityProvider"         // e.g., "aws", "gcp", "azure", "spiffe", "oidc"
	FieldTokenURL         = "workloadIdentityTokenURL"         // Optional: override default token endpoint
	FieldAudience         = "workloadIdentityAudience"         // Optional: custom audience for token
	FieldRegistryAuthURL  = "workloadIdentityRegistryAuthURL"  // Optional: registry auth endpoint for oidc provider
	FieldRegistryService  = "workloadIdentityRegistryService"  // Optional: registry service name for oidc provider
	FieldRegistryUsername = "workloadIdentityRegistryUsername" // Optional: registry username for Basic Auth (e.g., Quay robot account)

	// Standard cloud provider annotation fields (on service accounts)
	AnnotationAWSRoleARN    = "eks.amazonaws.com/role-arn"
	AnnotationGCPSA         = "iam.gke.io/gcp-service-account"
	AnnotationAzureClientID = "azure.workload.identity/client-id"
	AnnotationAzureTenantID = "azure.workload.identity/tenant-id"
)

// Credentials holds resolved username and password for repository access
type Credentials struct {
	Username string
	Password string
}

// Resolver resolves workload identity credentials from Kubernetes service accounts
type Resolver struct {
	clientset kubernetes.Interface
	namespace string
}

// NewResolver creates a new workload identity resolver
func NewResolver(clientset kubernetes.Interface, namespace string) *Resolver {
	return &Resolver{
		clientset: clientset,
		namespace: namespace,
	}
}

// ProviderConfig holds workload identity provider configuration from the repository
type ProviderConfig struct {
	Provider         string // "aws", "gcp", "azure", "spiffe", or "oidc"
	TokenURL         string // Optional: override default token endpoint
	Audience         string // Optional: custom audience for token
	RegistryAuthURL  string // Optional: registry auth endpoint (for oidc provider)
	RegistryService  string // Optional: registry service name (for oidc provider)
	RegistryUsername string // Optional: username for Basic Auth (e.g., Quay robot account "org+robot")
	Insecure         bool   // Optional: skip TLS certificate verification
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
func (r *Resolver) ResolveCredentials(ctx context.Context, projectName, repoURL string, config *ProviderConfig) (*Credentials, error) {
	if config == nil || config.Provider == "" {
		return nil, fmt.Errorf("workload identity provider not specified in repository configuration")
	}

	// Determine service account name from project
	saName := GetServiceAccountName(projectName)

	// Get service account (for its identity and cloud provider role annotations)
	sa, err := r.clientset.CoreV1().ServiceAccounts(r.namespace).Get(ctx, saName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get service account %s: %w", saName, err)
	}

	// Get K8s token via TokenRequest API
	k8sToken, err := r.requestToken(ctx, sa, config)
	if err != nil {
		return nil, fmt.Errorf("failed to request k8s token: %w", err)
	}

	// Exchange based on provider
	// Built-in providers (aws, gcp, azure, spiffe) have specific API calls they need to make
	// "oidc" uses RFC 8693 token exchange or direct K8s token
	switch config.Provider {
	case "aws":
		return r.resolveAWS(ctx, sa, k8sToken, repoURL, config)
	case "gcp":
		return r.resolveGCP(ctx, sa, k8sToken, config)
	case "azure":
		return r.resolveAzure(ctx, sa, k8sToken, repoURL, config)
	case "spiffe":
		return r.resolveSPIFFE(ctx, sa, repoURL, config)
	case "oidc":
		// RFC 8693 token exchange or direct K8s OIDC
		return r.resolveOIDC(ctx, sa, k8sToken, repoURL, config)
	default:
		return nil, fmt.Errorf("unsupported workload identity provider: %s", config.Provider)
	}
}

// GetServiceAccountName returns the service account name for a given project
// If projectName is empty, it returns the global service account name
func GetServiceAccountName(projectName string) string {
	if projectName == "" {
		return "argocd-global"
	}
	return fmt.Sprintf("argocd-project-%s", projectName)
}
