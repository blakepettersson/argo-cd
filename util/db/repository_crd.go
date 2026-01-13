package db

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/argoproj/argo-cd/v3/pkg/apis/application/v1alpha0"
	appsv1 "github.com/argoproj/argo-cd/v3/pkg/apis/application/v1alpha1"
	appclientset "github.com/argoproj/argo-cd/v3/pkg/client/clientset/versioned"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var _ repositoryBackend = &crdRepositoryBackend{}

// crdRepositoryBackend implements repositoryBackend using Repository CRDs
type crdRepositoryBackend struct {
	db         *db
	appclient  appclientset.Interface
	writeCreds bool
}

// CreateRepository creates a new Repository CRD
func (c *crdRepositoryBackend) CreateRepository(ctx context.Context, repository *appsv1.Repository) (*appsv1.Repository, error) {
	crd := c.repositoryToCRD(repository)

	created, err := c.appclient.ArgoprojV1alpha0().Repositories(c.db.ns).Create(ctx, crd, metav1.CreateOptions{})
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			return nil, status.Errorf(codes.AlreadyExists, "repository %q already exists", repository.Repo)
		}
		return nil, fmt.Errorf("failed to create repository CRD: %w", err)
	}

	return c.crdToRepository(created), nil
}

// GetRepository retrieves a Repository by URL and project
func (c *crdRepositoryBackend) GetRepository(ctx context.Context, repoURL, project string) (*appsv1.Repository, error) {
	log.Debugf("DEBUG CRD backend GetRepository: repoURL=%q, project=%q", repoURL, project)
	crd, err := c.getRepository(ctx, repoURL, project)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			log.Debugf("DEBUG CRD backend GetRepository: Not found, returning empty repo")
			// Return empty repository if not found (matches secrets backend behavior)
			return &appsv1.Repository{Repo: repoURL}, nil
		}
		return nil, err
	}

	log.Debugf("DEBUG CRD backend GetRepository: Found CRD, converting to Repository")
	return c.crdToRepository(crd), nil
}

// ListRepositories lists all Repository CRDs
func (c *crdRepositoryBackend) ListRepositories(ctx context.Context, repoType *string) ([]*appsv1.Repository, error) {
	crdList, err := c.appclient.ArgoprojV1alpha0().Repositories(c.db.ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list repository CRDs: %w", err)
	}

	var repos []*appsv1.Repository
	for i := range crdList.Items {
		repo := c.crdToRepository(&crdList.Items[i])
		if repoType == nil || *repoType == repo.Type {
			repos = append(repos, repo)
		}
	}

	return repos, nil
}

// UpdateRepository updates an existing Repository CRD
func (c *crdRepositoryBackend) UpdateRepository(ctx context.Context, repository *appsv1.Repository) (*appsv1.Repository, error) {
	// Get existing CRD
	existing, err := c.getRepository(ctx, repository.Repo, repository.Project)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return c.CreateRepository(ctx, repository)
		}
		return nil, err
	}

	// Update spec from repository
	updated := c.repositoryToCRD(repository)
	updated.ObjectMeta = existing.ObjectMeta // Preserve metadata

	result, err := c.appclient.ArgoprojV1alpha0().Repositories(c.db.ns).Update(ctx, updated, metav1.UpdateOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to update repository CRD: %w", err)
	}

	return c.crdToRepository(result), nil
}

// DeleteRepository deletes a Repository CRD
func (c *crdRepositoryBackend) DeleteRepository(ctx context.Context, repoURL, project string) error {
	crd, err := c.getRepository(ctx, repoURL, project)
	if err != nil {
		return err
	}

	err = c.appclient.ArgoprojV1alpha0().Repositories(c.db.ns).Delete(ctx, crd.Name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete repository CRD: %w", err)
	}

	return nil
}

// RepositoryExists checks if a Repository CRD exists
func (c *crdRepositoryBackend) RepositoryExists(ctx context.Context, repoURL, project string, allowFallback bool) (bool, error) {
	_, err := c.getRepository(ctx, repoURL, project)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// CreateRepoCreds creates a new RepositoryCredentials CRD
func (c *crdRepositoryBackend) CreateRepoCreds(ctx context.Context, repoCreds *appsv1.RepoCreds) (*appsv1.RepoCreds, error) {
	crd := c.repoCredsToCRD(repoCreds)

	created, err := c.appclient.ArgoprojV1alpha0().RepositoryCredentials(c.db.ns).Create(ctx, crd, metav1.CreateOptions{})
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			return nil, status.Errorf(codes.AlreadyExists, "repository credentials %q already exists", repoCreds.URL)
		}
		return nil, fmt.Errorf("failed to create repository credentials CRD: %w", err)
	}

	return c.crdToRepoCreds(created), nil
}

// GetRepoCreds retrieves RepositoryCredentials by URL
func (c *crdRepositoryBackend) GetRepoCreds(ctx context.Context, repoURL string) (*appsv1.RepoCreds, error) {
	crdList, err := c.appclient.ArgoprojV1alpha0().RepositoryCredentials(c.db.ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list repository credentials CRDs: %w", err)
	}

	// Find matching credentials by URL prefix
	for i := range crdList.Items {
		if c.urlMatches(repoURL, crdList.Items[i].Spec.URL) {
			return c.crdToRepoCreds(&crdList.Items[i]), nil
		}
	}

	return nil, status.Errorf(codes.NotFound, "repository credentials for %q not found", repoURL)
}

// ListRepoCreds lists all RepositoryCredentials URLs
func (c *crdRepositoryBackend) ListRepoCreds(ctx context.Context) ([]string, error) {
	crdList, err := c.appclient.ArgoprojV1alpha0().RepositoryCredentials(c.db.ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list repository credentials CRDs: %w", err)
	}

	urls := make([]string, len(crdList.Items))
	for i := range crdList.Items {
		urls[i] = crdList.Items[i].Spec.URL
	}

	return urls, nil
}

// UpdateRepoCreds updates existing RepositoryCredentials
func (c *crdRepositoryBackend) UpdateRepoCreds(ctx context.Context, repoCreds *appsv1.RepoCreds) (*appsv1.RepoCreds, error) {
	// Find existing CRD by URL
	existing, err := c.getRepoCredsCRD(ctx, repoCreds.URL)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return c.CreateRepoCreds(ctx, repoCreds)
		}
		return nil, err
	}

	updated := c.repoCredsToCRD(repoCreds)
	updated.ObjectMeta = existing.ObjectMeta

	result, err := c.appclient.ArgoprojV1alpha0().RepositoryCredentials(c.db.ns).Update(ctx, updated, metav1.UpdateOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to update repository credentials CRD: %w", err)
	}

	return c.crdToRepoCreds(result), nil
}

// DeleteRepoCreds deletes RepositoryCredentials by name
func (c *crdRepositoryBackend) DeleteRepoCreds(ctx context.Context, name string) error {
	err := c.appclient.ArgoprojV1alpha0().RepositoryCredentials(c.db.ns).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to delete repository credentials CRD: %w", err)
	}
	return nil
}

// RepoCredsExists checks if RepositoryCredentials exist for a URL
func (c *crdRepositoryBackend) RepoCredsExists(ctx context.Context, repoURL string) (bool, error) {
	_, err := c.GetRepoCreds(ctx, repoURL)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// GetAllHelmRepoCreds returns all Helm repository credentials
func (c *crdRepositoryBackend) GetAllHelmRepoCreds(ctx context.Context) ([]*appsv1.RepoCreds, error) {
	crdList, err := c.appclient.ArgoprojV1alpha0().RepositoryCredentials(c.db.ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list repository credentials CRDs: %w", err)
	}

	var creds []*appsv1.RepoCreds
	for i := range crdList.Items {
		if crdList.Items[i].Spec.Type == "helm" || crdList.Items[i].Spec.Type == "" {
			creds = append(creds, c.crdToRepoCreds(&crdList.Items[i]))
		}
	}

	return creds, nil
}

// GetAllOCIRepoCreds returns all OCI repository credentials
func (c *crdRepositoryBackend) GetAllOCIRepoCreds(ctx context.Context) ([]*appsv1.RepoCreds, error) {
	crdList, err := c.appclient.ArgoprojV1alpha0().RepositoryCredentials(c.db.ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list repository credentials CRDs: %w", err)
	}

	var creds []*appsv1.RepoCreds
	for i := range crdList.Items {
		if crdList.Items[i].Spec.Type == "oci" {
			creds = append(creds, c.crdToRepoCreds(&crdList.Items[i]))
		}
	}

	return creds, nil
}

// Helper functions

func (c *crdRepositoryBackend) getRepository(ctx context.Context, repoURL, project string) (*v1alpha0.Repository, error) {
	log.Debugf("DEBUG CRD getRepository: Looking for repoURL=%q, project=%q", repoURL, project)

	crdList, err := c.appclient.ArgoprojV1alpha0().Repositories(c.db.ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list repository CRDs: %w", err)
	}

	log.Debugf("DEBUG CRD getRepository: Found %d Repository CRDs", len(crdList.Items))

	// First pass: look for exact match (URL + project both match)
	if project != "" {
		for i := range crdList.Items {
			if crdList.Items[i].Spec.URL == repoURL && crdList.Items[i].Spec.Project == project {
				log.Debugf("DEBUG CRD getRepository: EXACT MATCH FOUND for %q with project=%q", repoURL, project)
				return &crdList.Items[i], nil
			}
		}
	}

	// Second pass: look for wildcard match (URL matches, CRD has empty project)
	for i := range crdList.Items {
		log.Debugf("DEBUG CRD getRepository: [Pass 2] Checking CRD[%d]: URL=%q, Project=%q", i, crdList.Items[i].Spec.URL, crdList.Items[i].Spec.Project)
		if crdList.Items[i].Spec.URL == repoURL && crdList.Items[i].Spec.Project == "" {
			log.Debugf("DEBUG CRD getRepository: WILDCARD MATCH FOUND for %q (CRD has empty project)", repoURL)
			return &crdList.Items[i], nil
		}
	}

	return nil, status.Errorf(codes.NotFound, "repository %q not found", repoURL)
}

func (c *crdRepositoryBackend) getRepoCredsCRD(ctx context.Context, url string) (*v1alpha0.RepositoryCredential, error) {
	crdList, err := c.appclient.ArgoprojV1alpha0().RepositoryCredentials(c.db.ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list repository credentials CRDs: %w", err)
	}

	for i := range crdList.Items {
		if crdList.Items[i].Spec.URL == url {
			return &crdList.Items[i], nil
		}
	}

	return nil, status.Errorf(codes.NotFound, "repository credentials for %q not found", url)
}

// urlMatches checks if a repository URL matches a credential URL pattern
func (c *crdRepositoryBackend) urlMatches(repoURL, credsURL string) bool {
	// Simple prefix matching for now
	// TODO: Implement more sophisticated matching logic
	return len(credsURL) > 0 && len(repoURL) >= len(credsURL) && repoURL[:len(credsURL)] == credsURL
}

// Conversion functions: CRD <-> Internal Repository

func (c *crdRepositoryBackend) repositoryToCRD(repo *appsv1.Repository) *v1alpha0.Repository {
	crd := &v1alpha0.Repository{
		ObjectMeta: metav1.ObjectMeta{
			Name: c.repoURLToName(repo.Repo, repo.Project),
		},
		Spec: v1alpha0.RepositorySpec{
			URL:                repo.Repo,
			Type:               repo.Type,
			Project:            repo.Project,
			Insecure:           repo.Insecure,
			Proxy:              repo.Proxy,
			NoProxy:            repo.NoProxy,
			ForceHttpBasicAuth: repo.ForceHttpBasicAuth,
		},
	}

	// Set default type if not specified
	if crd.Spec.Type == "" {
		crd.Spec.Type = "git"
	}

	// Map type-specific fields based on repository type
	switch crd.Spec.Type {
	case "git":
		crd.Spec.Git = &v1alpha0.GitRepositoryConfig{
			EnableLFS: repo.EnableLFS,
			Depth:     repo.Depth,
		}
	case "helm":
		crd.Spec.Helm = &v1alpha0.HelmRepositoryConfig{
			Name:      repo.Name,
			EnableOCI: repo.EnableOCI,
		}
	case "oci":
		crd.Spec.OCI = &v1alpha0.OCIRepositoryConfig{
			InsecureSkipTLS: repo.InsecureOCIForceHttp,
		}
	}

	// Handle credentials - they should be in a separate Secret
	// For now, we'll create a secret reference if the repository has credentials
	if repo.HasCredentials() {
		secretName := c.repoURLToName(repo.Repo, repo.Project) + "-creds"
		crd.Spec.SecretRef = &v1alpha0.SecretReference{
			Name: secretName,
		}
		// Note: The actual Secret creation/update should be handled separately
	}

	return crd
}

func (c *crdRepositoryBackend) crdToRepository(crd *v1alpha0.Repository) *appsv1.Repository {
	repo := &appsv1.Repository{
		Repo:               crd.Spec.URL,
		Type:               crd.Spec.Type,
		Project:            crd.Spec.Project,
		Insecure:           crd.Spec.Insecure,
		Proxy:              crd.Spec.Proxy,
		NoProxy:            crd.Spec.NoProxy,
		ForceHttpBasicAuth: crd.Spec.ForceHttpBasicAuth,
	}

	// Map type-specific fields from CRD nested structure to flat internal structure
	if crd.Spec.Git != nil {
		repo.EnableLFS = crd.Spec.Git.EnableLFS
		repo.Depth = crd.Spec.Git.Depth
	}

	if crd.Spec.Helm != nil {
		repo.Name = crd.Spec.Helm.Name
		repo.EnableOCI = crd.Spec.Helm.EnableOCI
	}

	if crd.Spec.OCI != nil {
		repo.InsecureOCIForceHttp = crd.Spec.OCI.InsecureSkipTLS
	}

	// Map status if present
	if crd.Status.ConnectionState != nil {
		repo.ConnectionState = appsv1.ConnectionState{
			Status:  string(crd.Status.ConnectionState.Status),
			Message: crd.Status.ConnectionState.Message,
		}
		if crd.Status.ConnectionState.AttemptedAt != nil {
			repo.ConnectionState.ModifiedAt = crd.Status.ConnectionState.AttemptedAt
		}
	}

	// Load credentials from referenced Secret
	if crd.Spec.SecretRef != nil && crd.Spec.SecretRef.Name != "" {
		if err := c.loadCredentialsFromSecret(crd, repo); err != nil {
			// Log error but don't fail - return repository without credentials
			// This matches the behavior when credentials are missing
			fmt.Printf("Warning: failed to load credentials for repository %q: %v\n", crd.Spec.URL, err)
		}
	}

	return repo
}

func (c *crdRepositoryBackend) repoCredsToCRD(creds *appsv1.RepoCreds) *v1alpha0.RepositoryCredential {
	crd := &v1alpha0.RepositoryCredential{
		ObjectMeta: metav1.ObjectMeta{
			Name: c.repoURLToName(creds.URL, ""),
		},
		Spec: v1alpha0.RepositoryCredentialSpec{
			URL:  creds.URL,
			Type: creds.Type,
			// SecretRef will be set separately
		},
	}

	// Create secret reference for credentials
	if c.hasRepoCreds(creds) {
		secretName := c.repoURLToName(creds.URL, "") + "-creds"
		crd.Spec.SecretRef = &v1alpha0.SecretReference{
			Name: secretName,
		}
	}

	return crd
}

func (c *crdRepositoryBackend) crdToRepoCreds(crd *v1alpha0.RepositoryCredential) *appsv1.RepoCreds {
	creds := &appsv1.RepoCreds{
		URL:  crd.Spec.URL,
		Type: crd.Spec.Type,
	}

	// Note: Actual credentials will be loaded from the referenced Secret separately

	return creds
}

// repoURLToName converts a repository URL to a valid Kubernetes resource name
func (c *crdRepositoryBackend) repoURLToName(url, project string) string {
	// Use the same logic as secrets backend
	prefix := "repo"
	if c.writeCreds {
		prefix = "repo-write"
	}
	return RepoURLToSecretName(prefix, url, project)
}

// hasRepoCreds checks if RepoCreds has any credential fields set
func (c *crdRepositoryBackend) hasRepoCreds(creds *appsv1.RepoCreds) bool {
	return creds.Username != "" || creds.Password != "" || creds.SSHPrivateKey != "" ||
		creds.TLSClientCertData != "" || creds.GithubAppPrivateKey != "" ||
		creds.BearerToken != "" || creds.GCPServiceAccountKey != ""
}

// loadCredentialsFromSecret loads repository credentials from a Kubernetes Secret
func (c *crdRepositoryBackend) loadCredentialsFromSecret(crd *v1alpha0.Repository, repo *appsv1.Repository) error {
	secretName := crd.Spec.SecretRef.Name
	secretNamespace := crd.Namespace

	secret, err := c.db.kubeclientset.CoreV1().Secrets(secretNamespace).Get(context.Background(), secretName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get secret %s/%s: %w", secretNamespace, secretName, err)
	}

	// Load basic auth credentials
	if username, ok := secret.Data["username"]; ok {
		repo.Username = string(username)
	}
	if password, ok := secret.Data["password"]; ok {
		repo.Password = string(password)
	}

	// Load SSH private key
	if sshPrivateKey, ok := secret.Data["sshPrivateKey"]; ok {
		repo.SSHPrivateKey = string(sshPrivateKey)
	}

	// Load TLS client certificate
	if tlsClientCertData, ok := secret.Data["tlsClientCertData"]; ok {
		repo.TLSClientCertData = string(tlsClientCertData)
	}
	if tlsClientCertKey, ok := secret.Data["tlsClientCertKey"]; ok {
		repo.TLSClientCertKey = string(tlsClientCertKey)
	}

	// Load GitHub App credentials
	if githubAppPrivateKey, ok := secret.Data["githubAppPrivateKey"]; ok {
		repo.GithubAppPrivateKey = string(githubAppPrivateKey)
	}
	if githubAppID, ok := secret.Data["githubAppID"]; ok {
		if id, err := parseInt64(string(githubAppID)); err == nil {
			repo.GithubAppId = id
		}
	}
	if githubAppInstallationID, ok := secret.Data["githubAppInstallationID"]; ok {
		if id, err := parseInt64(string(githubAppInstallationID)); err == nil {
			repo.GithubAppInstallationId = id
		}
	}
	if githubAppEnterpriseBaseURL, ok := secret.Data["githubAppEnterpriseBaseURL"]; ok {
		repo.GitHubAppEnterpriseBaseURL = string(githubAppEnterpriseBaseURL)
	}

	// Load Google Cloud Source credentials
	if gcpServiceAccountKey, ok := secret.Data["gcpServiceAccountKey"]; ok {
		repo.GCPServiceAccountKey = string(gcpServiceAccountKey)
	}

	// Load bearer token
	if bearerToken, ok := secret.Data["bearerToken"]; ok {
		repo.BearerToken = string(bearerToken)
	}

	return nil
}

// parseInt64 parses a string to int64, returns 0 and error on failure
func parseInt64(s string) (int64, error) {
	var result int64
	_, err := fmt.Sscanf(s, "%d", &result)
	return result, err
}

// createCredentialsSecret creates or updates a Secret containing repository credentials
func (c *crdRepositoryBackend) createCredentialsSecret(ctx context.Context, repo *appsv1.Repository, secretName string) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: c.db.ns,
		},
		StringData: make(map[string]string),
	}

	// Populate secret data with credentials
	if repo.Username != "" {
		secret.StringData["username"] = repo.Username
	}
	if repo.Password != "" {
		secret.StringData["password"] = repo.Password
	}
	if repo.SSHPrivateKey != "" {
		secret.StringData["sshPrivateKey"] = repo.SSHPrivateKey
	}
	if repo.TLSClientCertData != "" {
		secret.StringData["tlsClientCertData"] = repo.TLSClientCertData
	}
	if repo.TLSClientCertKey != "" {
		secret.StringData["tlsClientCertKey"] = repo.TLSClientCertKey
	}
	if repo.GithubAppPrivateKey != "" {
		secret.StringData["githubAppPrivateKey"] = repo.GithubAppPrivateKey
	}
	if repo.BearerToken != "" {
		secret.StringData["bearerToken"] = repo.BearerToken
	}
	if repo.GCPServiceAccountKey != "" {
		secret.StringData["gcpServiceAccountKey"] = repo.GCPServiceAccountKey
	}

	// Try to create, update if already exists
	_, err := c.db.kubeclientset.CoreV1().Secrets(c.db.ns).Create(ctx, secret, metav1.CreateOptions{})
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			_, err = c.db.kubeclientset.CoreV1().Secrets(c.db.ns).Update(ctx, secret, metav1.UpdateOptions{})
		}
		return err
	}

	return nil
}
