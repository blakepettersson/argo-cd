package controller

import (
	"context"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/utils/ptr"

	appv1 "github.com/argoproj/argo-cd/v3/pkg/apis/application/v1alpha1"
	v1alpha0 "github.com/argoproj/argo-cd/v3/pkg/apis/application/v1alpha0"
	appclientset "github.com/argoproj/argo-cd/v3/pkg/client/clientset/versioned"
	appinformers "github.com/argoproj/argo-cd/v3/pkg/client/informers/externalversions/application/v1alpha0"
	applisters "github.com/argoproj/argo-cd/v3/pkg/client/listers/application/v1alpha0"
	"github.com/argoproj/argo-cd/v3/reposerver/apiclient"
	"github.com/argoproj/argo-cd/v3/util/argo"
)

const (
	// defaultRepoTestInterval is the default interval between repository connection tests
	defaultRepoTestInterval = 3 * time.Minute
	// defaultRepoTestTimeout is the default timeout for repository connection tests
	defaultRepoTestTimeout = 30 * time.Second
)

// RepositoryController watches Repository CRDs and updates their connection status
type RepositoryController struct {
	namespace        string
	controlplaneName string
	appClientset     appclientset.Interface
	kubeClientset    kubernetes.Interface
	repoClientset    apiclient.Clientset
	repoInformer     cache.SharedIndexInformer
	repoLister       applisters.RepositoryLister
	repoQueue        workqueue.TypedRateLimitingInterface[string]
	auditLogger      *argo.AuditLogger
	testInterval     time.Duration
	testTimeout      time.Duration
}

// NewRepositoryController creates a new instance of RepositoryController
func NewRepositoryController(
	namespace string,
	controlplaneName string,
	appClientset appclientset.Interface,
	kubeClientset kubernetes.Interface,
	repoClientset apiclient.Clientset,
	repoInformer appinformers.RepositoryInformer,
	auditLogger *argo.AuditLogger,
	testInterval time.Duration,
	testTimeout time.Duration,
) *RepositoryController {
	if testInterval == 0 {
		testInterval = defaultRepoTestInterval
	}
	if testTimeout == 0 {
		testTimeout = defaultRepoTestTimeout
	}
	if controlplaneName == "" {
		controlplaneName = "argocd-application-controller"
	}

	ctrl := &RepositoryController{
		namespace:        namespace,
		controlplaneName: controlplaneName,
		appClientset:     appClientset,
		kubeClientset:    kubeClientset,
		repoClientset:    repoClientset,
		repoInformer:     repoInformer.Informer(),
		repoLister:       repoInformer.Lister(),
		repoQueue:        workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
		auditLogger:      auditLogger,
		testInterval:     testInterval,
		testTimeout:      testTimeout,
	}

	// Set up event handlers for when Repository resources change
	_, err := ctrl.repoInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if repo, ok := obj.(*v1alpha0.Repository); ok {
				ctrl.enqueueRepository(repo)
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			if repo, ok := newObj.(*v1alpha0.Repository); ok {
				ctrl.enqueueRepository(repo)
			}
		},
		DeleteFunc: func(obj interface{}) {
			// Nothing to do on delete
		},
	})
	if err != nil {
		log.Errorf("Failed to add event handler for repository informer: %v", err)
	}

	return ctrl
}

// enqueueRepository adds a repository to the work queue
func (c *RepositoryController) enqueueRepository(repo *v1alpha0.Repository) {
	key, err := cache.MetaNamespaceKeyFunc(repo)
	if err != nil {
		runtime.HandleError(fmt.Errorf("failed to get key for repository %s: %w", repo.Name, err))
		return
	}
	c.repoQueue.AddRateLimited(key)
}

// Run starts the repository controller
func (c *RepositoryController) Run(ctx context.Context, workers int) error {
	defer runtime.HandleCrash()
	defer c.repoQueue.ShutDown()

	log.Info("Starting repository controller")

	// Note: The informer is already started by the informer factory in the caller
	// We just need to wait for the cache to sync
	log.Info("Waiting for repository controller cache to sync")
	if !cache.WaitForCacheSync(ctx.Done(), c.repoInformer.HasSynced) {
		return fmt.Errorf("timed out waiting for repository cache to sync")
	}

	log.Info("Repository controller cache synced, starting workers")

	// Start worker goroutines
	for i := 0; i < workers; i++ {
		go wait.Until(func() {
			for c.processNextWorkItem() {
			}
		}, time.Second, ctx.Done())
	}

	// Start periodic re-queue of all repositories
	go wait.Until(func() {
		c.requeueAllRepositories()
	}, c.testInterval, ctx.Done())

	log.Info("Repository controller started")
	<-ctx.Done()
	log.Info("Shutting down repository controller")

	return nil
}

// processNextWorkItem processes the next item in the work queue
func (c *RepositoryController) processNextWorkItem() bool {
	key, quit := c.repoQueue.Get()
	if quit {
		return false
	}
	defer c.repoQueue.Done(key)

	err := c.syncRepository(key)
	if err != nil {
		c.repoQueue.AddRateLimited(key)
		runtime.HandleError(fmt.Errorf("error syncing repository %q: %w", key, err))
		return true
	}

	c.repoQueue.Forget(key)
	return true
}

// syncRepository tests the repository connection and updates its status
func (c *RepositoryController) syncRepository(key string) error {
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return fmt.Errorf("invalid resource key: %s", key)
	}

	// Get the repository from the lister
	repo, err := c.repoLister.Repositories(namespace).Get(name)
	if err != nil {
		// Repository has been deleted, nothing to do
		return nil
	}

	log.Debugf("Testing connection for repository %s/%s (URL: %s)", namespace, name, repo.Spec.URL)

	// Convert CRD repository to internal repository format
	internalRepo := c.crdToInternalRepo(repo)

	// Test the repository connection
	ctx, cancel := context.WithTimeout(context.Background(), c.testTimeout)
	defer cancel()

	connectionState := c.testRepository(ctx, internalRepo)

	// Update the repository status
	return c.updateRepositoryStatus(repo, connectionState)
}

// testRepository tests the connection to a repository
func (c *RepositoryController) testRepository(ctx context.Context, repo *appv1.Repository) appv1.ConnectionState {
	conn, repoClient, err := c.repoClientset.NewRepoServerClient()
	if err != nil {
		log.Errorf("Failed to connect to repo-server: %v", err)
		return appv1.ConnectionState{
			Status:     appv1.ConnectionStatusFailed,
			Message:    fmt.Sprintf("Failed to connect to repo-server: %v", err),
			ModifiedAt: ptr.To(metav1.Now()),
		}
	}
	defer conn.Close()

	_, err = repoClient.TestRepository(ctx, &apiclient.TestRepositoryRequest{
		Repo: repo,
	})

	if err != nil {
		return appv1.ConnectionState{
			Status:     appv1.ConnectionStatusFailed,
			Message:    fmt.Sprintf("Repository connection test failed: %v", err),
			ModifiedAt: ptr.To(metav1.Now()),
		}
	}

	return appv1.ConnectionState{
		Status:     appv1.ConnectionStatusSuccessful,
		Message:    "Repository connection test successful",
		ModifiedAt: ptr.To(metav1.Now()),
	}
}

// updateRepositoryStatus updates the status of a repository CRD
func (c *RepositoryController) updateRepositoryStatus(repo *v1alpha0.Repository, connectionState appv1.ConnectionState) error {
	// Create a copy to modify
	repoCopy := repo.DeepCopy()

	// Determine the new connection status
	newStatus := v1alpha0.ConnectionStatus(connectionState.Status)
	isSuccessful := connectionState.Status == appv1.ConnectionStatusSuccessful

	// Get previous state for event detection
	var previousStatus v1alpha0.ConnectionStatus
	if repo.Status.ConnectionState != nil {
		previousStatus = repo.Status.ConnectionState.Status
	}

	// Update the aggregate connection state (single-cluster scenario for now)
	repoCopy.Status.ConnectionState = &v1alpha0.AggregateConnectionState{
		Status:             newStatus,
		Message:            connectionState.Message,
		AttemptedAt:        connectionState.ModifiedAt,
		TotalClusters:      1,
		SuccessfulClusters: 0,
		FailedClusters:     0,
	}

	if isSuccessful {
		repoCopy.Status.ConnectionState.SuccessfulClusters = 1
	} else {
		repoCopy.Status.ConnectionState.FailedClusters = 1
	}

	// Update the Ready condition
	readyCondition := c.buildReadyCondition(repoCopy, isSuccessful, connectionState.Message)
	meta.SetStatusCondition(&repoCopy.Status.Conditions, readyCondition)

	// Update the repository status
	_, err := c.appClientset.ArgoprojV1alpha0().Repositories(repoCopy.Namespace).UpdateStatus(context.Background(), repoCopy, metav1.UpdateOptions{})
	if err != nil {
		if apierrors.IsConflict(err) {
			// Conflict error - will retry via requeue
			return err
		}
		return fmt.Errorf("failed to update repository status: %w", err)
	}

	// Emit events for state transitions
	c.emitConnectionEvents(repo, previousStatus, newStatus, connectionState.Message)

	log.Debugf("Updated connection status for repository %s/%s: %s", repoCopy.Namespace, repoCopy.Name, connectionState.Status)
	return nil
}

// buildReadyCondition creates the Ready condition based on connection state
func (c *RepositoryController) buildReadyCondition(repo *v1alpha0.Repository, isSuccessful bool, message string) metav1.Condition {
	condition := metav1.Condition{
		Type:               string(v1alpha0.RepositoryConditionReady),
		ObservedGeneration: repo.Generation,
		LastTransitionTime: metav1.Now(),
	}

	if isSuccessful {
		condition.Status = metav1.ConditionTrue
		condition.Reason = v1alpha0.ReasonConnectionSuccessful
		condition.Message = message
	} else {
		condition.Status = metav1.ConditionFalse
		condition.Reason = v1alpha0.ReasonConnectionFailed
		condition.Message = message
	}

	return condition
}

// emitConnectionEvents emits Kubernetes events for connection state transitions
func (c *RepositoryController) emitConnectionEvents(repo *v1alpha0.Repository, previousStatus, newStatus v1alpha0.ConnectionStatus, message string) {
	if c.auditLogger == nil {
		return
	}

	// Detect state transitions and emit appropriate events
	switch {
	case newStatus == v1alpha0.ConnectionStatusSuccessful && previousStatus == v1alpha0.ConnectionStatusFailed:
		// Connection recovered
		c.auditLogger.LogRepoEvent(repo, argo.EventInfo{
			Type:   corev1.EventTypeNormal,
			Reason: argo.EventReasonConnectionRecovered,
		}, message)
	case newStatus == v1alpha0.ConnectionStatusSuccessful && previousStatus != v1alpha0.ConnectionStatusSuccessful:
		// Connection successful (first time or from unknown state)
		c.auditLogger.LogRepoEvent(repo, argo.EventInfo{
			Type:   corev1.EventTypeNormal,
			Reason: argo.EventReasonConnectionSuccessful,
		}, message)
	case newStatus == v1alpha0.ConnectionStatusFailed && previousStatus != v1alpha0.ConnectionStatusFailed:
		// Connection failed (transition from success or unknown)
		c.auditLogger.LogRepoEvent(repo, argo.EventInfo{
			Type:   corev1.EventTypeWarning,
			Reason: argo.EventReasonConnectionFailed,
		}, message)
	}
}

// requeueAllRepositories adds all repositories to the work queue for periodic testing
func (c *RepositoryController) requeueAllRepositories() {
	repos, err := c.repoLister.List(nil)
	if err != nil {
		log.Errorf("Failed to list repositories: %v", err)
		return
	}

	for _, repo := range repos {
		c.enqueueRepository(repo)
	}

	log.Debugf("Re-queued %d repositories for connection testing", len(repos))
}

// crdToInternalRepo converts a v1alpha0.Repository CRD to internal v1alpha1.Repository format
func (c *RepositoryController) crdToInternalRepo(crd *v1alpha0.Repository) *appv1.Repository {
	repo := &appv1.Repository{
		Repo:               crd.Spec.URL,
		Type:               crd.Spec.Type,
		Project:            crd.Spec.Project,
		Insecure:           crd.Spec.Insecure,
		Proxy:              crd.Spec.Proxy,
		NoProxy:            crd.Spec.NoProxy,
		ForceHttpBasicAuth: crd.Spec.ForceHttpBasicAuth,
	}

	// Map Git-specific fields
	if crd.Spec.Git != nil {
		repo.EnableLFS = crd.Spec.Git.EnableLFS
		repo.Depth = crd.Spec.Git.Depth
	}

	// Map Helm-specific fields
	if crd.Spec.Helm != nil {
		repo.Name = crd.Spec.Helm.Name
		repo.EnableOCI = crd.Spec.Helm.EnableOCI
	}

	// Map OCI-specific fields
	if crd.Spec.OCI != nil {
		repo.InsecureOCIForceHttp = crd.Spec.OCI.InsecureSkipTLS
	}

	// Load credentials from SecretRef if present
	if crd.Spec.SecretRef != nil {
		if err := c.loadCredentialsFromSecret(crd, repo); err != nil {
			log.Warnf("Failed to load credentials from secret for repository %s/%s: %v", crd.Namespace, crd.Name, err)
		}
	}

	return repo
}

// loadCredentialsFromSecret loads repository credentials from a Kubernetes Secret
func (c *RepositoryController) loadCredentialsFromSecret(crd *v1alpha0.Repository, repo *appv1.Repository) error {
	secretName := crd.Spec.SecretRef.Name
	secretNamespace := crd.Namespace

	secret, err := c.kubeClientset.CoreV1().Secrets(secretNamespace).Get(context.Background(), secretName, metav1.GetOptions{})
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
		repo.GithubAppId, _ = parseInt64(string(githubAppID))
	}
	if githubAppInstallationID, ok := secret.Data["githubAppInstallationID"]; ok {
		repo.GithubAppInstallationId, _ = parseInt64(string(githubAppInstallationID))
	}
	if githubAppEnterpriseBaseURL, ok := secret.Data["githubAppEnterpriseBaseURL"]; ok {
		repo.GitHubAppEnterpriseBaseURL = string(githubAppEnterpriseBaseURL)
	}

	// Load Google Cloud Source credentials
	if gcpServiceAccountKey, ok := secret.Data["gcpServiceAccountKey"]; ok {
		repo.GCPServiceAccountKey = string(gcpServiceAccountKey)
	}

	return nil
}

// parseInt64 safely parses a string to int64
func parseInt64(s string) (int64, error) {
	var result int64
	_, err := fmt.Sscanf(s, "%d", &result)
	return result, err
}