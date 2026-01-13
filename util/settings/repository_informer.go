package settings

import (
	"fmt"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/tools/cache"

	"github.com/argoproj/argo-cd/v3/pkg/apis/application/v1alpha0"
	appclientset "github.com/argoproj/argo-cd/v3/pkg/client/clientset/versioned"
	repoinformers "github.com/argoproj/argo-cd/v3/pkg/client/informers/externalversions/application/v1alpha0"
)

const (
	// RepositoryCacheByURLIndexer indexes repositories by URL
	RepositoryCacheByURLIndexer = "byRepositoryURL"
)

// RepositoryInformer provides a cached view of Repository CRDs.
// It uses an informer with a URL index for efficient lookups by repository URL.
type RepositoryInformer struct {
	cache.SharedIndexInformer
}

// NewRepositoryInformer creates a new repository informer that watches Repository CRDs
// and indexes them by URL for efficient lookups.
func NewRepositoryInformer(appclientset appclientset.Interface, namespace string) (*RepositoryInformer, error) {
	informer := repoinformers.NewRepositoryInformer(appclientset, namespace, 3*time.Minute, cache.Indexers{
		cache.NamespaceIndex: cache.MetaNamespaceIndexFunc,
		RepositoryCacheByURLIndexer: func(obj any) ([]string, error) {
			repo, ok := obj.(*v1alpha0.Repository)
			if !ok {
				return nil, nil
			}
			if repo.Spec.URL != "" {
				return []string{strings.TrimRight(repo.Spec.URL, "/")}, nil
			}
			return nil, nil
		},
	})

	return &RepositoryInformer{informer}, nil
}

// GetRepositoryByURL retrieves a repository by its URL from the cache.
// Returns nil if no matching repository is found.
func (ri *RepositoryInformer) GetRepositoryByURL(url string) (*v1alpha0.Repository, error) {
	url = strings.TrimRight(url, "/")
	items, err := ri.GetIndexer().ByIndex(RepositoryCacheByURLIndexer, url)
	if err != nil {
		return nil, fmt.Errorf("failed to query repository cache by URL: %w", err)
	}

	if len(items) == 0 {
		return nil, nil // Not found, return nil without error
	}

	repo, ok := items[0].(*v1alpha0.Repository)
	if !ok {
		return nil, fmt.Errorf("expected *v1alpha0.Repository, got %T", items[0])
	}

	// Return a copy to prevent callers from modifying the cached object
	return repo.DeepCopy(), nil
}

// ListRepositories returns all repositories in the cache.
func (ri *RepositoryInformer) ListRepositories() ([]*v1alpha0.Repository, error) {
	items := ri.GetIndexer().List()
	repos := make([]*v1alpha0.Repository, 0, len(items))

	for _, item := range items {
		repo, ok := item.(*v1alpha0.Repository)
		if !ok {
			log.Warnf("Expected *v1alpha0.Repository in cache, got %T (skipping)", item)
			continue
		}
		// Return copies to prevent modification of cached objects
		repos = append(repos, repo.DeepCopy())
	}

	return repos, nil
}