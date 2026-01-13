package db

import (
	"context"
	"fmt"
	"maps"
	"slices"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	appsv1 "github.com/argoproj/argo-cd/v3/pkg/apis/application/v1alpha1"
	appclientset "github.com/argoproj/argo-cd/v3/pkg/client/clientset/versioned"
)

var _ repositoryBackend = &hybridRepositoryBackend{}

// hybridRepositoryBackend implements repositoryBackend using both CRDs and Secrets
// It reads from CRDs first, falling back to Secrets for legacy data
// Writes go to CRDs (the new storage backend)
type hybridRepositoryBackend struct {
	crdBackend     *crdRepositoryBackend
	secretsBackend *secretsRepositoryBackend
}

// newHybridRepositoryBackend creates a new hybrid backend instance
func newHybridRepositoryBackend(db *db, appclient appclientset.Interface, writeCreds bool) *hybridRepositoryBackend {
	return &hybridRepositoryBackend{
		crdBackend: &crdRepositoryBackend{
			db:         db,
			appclient:  appclient,
			writeCreds: writeCreds,
		},
		secretsBackend: &secretsRepositoryBackend{
			db:         db,
			writeCreds: writeCreds,
		},
	}
}

// CreateRepository creates a new Repository in CRD backend
func (h *hybridRepositoryBackend) CreateRepository(ctx context.Context, r *appsv1.Repository) (*appsv1.Repository, error) {
	// Check if repository already exists in either backend
	exists, err := h.RepositoryExists(ctx, r.Repo, r.Project, false)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, status.Errorf(codes.AlreadyExists, "repository %q already exists", r.Repo)
	}

	// Create in CRD backend
	log.Debugf("Creating repository %q in CRD backend", r.Repo)
	return h.crdBackend.CreateRepository(ctx, r)
}

// GetRepository retrieves a Repository, checking CRDs first, then Secrets
func (h *hybridRepositoryBackend) GetRepository(ctx context.Context, repoURL, project string) (*appsv1.Repository, error) {
	repo, err := h.crdBackend.GetRepository(ctx, repoURL, project)
	if err == nil && repo != nil {
		log.Debugf("Found repository %q in CRD backend", repoURL)
		return repo, nil
	}
	log.Warnf("Error getting repository %q from CRD backend: %v", repoURL, err)
	return h.secretsBackend.GetRepository(ctx, repoURL, project)
}

// ListRepositories lists all Repositories from both CRDs and Secrets, deduplicating by URL
func (h *hybridRepositoryBackend) ListRepositories(ctx context.Context, repoType *string) ([]*appsv1.Repository, error) {
	// Collect repositories from both backends
	repoMap := make(map[string]*appsv1.Repository) // key: repo URL + project

	// Get from CRD backend
	crdRepos, err := h.crdBackend.ListRepositories(ctx, repoType)
	if err != nil {
		log.Warnf("Error listing repositories from CRD backend: %v", err)
	} else {
		for _, repo := range crdRepos {
			key := repo.Repo + "|" + repo.Project
			repoMap[key] = repo
			log.Debugf("Found repository %q in CRD backend", repo.Repo)
		}
	}

	// Get from secrets backend
	secretRepos, err := h.secretsBackend.ListRepositories(ctx, repoType)
	if err != nil {
		log.Warnf("Error listing repositories from secrets backend: %v", err)
	} else {
		for _, repo := range secretRepos {
			key := repo.Repo + "|" + repo.Project
			// Only add if not already found in CRD backend (CRDs take precedence)
			if _, exists := repoMap[key]; !exists {
				repoMap[key] = repo
				log.Debugf("Found repository %q in secrets backend (legacy)", repo.Repo)
			}
		}
	}

	return slices.Collect(maps.Values(repoMap)), nil
}

// UpdateRepository updates a Repository, migrating from Secrets to CRDs if needed
func (h *hybridRepositoryBackend) UpdateRepository(ctx context.Context, r *appsv1.Repository) (*appsv1.Repository, error) {
	// Check if repository exists in CRD backend
	crdExists, err := h.crdBackend.RepositoryExists(ctx, r.Repo, r.Project, false)
	if err != nil {
		return nil, fmt.Errorf("error checking CRD backend: %w", err)
	}

	if crdExists {
		// Update in CRD backend
		log.Debugf("Updating repository %q in CRD backend", r.Repo)
		return h.crdBackend.UpdateRepository(ctx, r)
	}

	// Check if repository exists in secrets backend
	secretsExists, err := h.secretsBackend.RepositoryExists(ctx, r.Repo, r.Project, false)
	if err != nil {
		return nil, fmt.Errorf("error checking secrets backend: %w", err)
	}

	if secretsExists {
		// Migrate: Create in CRD backend, then delete from secrets backend
		log.Infof("Migrating repository %q from secrets to CRD backend", r.Repo)
		created, err := h.crdBackend.CreateRepository(ctx, r)
		if err != nil {
			return nil, fmt.Errorf("error migrating repository to CRD backend: %w", err)
		}

		// Delete from secrets backend (best effort - log errors but don't fail)
		/*
			if err := h.secretsBackend.DeleteRepository(ctx, r.Repo, r.Project); err != nil {
				log.Warnf("Failed to delete repository %q from secrets backend after migration: %v", r.Repo, err)
			} else {
				log.Infof("Successfully deleted repository %q from secrets backend after migration", r.Repo)
			}
		*/

		return created, nil
	}

	// Repository not found in either backend
	return nil, status.Errorf(codes.NotFound, "repository %q not found", r.Repo)
}

// DeleteRepository deletes a Repository from both backends
func (h *hybridRepositoryBackend) DeleteRepository(ctx context.Context, repoURL, project string) error {
	var lastErr error

	// Try to delete from CRD backend
	crdExists, err := h.crdBackend.RepositoryExists(ctx, repoURL, project, false)
	if err != nil {
		log.Warnf("Error checking CRD backend for repository %q: %v", repoURL, err)
		lastErr = err
	} else if crdExists {
		if err := h.crdBackend.DeleteRepository(ctx, repoURL, project); err != nil {
			log.Warnf("Error deleting repository %q from CRD backend: %v", repoURL, err)
			lastErr = err
		} else {
			log.Debugf("Deleted repository %q from CRD backend", repoURL)
		}
	}

	// Try to delete from secrets backend
	secretsExists, err := h.secretsBackend.RepositoryExists(ctx, repoURL, project, false)
	if err != nil {
		log.Warnf("Error checking secrets backend for repository %q: %v", repoURL, err)
		if lastErr == nil {
			lastErr = err
		}
	} else if secretsExists {
		if err := h.secretsBackend.DeleteRepository(ctx, repoURL, project); err != nil {
			log.Warnf("Error deleting repository %q from secrets backend: %v", repoURL, err)
			if lastErr == nil {
				lastErr = err
			}
		} else {
			log.Debugf("Deleted repository %q from secrets backend", repoURL)
		}
	}

	// If we didn't find it in either backend and have no errors, return not found
	if !crdExists && !secretsExists && lastErr == nil {
		return status.Errorf(codes.NotFound, "repository %q not found", repoURL)
	}

	return lastErr
}

// RepositoryExists checks if a Repository exists in either backend
func (h *hybridRepositoryBackend) RepositoryExists(ctx context.Context, repoURL, project string, allowFallback bool) (bool, error) {
	crdExists, err := h.crdBackend.RepositoryExists(ctx, repoURL, project, false)
	if err != nil {
		log.Warnf("Error checking CRD backend for repository %q: %v", repoURL, err)
	} else if crdExists {
		return true, nil
	}

	return h.secretsBackend.RepositoryExists(ctx, repoURL, project, allowFallback)
}

// CreateRepoCreds creates new RepositoryCredentials in CRD backend
func (h *hybridRepositoryBackend) CreateRepoCreds(ctx context.Context, r *appsv1.RepoCreds) (*appsv1.RepoCreds, error) {
	// Check if credentials already exist in either backend
	exists, err := h.RepoCredsExists(ctx, r.URL)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, status.Errorf(codes.AlreadyExists, "repository credentials %q already exists", r.URL)
	}

	// Create in CRD backend
	log.Debugf("Creating repository credentials %q in CRD backend", r.URL)
	return h.crdBackend.CreateRepoCreds(ctx, r)
}

// GetRepoCreds retrieves RepositoryCredentials, checking CRDs first, then Secrets
func (h *hybridRepositoryBackend) GetRepoCreds(ctx context.Context, repoURL string) (*appsv1.RepoCreds, error) {
	crdCreds, err := h.crdBackend.GetRepoCreds(ctx, repoURL)
	if err == nil && crdCreds != nil {
		log.Debugf("Found repository credentials for %q in CRD backend", repoURL)
		return crdCreds, nil
	}
	if err != nil && status.Code(err) != codes.NotFound {
		log.Warnf("Error getting repository credentials from CRD backend: %v", err)
	}

	log.Debugf("Checking secrets backend for repository credentials for %q", repoURL)
	return h.secretsBackend.GetRepoCreds(ctx, repoURL)
}

// ListRepoCreds lists all RepositoryCredentials URLs from both backends
func (h *hybridRepositoryBackend) ListRepoCreds(ctx context.Context) ([]string, error) {
	urlMap := make(map[string]bool)

	// Get from CRD backend
	crdURLs, err := h.crdBackend.ListRepoCreds(ctx)
	if err != nil {
		log.Warnf("Error listing repository credentials from CRD backend: %v", err)
	} else {
		for _, url := range crdURLs {
			urlMap[url] = true
		}
	}

	// Get from secrets backend
	secretURLs, err := h.secretsBackend.ListRepoCreds(ctx)
	if err != nil {
		log.Warnf("Error listing repository credentials from secrets backend: %v", err)
	} else {
		for _, url := range secretURLs {
			urlMap[url] = true
		}
	}

	return slices.Collect(maps.Keys(urlMap)), nil
}

// UpdateRepoCreds updates RepositoryCredentials, migrating from Secrets to CRDs if needed
func (h *hybridRepositoryBackend) UpdateRepoCreds(ctx context.Context, r *appsv1.RepoCreds) (*appsv1.RepoCreds, error) {
	// Check if credentials exist in CRD backend
	crdExists, err := h.crdBackend.RepoCredsExists(ctx, r.URL)
	if err != nil {
		return nil, fmt.Errorf("error checking CRD backend: %w", err)
	}

	if crdExists {
		// Update in CRD backend
		log.Debugf("Updating repository credentials %q in CRD backend", r.URL)
		return h.crdBackend.UpdateRepoCreds(ctx, r)
	}

	// Check if credentials exist in secrets backend
	secretsExists, err := h.secretsBackend.RepoCredsExists(ctx, r.URL)
	if err != nil {
		return nil, fmt.Errorf("error checking secrets backend: %w", err)
	}

	if secretsExists {
		// Migrate: Create in CRD backend, then delete from secrets backend
		log.Infof("Migrating repository credentials %q from secrets to CRD backend", r.URL)
		created, err := h.crdBackend.CreateRepoCreds(ctx, r)
		if err != nil {
			return nil, fmt.Errorf("error migrating repository credentials to CRD backend: %w", err)
		}

		// Delete from secrets backend (best effort)
		/*
			if err := h.secretsBackend.DeleteRepoCreds(ctx, r.URL); err != nil {
				log.Warnf("Failed to delete repository credentials %q from secrets backend after migration: %v", r.URL, err)
			} else {
				log.Infof("Successfully deleted repository credentials %q from secrets backend after migration", r.URL)
			}
		*/

		return created, nil
	}

	// Credentials not found in either backend
	return nil, status.Errorf(codes.NotFound, "repository credentials %q not found", r.URL)
}

// DeleteRepoCreds deletes RepositoryCredentials from both backends
func (h *hybridRepositoryBackend) DeleteRepoCreds(ctx context.Context, name string) error {
	var lastErr error

	// Try to delete from CRD backend
	crdExists, err := h.crdBackend.RepoCredsExists(ctx, name)
	if err != nil {
		log.Warnf("Error checking CRD backend for repository credentials %q: %v", name, err)
		lastErr = err
	} else if crdExists {
		if err := h.crdBackend.DeleteRepoCreds(ctx, name); err != nil {
			log.Warnf("Error deleting repository credentials %q from CRD backend: %v", name, err)
			lastErr = err
		} else {
			log.Debugf("Deleted repository credentials %q from CRD backend", name)
		}
	}

	// Try to delete from secrets backend
	secretsExists, err := h.secretsBackend.RepoCredsExists(ctx, name)
	if err != nil {
		log.Warnf("Error checking secrets backend for repository credentials %q: %v", name, err)
		lastErr = err
	} else if secretsExists {
		if err := h.secretsBackend.DeleteRepoCreds(ctx, name); err != nil {
			log.Warnf("Error deleting repository credentials %q from secrets backend: %v", name, err)
			lastErr = err
		} else {
			log.Debugf("Deleted repository credentials %q from secrets backend", name)
		}
	}

	// If we didn't find it in either backend and have no errors, just succeed
	// (matches secrets backend behavior)
	return lastErr
}

// RepoCredsExists checks if RepositoryCredentials exist in either backend
func (h *hybridRepositoryBackend) RepoCredsExists(ctx context.Context, repoURL string) (bool, error) {
	crdExists, err := h.crdBackend.RepoCredsExists(ctx, repoURL)
	if err != nil {
		log.Warnf("Error checking CRD backend for repository credentials %q: %v", repoURL, err)
	} else if crdExists {
		return true, nil
	}

	return h.secretsBackend.RepoCredsExists(ctx, repoURL)
}

// GetAllHelmRepoCreds returns all Helm repository credentials from both backends
func (h *hybridRepositoryBackend) GetAllHelmRepoCreds(ctx context.Context) ([]*appsv1.RepoCreds, error) {
	credsMap := make(map[string]*appsv1.RepoCreds) // key: URL

	// Get from CRD backend
	crdCreds, err := h.crdBackend.GetAllHelmRepoCreds(ctx)
	if err != nil {
		log.Warnf("Error getting Helm repo credentials from CRD backend: %v", err)
	} else {
		for _, creds := range crdCreds {
			credsMap[creds.URL] = creds
		}
	}

	// Get from secrets backend
	secretCreds, err := h.secretsBackend.GetAllHelmRepoCreds(ctx)
	if err != nil {
		log.Warnf("Error getting Helm repo credentials from secrets backend: %v", err)
	} else {
		for _, creds := range secretCreds {
			// Only add if not already found in CRD backend (CRDs take precedence)
			if _, exists := credsMap[creds.URL]; !exists {
				credsMap[creds.URL] = creds
			}
		}
	}

	return slices.Collect(maps.Values(credsMap)), nil
}

// GetAllOCIRepoCreds returns all OCI repository credentials from both backends
func (h *hybridRepositoryBackend) GetAllOCIRepoCreds(ctx context.Context) ([]*appsv1.RepoCreds, error) {
	credsMap := make(map[string]*appsv1.RepoCreds) // key: URL

	// Get from CRD backend
	crdCreds, err := h.crdBackend.GetAllOCIRepoCreds(ctx)
	if err != nil {
		log.Warnf("Error getting OCI repo credentials from CRD backend: %v", err)
	} else {
		for _, creds := range crdCreds {
			credsMap[creds.URL] = creds
		}
	}

	// Get from secrets backend
	secretCreds, err := h.secretsBackend.GetAllOCIRepoCreds(ctx)
	if err != nil {
		log.Warnf("Error getting OCI repo credentials from secrets backend: %v", err)
	} else {
		for _, creds := range secretCreds {
			// Only add if not already found in CRD backend (CRDs take precedence)
			if _, exists := credsMap[creds.URL]; !exists {
				credsMap[creds.URL] = creds
			}
		}
	}

	return slices.Collect(maps.Values(credsMap)), nil
}
