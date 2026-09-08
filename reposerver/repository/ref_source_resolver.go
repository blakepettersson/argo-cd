package repository

import (
	"context"
	"errors"
	"fmt"
	goio "io"
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/argoproj/argo-cd/v3/common"
	"github.com/argoproj/argo-cd/v3/pkg/apis/application/v1alpha1"
	"github.com/argoproj/argo-cd/v3/reposerver/cache"
	apppathutil "github.com/argoproj/argo-cd/v3/util/app/path"
	"github.com/argoproj/argo-cd/v3/util/git"
	utilio "github.com/argoproj/argo-cd/v3/util/io"
	"github.com/argoproj/argo-cd/v3/util/oci"
)

// refSourceResolver materializes the sources that Helm value files reference ("$ref/...") so the
// value file resolver can read from them. Its repository dependencies are injected, so it has no
// other coupling to Service.
type refSourceResolver struct {
	// newGitClient returns a git client for repo along with the commit revision resolves to.
	newGitClient func(repo *v1alpha1.Repository, revision string, noRevisionCache bool) (git.Client, string, error)
	// newOCIClient returns an OCI client for repo.
	newOCIClient func(repo *v1alpha1.Repository) (oci.Client, error)
	// checkout locks the git client's root and checks out revision. The returned closer releases
	// the lock.
	checkout func(ctx context.Context, gitClient git.Client, revision string, depth int64) (goio.Closer, error)
	// checkSymlinks scans root for out-of-bounds symlinks, memoized per root+version. nil disables
	// the check.
	checkSymlinks func(root, version string, noCache bool, skipPaths ...string) error
}

// refSourceResolveOpts carries the per-request settings for refSourceResolver.resolve.
type refSourceResolveOpts struct {
	noCache         bool
	noRevisionCache bool
	// appRepoURL, appRevision and commitSHA describe the primary (application) source when it is a
	// git repository, so a ref to a different revision of that same repository can be rejected.
	// appRepoURL is empty for OCI and Helm primary sources.
	appRepoURL  string
	appRevision string
	commitSHA   string
	// refRevisions holds revisions already resolved by resolveRevisions for the cache probe, keyed by
	// normalized repo URL. OCI refs reuse them instead of resolving the tag a second time, which also
	// keeps the extracted content consistent with the revision the cache was probed with.
	refRevisions cache.ResolvedRevisions
}

type repoRef struct {
	// revision is the requested revision - a branch, tag, commit SHA, OCI tag or digest.
	revision string
	// commitSHA is the commit SHA or OCI digest that revision resolved to.
	commitSHA string
	// key is the name of the key which was used to reference this repo.
	key string
}

// forEachRefSource validates every "$ref/..." entry in candidates against refSources and calls fn
// once per distinct referenced repository, keyed by its normalized URL, in candidate order.
// Referencing one repository at two different revisions is rejected.
func forEachRefSource(candidates []string, refSources map[string]*v1alpha1.RefTarget, fn func(refVar, normalizedRepoURL string, ref *v1alpha1.RefTarget) error) error {
	seen := make(map[string]repoRef)
	for _, candidate := range candidates {
		refVar := getReferencedSourceName(candidate)
		if refVar == "" {
			continue
		}
		ref, ok := refSources[refVar]
		if !ok {
			if len(refSources) == 0 {
				return fmt.Errorf("source referenced %q, but no source has a 'ref' field defined", refVar)
			}
			refKeys := make([]string, 0, len(refSources))
			for refKey := range refSources {
				refKeys = append(refKeys, refKey)
			}
			sort.Strings(refKeys)
			return fmt.Errorf("source referenced %q, which is not one of the available sources (%s)", refVar, strings.Join(refKeys, ", "))
		}
		// Ref resolution keys off the repository URL only, so a 'chart' would be silently ignored.
		if ref.Chart != "" {
			return errors.New("source has a 'chart' field defined, but the 'chart' field is not supported for 'ref' sources")
		}
		normalizedRepoURL := ref.Repo.NormalizeRepoURL()
		if prev, ok := seen[normalizedRepoURL]; ok {
			if prev.revision != ref.TargetRevision {
				return fmt.Errorf("cannot reference multiple revisions for the same repository (%s references %q while %s references %q)", refVar, ref.TargetRevision, prev.key, prev.revision)
			}
			continue
		}
		if err := fn(refVar, normalizedRepoURL, ref); err != nil {
			return err
		}
		seen[normalizedRepoURL] = repoRef{revision: ref.TargetRevision, key: refVar}
	}
	return nil
}

// resolveRevisions resolves the revision of every source referenced by candidates without
// materializing anything, so the manifest cache can be probed first.
func (r *refSourceResolver) resolveRevisions(ctx context.Context, candidates []string, refSources map[string]*v1alpha1.RefTarget, noRevisionCache bool) (cache.ResolvedRevisions, error) {
	revisions := cache.ResolvedRevisions{}
	err := forEachRefSource(candidates, refSources, func(_, normalizedRepoURL string, ref *v1alpha1.RefTarget) error {
		var revision string
		var err error
		if ref.Repo.IsOCI() {
			revision, err = r.resolveOCIRevision(ctx, ref, noRevisionCache)
		} else {
			_, revision, err = r.newGitClient(&ref.Repo, ref.TargetRevision, noRevisionCache)
			if err != nil {
				log.Errorf("Failed to get git client for repo %s: %v", ref.Repo.Repo, err)
				err = fmt.Errorf("failed to get git client for repo %s", ref.Repo.Repo)
			}
		}
		if err != nil {
			return err
		}
		revisions[normalizedRepoURL] = revision
		return nil
	})
	if err != nil {
		return nil, err
	}
	return revisions, nil
}

// resolve checks out (Git) or extracts (OCI) every source referenced by candidates. The returned
// refSourceRoots must be closed once the referenced value files have been read; on error nothing is
// left locked.
func (r *refSourceResolver) resolve(ctx context.Context, candidates []string, refSources map[string]*v1alpha1.RefTarget, opts refSourceResolveOpts) (*refSourceRoots, error) {
	rootsByRepo := make(map[string]string)
	refs := &refSourceRoots{roots: make(map[string]string, len(refSources)), revisions: cache.ResolvedRevisions{}}
	var closers []goio.Closer
	refs.closer = utilio.NewCloser(func() error {
		for _, closer := range closers {
			utilio.Close(closer)
		}
		return nil
	})
	err := forEachRefSource(candidates, refSources, func(refVar, normalizedRepoURL string, ref *v1alpha1.RefTarget) error {
		var (
			root   string
			result repoRef
			closer goio.Closer
			err    error
		)
		if ref.Repo.IsOCI() {
			root, result, closer, err = r.resolveOCI(ctx, refVar, ref, opts.refRevisions[normalizedRepoURL], opts)
		} else {
			root, result, closer, err = r.resolveGit(ctx, refVar, normalizedRepoURL, ref, opts)
		}
		if err != nil {
			return err
		}
		closers = append(closers, closer)
		rootsByRepo[normalizedRepoURL] = root
		refs.revisions[normalizedRepoURL] = result.commitSHA
		return nil
	})
	if err != nil {
		utilio.Close(refs)
		return nil, err
	}
	// Every ref variable maps to its repository's root, so two refs to one repository share a
	// checkout and a ref that was not a candidate is still known to the value file resolver.
	for refVar, ref := range refSources {
		refs.roots[refVar] = rootsByRepo[ref.Repo.NormalizeRepoURL()]
	}
	return refs, nil
}

// resolveOCIRevision resolves an OCI ref's tag to a digest. Errors are redacted for the client;
// the cause is logged.
func (r *refSourceResolver) resolveOCIRevision(ctx context.Context, ref *v1alpha1.RefTarget, noRevisionCache bool) (string, error) {
	ociClient, err := r.newOCIClient(&ref.Repo)
	if err != nil {
		log.Errorf("Failed to create OCI client for repo %s: %v", ref.Repo.Repo, err)
		return "", fmt.Errorf("failed to create OCI client for repo %s", ref.Repo.Repo)
	}
	digest, err := ociClient.ResolveRevision(ctx, ref.TargetRevision, noRevisionCache)
	if err != nil {
		log.Errorf("Failed to resolve OCI revision %s: %v", ref.TargetRevision, err)
		return "", fmt.Errorf("failed to resolve OCI revision %s", ref.TargetRevision)
	}
	return digest, nil
}

// resolveOCI extracts an OCI ref source and returns its directory, the resolution and a closer
// releasing the OCI lock. resolvedDigest, when non-empty, skips tag resolution. Errors returned for
// external causes are redacted for surfacing to the client; the detailed cause is logged here.
//
// Unlike resolveGit, there is deliberately no "same repository, different revision" guard. That git
// check exists because a referenced git source and the primary source can share a single checkout
// directory, making two revisions of one repo contradictory. OCI ref content is extracted into a
// request-scoped directory of its own, so there is no shared-checkout conflict to detect, and the
// primary source's revision (a git commit SHA) is not comparable to an OCI digest.
func (r *refSourceResolver) resolveOCI(ctx context.Context, refVar string, ref *v1alpha1.RefTarget, resolvedDigest string, opts refSourceResolveOpts) (string, repoRef, goio.Closer, error) {
	ociClient, err := r.newOCIClient(&ref.Repo)
	if err != nil {
		log.Errorf("Failed to create OCI client for repo %s: %v", ref.Repo.Repo, err)
		return "", repoRef{}, nil, fmt.Errorf("failed to create OCI client for repo %s", ref.Repo.Repo)
	}

	digest := resolvedDigest
	if digest == "" {
		digest, err = ociClient.ResolveRevision(ctx, ref.TargetRevision, opts.noCache || opts.noRevisionCache)
		if err != nil {
			log.Errorf("Failed to resolve OCI revision %s: %v", ref.TargetRevision, err)
			return "", repoRef{}, nil, fmt.Errorf("failed to resolve OCI revision %s", ref.TargetRevision)
		}
	}

	// A hard refresh must be able to evict a corrupt cached artifact, as it does for a primary OCI
	// source.
	if opts.noCache {
		if err := ociClient.CleanCache(digest); err != nil {
			log.Errorf("Failed to clean OCI cache for %s: %v", ref.Repo.Repo, err)
			return "", repoRef{}, nil, fmt.Errorf("failed to clean OCI cache for %s", ref.Repo.Repo)
		}
	}

	root, closer, err := ociClient.Extract(ctx, digest)
	if err != nil {
		log.Errorf("Failed to extract OCI image %s: %v", ref.Repo.Repo, err)
		return "", repoRef{}, nil, fmt.Errorf("failed to extract OCI image %s", ref.Repo.Repo)
	}

	if r.checkSymlinks != nil {
		if err := r.checkSymlinks(root, digest, opts.noCache); err != nil {
			utilio.Close(closer)
			return "", repoRef{}, nil, outOfBoundsSymlinkError(err, "oci image", ref)
		}
	}

	return root, repoRef{revision: ref.TargetRevision, commitSHA: digest, key: refVar}, closer, nil
}

// resolveGit checks out a git ref source at its target revision and returns its directory, the
// resolution and a closer releasing the repo lock. Errors returned for external causes are redacted
// for surfacing to the client; the detailed cause is logged here.
func (r *refSourceResolver) resolveGit(ctx context.Context, refVar, normalizedRepoURL string, ref *v1alpha1.RefTarget, opts refSourceResolveOpts) (string, repoRef, goio.Closer, error) {
	gitClient, commitSHA, err := r.newGitClient(&ref.Repo, ref.TargetRevision, opts.noCache || opts.noRevisionCache)
	if err != nil {
		log.Errorf("Failed to get git client for repo %s: %v", ref.Repo.Repo, err)
		return "", repoRef{}, nil, fmt.Errorf("failed to get git client for repo %s", ref.Repo.Repo)
	}

	if opts.appRepoURL != "" && git.NormalizeGitURL(opts.appRepoURL) == normalizedRepoURL && opts.commitSHA != commitSHA {
		return "", repoRef{}, nil, fmt.Errorf("cannot reference a different revision of the same repository (%s references %q which resolves to %q while the application references %q which resolves to %q)", refVar, ref.TargetRevision, commitSHA, opts.appRevision, opts.commitSHA)
	}

	// Use the referenced source's own depth: for a Helm/OCI primary source the request's depth is
	// unset, which would otherwise force a full fetch of the referenced repository.
	closer, err := r.checkout(ctx, gitClient, commitSHA, ref.Repo.Depth)
	if err != nil {
		return "", repoRef{}, nil, fmt.Errorf("failed to acquire lock for referenced repo %q: %w", ref.Repo.Repo, err)
	}

	// The check runs after the lock is held and is memoized per checkout, so it is keyed on the
	// referenced repo's own commit, not the primary source's.
	if r.checkSymlinks != nil {
		if err := r.checkSymlinks(gitClient.Root(), commitSHA, opts.noCache, ".git"); err != nil {
			utilio.Close(closer)
			return "", repoRef{}, nil, outOfBoundsSymlinkError(err, "repository", ref)
		}
	}

	return gitClient.Root(), repoRef{revision: ref.TargetRevision, commitSHA: commitSHA, key: refVar}, closer, nil
}

// outOfBoundsSymlinkError logs a security warning for an out-of-bounds symlink found in a ref source
// and returns the client-facing error. Only the repo URL is logged, never the credentials.
func outOfBoundsSymlinkError(err error, what string, ref *v1alpha1.RefTarget) error {
	oobError := &apppathutil.OutOfBoundsSymlinkError{}
	if !errors.As(err, &oobError) {
		return err
	}
	log.WithFields(log.Fields{
		common.SecurityField: common.SecurityHigh,
		"repo":               ref.Repo.Repo,
		"revision":           ref.TargetRevision,
		"file":               oobError.File,
	}).Warnf("%s contains out-of-bounds symlink", what)
	return fmt.Errorf("%s contains out-of-bounds symlinks. file: %s", what, oobError.File)
}
