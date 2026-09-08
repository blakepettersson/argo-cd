package repository

import (
	"context"
	"errors"
	goio "io"
	"os"
	"path/filepath"
	gosync "sync"
	"testing"

	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/argoproj/argo-cd/v3/pkg/apis/application/v1alpha1"
	"github.com/argoproj/argo-cd/v3/reposerver/cache"
	"github.com/argoproj/argo-cd/v3/util/git"
	gitmocks "github.com/argoproj/argo-cd/v3/util/git/mocks"
	helmmocks "github.com/argoproj/argo-cd/v3/util/helm/mocks"
	utilio "github.com/argoproj/argo-cd/v3/util/io"
	iomocks "github.com/argoproj/argo-cd/v3/util/io/mocks"
	"github.com/argoproj/argo-cd/v3/util/oci"
	ocimocks "github.com/argoproj/argo-cd/v3/util/oci/mocks"
)

func TestResolveOCIRefSource(t *testing.T) {
	const repo = "oci://registry.example.com/chart"
	ref := func() *v1alpha1.RefTarget {
		return &v1alpha1.RefTarget{Repo: v1alpha1.Repository{Repo: repo}, TargetRevision: "v1.0.0"}
	}

	t.Run("OCI client creation fails", func(t *testing.T) {
		service, _, _ := newServiceWithOpt(t, func(_ *gitmocks.Client, _ *helmmocks.Client, _ *ocimocks.Client, _ *iomocks.TempPaths) {}, ".")
		service.newOCIClient = func(_ string, _ oci.Creds, _ string, _ string, _ []string, _ ...oci.ClientOpts) (oci.Client, error) {
			return nil, errors.New("internal client failure")
		}

		_, _, closer, err := service.newRefSourceResolver().resolveOCI(t.Context(), "$ref", ref(), "", refSourceResolveOpts{})
		assert.Nil(t, closer)
		require.ErrorContains(t, err, "failed to create OCI client for repo")
		// The underlying cause must not leak into the client-facing error.
		assert.NotContains(t, err.Error(), "internal client failure")
	})

	t.Run("revision resolution fails", func(t *testing.T) {
		service, _, _ := newServiceWithOpt(t, func(_ *gitmocks.Client, _ *helmmocks.Client, ociClient *ocimocks.Client, _ *iomocks.TempPaths) {
			ociClient.EXPECT().ResolveRevision(mock.Anything, "v1.0.0", mock.Anything).Return("", errors.New("registry unreachable"))
		}, ".")

		_, _, closer, err := service.newRefSourceResolver().resolveOCI(t.Context(), "$ref", ref(), "", refSourceResolveOpts{})
		assert.Nil(t, closer)
		require.ErrorContains(t, err, "failed to resolve OCI revision v1.0.0")
		assert.NotContains(t, err.Error(), "registry unreachable")
	})

	t.Run("extraction fails", func(t *testing.T) {
		service, _, _ := newServiceWithOpt(t, func(_ *gitmocks.Client, _ *helmmocks.Client, ociClient *ocimocks.Client, _ *iomocks.TempPaths) {
			ociClient.EXPECT().ResolveRevision(mock.Anything, "v1.0.0", mock.Anything).Return("sha256:abc", nil)
			ociClient.EXPECT().Extract(mock.Anything, "sha256:abc").Return("", nil, errors.New("layer digest mismatch"))
		}, ".")

		_, _, closer, err := service.newRefSourceResolver().resolveOCI(t.Context(), "$ref", ref(), "", refSourceResolveOpts{})
		assert.Nil(t, closer)
		require.ErrorContains(t, err, "failed to extract OCI image")
		assert.NotContains(t, err.Error(), "layer digest mismatch")
	})

	t.Run("out-of-bounds symlink is rejected without logging credentials", func(t *testing.T) {
		ociDir := t.TempDir()
		require.NoError(t, os.Symlink("/etc/passwd", filepath.Join(ociDir, "link.yaml")))
		closed := false
		service, _, _ := newServiceWithOpt(t, func(_ *gitmocks.Client, _ *helmmocks.Client, ociClient *ocimocks.Client, _ *iomocks.TempPaths) {
			ociClient.EXPECT().ResolveRevision(mock.Anything, "v1.0.0", mock.Anything).Return("sha256:abc", nil)
			ociClient.EXPECT().Extract(mock.Anything, "sha256:abc").Return(ociDir, utilio.NewCloser(func() error { closed = true; return nil }), nil)
		}, ".")
		hook := logtest.NewGlobal()
		t.Cleanup(hook.Reset)

		r := ref()
		r.Repo.Password = "s3cret-registry-password"
		root, _, closer, err := service.newRefSourceResolver().resolveOCI(t.Context(), "$ref", r, "", refSourceResolveOpts{})
		require.ErrorContains(t, err, "oci image contains out-of-bounds symlinks")
		assert.Empty(t, root)
		assert.Nil(t, closer)
		assert.True(t, closed, "the OCI lock must be released when the symlink check fails")
		for _, entry := range hook.AllEntries() {
			line, err := entry.String()
			require.NoError(t, err)
			assert.NotContains(t, line, "s3cret-registry-password")
		}
	})

	t.Run("success returns the extracted directory", func(t *testing.T) {
		ociDir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(ociDir, "values.yaml"), []byte("foo: bar"), 0o644))
		service, _, _ := newServiceWithOpt(t, func(_ *gitmocks.Client, _ *helmmocks.Client, ociClient *ocimocks.Client, _ *iomocks.TempPaths) {
			ociClient.EXPECT().ResolveRevision(mock.Anything, "v1.0.0", mock.Anything).Return("sha256:abc", nil)
			ociClient.EXPECT().Extract(mock.Anything, "sha256:abc").Return(ociDir, utilio.NopCloser, nil)
		}, ".")

		root, resolved, closer, err := service.newRefSourceResolver().resolveOCI(t.Context(), "$ref", ref(), "", refSourceResolveOpts{})
		require.NoError(t, err)
		require.NotNil(t, closer)
		assert.Equal(t, ociDir, root)
		assert.Equal(t, repoRef{revision: "v1.0.0", commitSHA: "sha256:abc", key: "$ref"}, resolved)
	})

	t.Run("noCache evicts the cached artifact before extracting", func(t *testing.T) {
		service, _, _ := newServiceWithOpt(t, func(_ *gitmocks.Client, _ *helmmocks.Client, ociClient *ocimocks.Client, _ *iomocks.TempPaths) {
			ociClient.EXPECT().ResolveRevision(mock.Anything, "v1.0.0", true).Return("sha256:abc", nil)
			ociClient.EXPECT().CleanCache("sha256:abc").Return(nil).Once()
			ociClient.EXPECT().Extract(mock.Anything, "sha256:abc").Return(t.TempDir(), utilio.NopCloser, nil)
		}, ".")

		_, _, _, err := service.newRefSourceResolver().resolveOCI(t.Context(), "$ref", ref(), "", refSourceResolveOpts{noCache: true})
		require.NoError(t, err)
	})

	t.Run("a pre-resolved digest is not resolved again", func(t *testing.T) {
		service, _, _ := newServiceWithOpt(t, func(_ *gitmocks.Client, _ *helmmocks.Client, ociClient *ocimocks.Client, _ *iomocks.TempPaths) {
			ociClient.EXPECT().Extract(mock.Anything, "sha256:probed").Return(t.TempDir(), utilio.NopCloser, nil)
		}, ".")

		_, resolved, _, err := service.newRefSourceResolver().resolveOCI(t.Context(), "$ref", ref(), "sha256:probed", refSourceResolveOpts{})
		require.NoError(t, err)
		assert.Equal(t, "sha256:probed", resolved.commitSHA)
	})
}

func TestResolveGitRefSource(t *testing.T) {
	const repo = "https://github.com/test/repo.git"
	ref := func() *v1alpha1.RefTarget {
		return &v1alpha1.RefTarget{Repo: v1alpha1.Repository{Repo: repo}, TargetRevision: "main"}
	}
	opts := refSourceResolveOpts{appRepoURL: repo, appRevision: "primary-revision", commitSHA: "primary-sha"}
	normalized := git.NormalizeGitURL(repo)

	t.Run("git client resolution fails", func(t *testing.T) {
		service, _, _ := newServiceWithOpt(t, func(gitClient *gitmocks.Client, _ *helmmocks.Client, _ *ocimocks.Client, paths *iomocks.TempPaths) {
			paths.EXPECT().GetPath(mock.Anything).Return(t.TempDir(), nil)
			gitClient.EXPECT().Root().Return("/tmp/repo")
			gitClient.EXPECT().LsRemote(mock.Anything).Return("", errors.New("auth required"))
		}, ".")

		_, _, closer, err := service.newRefSourceResolver().resolveGit(t.Context(), "$ref", normalized, ref(), opts)
		assert.Nil(t, closer)
		require.ErrorContains(t, err, "failed to get git client for repo")
		assert.NotContains(t, err.Error(), "auth required")
	})

	t.Run("same repository at a different revision is rejected", func(t *testing.T) {
		service, _, _ := newServiceWithOpt(t, func(gitClient *gitmocks.Client, _ *helmmocks.Client, _ *ocimocks.Client, paths *iomocks.TempPaths) {
			paths.EXPECT().GetPath(mock.Anything).Return(t.TempDir(), nil)
			gitClient.EXPECT().Root().Return("/tmp/repo")
			gitClient.EXPECT().LsRemote(mock.Anything).Return("other-sha", nil)
		}, ".")

		_, _, closer, err := service.newRefSourceResolver().resolveGit(t.Context(), "$ref", normalized, ref(), opts)
		assert.Nil(t, closer)
		require.ErrorContains(t, err, "cannot reference a different revision of the same repository")
	})

	t.Run("out-of-bounds symlink is rejected and the lock released", func(t *testing.T) {
		root := t.TempDir()
		require.NoError(t, os.Symlink("/etc/passwd", filepath.Join(root, "link.yaml")))
		service, _, _ := newServiceWithOpt(t, func(gitClient *gitmocks.Client, _ *helmmocks.Client, _ *ocimocks.Client, paths *iomocks.TempPaths) {
			paths.EXPECT().GetPath(mock.Anything).Return(root, nil)
			gitClient.EXPECT().Root().Return(root)
			gitClient.EXPECT().LsRemote(mock.Anything).Return("primary-sha", nil)
			gitClient.EXPECT().Init().Return(nil)
			gitClient.EXPECT().IsRevisionPresent(mock.Anything, mock.Anything).Return(true)
			gitClient.EXPECT().Checkout(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("", nil)
		}, ".")

		_, _, closer, err := service.newRefSourceResolver().resolveGit(t.Context(), "$ref", normalized, ref(), opts)
		assert.Nil(t, closer)
		require.ErrorContains(t, err, "repository contains out-of-bounds symlinks")
	})

	t.Run("out-of-bounds symlink check is keyed on the referenced commit", func(t *testing.T) {
		root := t.TempDir()
		require.NoError(t, os.Symlink("/etc/passwd", filepath.Join(root, "link.yaml")))
		service, _, _ := newServiceWithOpt(t, func(gitClient *gitmocks.Client, _ *helmmocks.Client, _ *ocimocks.Client, paths *iomocks.TempPaths) {
			paths.EXPECT().GetPath(mock.Anything).Return(root, nil)
			gitClient.EXPECT().Root().Return(root)
			gitClient.EXPECT().LsRemote(mock.Anything).Return("ref-sha", nil)
			gitClient.EXPECT().Init().Return(nil)
			gitClient.EXPECT().IsRevisionPresent(mock.Anything, mock.Anything).Return(true)
			gitClient.EXPECT().Checkout(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("", nil)
		}, ".")
		// A verdict memoized for the primary source's commit must not be reused for the ref checkout.
		service.symlinksState.Set(root+"/primary-sha/.git", gosync.OnceValue(func() error { return nil }), 0)

		o := opts
		o.appRepoURL = "" // primary source is not this repository
		_, _, _, err := service.newRefSourceResolver().resolveGit(t.Context(), "$ref", normalized, ref(), o)
		require.ErrorContains(t, err, "repository contains out-of-bounds symlinks")
	})

	t.Run("success returns the checkout and a closer", func(t *testing.T) {
		root := t.TempDir()
		service, _, _ := newServiceWithOpt(t, func(gitClient *gitmocks.Client, _ *helmmocks.Client, _ *ocimocks.Client, paths *iomocks.TempPaths) {
			paths.EXPECT().GetPath(mock.Anything).Return(root, nil)
			gitClient.EXPECT().Root().Return(root)
			gitClient.EXPECT().LsRemote(mock.Anything).Return("primary-sha", nil)
			gitClient.EXPECT().Init().Return(nil)
			gitClient.EXPECT().IsRevisionPresent(mock.Anything, mock.Anything).Return(true)
			gitClient.EXPECT().Checkout(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return("", nil)
		}, ".")

		o := opts
		o.noCache = true
		gotRoot, resolved, closer, err := service.newRefSourceResolver().resolveGit(t.Context(), "$ref", normalized, ref(), o)
		require.NoError(t, err)
		require.NotNil(t, closer)
		defer utilio.Close(closer)
		assert.Equal(t, root, gotRoot)
		assert.Equal(t, repoRef{revision: "main", commitSHA: "primary-sha", key: "$ref"}, resolved)
	})
}

// TestRefSourceResolver_Resolve exercises the orchestration with fake dependencies: every ref maps
// to its repository's root, shared repositories are materialized once, revisions feed the cache key,
// and every lock is released on Close or on failure.
func TestRefSourceResolver_Resolve(t *testing.T) {
	gitRoot, ociRoot := t.TempDir(), t.TempDir()
	refSources := map[string]*v1alpha1.RefTarget{
		"$a":     {Repo: v1alpha1.Repository{Repo: "https://github.com/org/values.git"}, TargetRevision: "main"},
		"$alias": {Repo: v1alpha1.Repository{Repo: "https://github.com/org/values"}, TargetRevision: "main"},
		"$oci":   {Repo: v1alpha1.Repository{Repo: "oci://registry.example.com/values"}, TargetRevision: "1.0.0"},
		"$spare": {Repo: v1alpha1.Repository{Repo: "https://github.com/org/spare.git"}, TargetRevision: "main"},
	}
	var closed []string
	newResolver := func(t *testing.T, checkoutErr error) *refSourceResolver {
		t.Helper()
		gitClient := gitmocks.NewClient(t)
		gitClient.EXPECT().Root().Return(gitRoot).Maybe()
		ociClient := ocimocks.NewClient(t)
		ociClient.EXPECT().Extract(mock.Anything, "sha256:abc").Return(ociRoot, utilio.NewCloser(func() error { closed = append(closed, "oci"); return nil }), nil).Maybe()
		return &refSourceResolver{
			newGitClient: func(_ *v1alpha1.Repository, revision string, _ bool) (git.Client, string, error) {
				return gitClient, "sha-" + revision, nil
			},
			newOCIClient: func(*v1alpha1.Repository) (oci.Client, error) { return ociClient, nil },
			checkout: func(_ context.Context, _ git.Client, _ string, _ int64) (goio.Closer, error) {
				if checkoutErr != nil {
					return nil, checkoutErr
				}
				return utilio.NewCloser(func() error { closed = append(closed, "git"); return nil }), nil
			},
		}
	}

	t.Run("materializes each repository once and maps every ref", func(t *testing.T) {
		closed = nil
		refs, err := newResolver(t, nil).resolve(t.Context(), []string{"$a/x.yaml", "$oci/y.yaml", "$alias/z.yaml", "plain.yaml"}, refSources,
			refSourceResolveOpts{refRevisions: cache.ResolvedRevisions{"oci://registry.example.com/values": "sha256:abc"}})
		require.NoError(t, err)

		for refVar, want := range map[string]string{"$a": gitRoot, "$alias": gitRoot, "$oci": ociRoot, "$spare": ""} {
			root, known := refs.root(refVar)
			assert.True(t, known, refVar)
			assert.Equal(t, want, root, refVar)
		}
		_, known := refs.root("$unknown")
		assert.False(t, known)
		assert.Equal(t, cache.ResolvedRevisions{
			"https://github.com/org/values":     "sha-main",
			"oci://registry.example.com/values": "sha256:abc",
		}, refs.resolvedRevisions())
		assert.ElementsMatch(t, []string{gitRoot, ociRoot}, refs.paths())

		require.NoError(t, refs.Close())
		assert.ElementsMatch(t, []string{"git", "oci"}, closed)
	})

	t.Run("releases already acquired locks when a later ref fails", func(t *testing.T) {
		closed = nil
		r := newResolver(t, nil)
		failing := errors.New("lock timeout")
		calls := 0
		checkout := r.checkout
		r.checkout = func(ctx context.Context, c git.Client, rev string, depth int64) (goio.Closer, error) {
			calls++
			if calls == 2 {
				return nil, failing
			}
			return checkout(ctx, c, rev, depth)
		}

		refs, err := r.resolve(t.Context(), []string{"$a/x.yaml", "$spare/y.yaml"}, refSources, refSourceResolveOpts{})
		require.ErrorIs(t, err, failing)
		assert.Nil(t, refs)
		assert.Equal(t, []string{"git"}, closed)
	})

	t.Run("nil roots are safe to query and close", func(t *testing.T) {
		var refs *refSourceRoots
		_, known := refs.root("$a")
		assert.False(t, known)
		assert.Nil(t, refs.resolvedRevisions())
		assert.Empty(t, refs.paths())
		require.NoError(t, refs.Close())
	})
}

func TestForEachRefSource(t *testing.T) {
	gitRef := func(repo, revision string) *v1alpha1.RefTarget {
		return &v1alpha1.RefTarget{Repo: v1alpha1.Repository{Repo: repo}, TargetRevision: revision}
	}
	collect := func(t *testing.T, candidates []string, refSources map[string]*v1alpha1.RefTarget) ([]string, error) {
		t.Helper()
		var visited []string
		err := forEachRefSource(candidates, refSources, func(refVar, normalizedRepoURL string, _ *v1alpha1.RefTarget) error {
			visited = append(visited, refVar+"="+normalizedRepoURL)
			return nil
		})
		return visited, err
	}

	t.Run("visits each repository once, in candidate order, skipping non-ref entries", func(t *testing.T) {
		visited, err := collect(t, []string{"values.yaml", "$b/b.yaml", "$a/a.yaml", "$b/other.yaml", "$c/c.yaml"}, map[string]*v1alpha1.RefTarget{
			"$a": gitRef("https://github.com/org/a.git", "main"),
			"$b": gitRef("https://github.com/org/b.git", "main"),
			"$c": gitRef("https://github.com/org/B", "main"), // same repository as $b
		})
		require.NoError(t, err)
		assert.Equal(t, []string{"$b=https://github.com/org/b", "$a=https://github.com/org/a"}, visited)
	})

	t.Run("rejects two revisions of one repository", func(t *testing.T) {
		_, err := collect(t, []string{"$a/a.yaml", "$b/b.yaml"}, map[string]*v1alpha1.RefTarget{
			"$a": gitRef("https://github.com/org/repo.git", "main"),
			"$b": gitRef("https://github.com/org/repo", "dev"),
		})
		require.EqualError(t, err, `cannot reference multiple revisions for the same repository ($b references "dev" while $a references "main")`)
	})

	t.Run("rejects an unknown ref", func(t *testing.T) {
		_, err := collect(t, []string{"$missing/a.yaml"}, map[string]*v1alpha1.RefTarget{
			"$b": gitRef("https://github.com/org/b.git", "main"),
			"$a": gitRef("https://github.com/org/a.git", "main"),
		})
		require.EqualError(t, err, `source referenced "$missing", which is not one of the available sources ($a, $b)`)
		_, err = collect(t, []string{"$missing/a.yaml"}, nil)
		require.EqualError(t, err, `source referenced "$missing", but no source has a 'ref' field defined`)
	})

	t.Run("rejects a ref source with a chart", func(t *testing.T) {
		ref := gitRef("oci://registry.example.com/charts", "1.0.0")
		ref.Chart = "my-chart"
		_, err := collect(t, []string{"$a/a.yaml"}, map[string]*v1alpha1.RefTarget{"$a": ref})
		require.ErrorContains(t, err, "'chart' field is not supported for 'ref' sources")
	})
}
