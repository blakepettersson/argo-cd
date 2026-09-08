package repository

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/argoproj/argo-cd/v3/pkg/apis/application/v1alpha1"
	utilio "github.com/argoproj/argo-cd/v3/util/io"
	pathutil "github.com/argoproj/argo-cd/v3/util/io/path"
)

func TestValueFileResolver_ResolveValueFiles(t *testing.T) {
	// Setup test environment
	tmpDir := t.TempDir()
	appPath := filepath.Join(tmpDir, "app")
	repoRoot := tmpDir

	// Create test files
	require.NoError(t, os.MkdirAll(appPath, 0o755))
	testValueFile := filepath.Join(appPath, "values.yaml")
	require.NoError(t, os.WriteFile(testValueFile, []byte("test: value"), 0o644))

	tests := []struct {
		name                    string
		rawValueFiles           []string
		ignoreMissingValueFiles bool
		expectError             bool
		expectedCount           int
	}{
		{
			name:          "resolve local file",
			rawValueFiles: []string{"values.yaml"},
			expectedCount: 1,
		},
		{
			name:                    "ignore missing file",
			rawValueFiles:           []string{"missing.yaml"},
			ignoreMissingValueFiles: true,
			expectedCount:           0,
		},
		{
			name:          "duplicate files are de-duplicated",
			rawValueFiles: []string{"values.yaml", "values.yaml"},
			expectedCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := newValueFileResolver(
				appPath,
				repoRoot,
				&v1alpha1.Env{},
				[]string{"https", "http"},
				nil, // no ref sources for this test
				tt.ignoreMissingValueFiles,
			)

			result, err := resolver.ResolveValueFiles(tt.rawValueFiles)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Len(t, result, tt.expectedCount)
			}
		})
	}
}

func TestValueFileResolver_resolveRawPath_local(t *testing.T) {
	tmpDir := t.TempDir()
	appPath := filepath.Join(tmpDir, "app")
	repoRoot := tmpDir

	require.NoError(t, os.MkdirAll(appPath, 0o755))
	testFile := filepath.Join(appPath, "test.yaml")
	require.NoError(t, os.WriteFile(testFile, []byte("test"), 0o644))

	resolver := newValueFileResolver(
		appPath,
		repoRoot,
		&v1alpha1.Env{},
		[]string{"https", "http"},
		nil,
		false,
	)

	// Test existing local file
	resolved, err := resolver.resolveRawPath("test.yaml")
	require.NoError(t, err)
	assert.False(t, resolved.IsRemote)
	assert.Equal(t, repoRoot, resolved.EffectiveRoot)
	assert.Contains(t, string(resolved.Path), "test.yaml")

	// Test with URL
	resolved, err = resolver.resolveRawPath("https://example.com/values.yaml")
	require.NoError(t, err)
	assert.True(t, resolved.IsRemote)
	assert.Equal(t, pathutil.ResolvedFilePath("https://example.com/values.yaml"), resolved.Path)
}

func TestValueFileResolver_checkFileExists(t *testing.T) {
	tmpDir := t.TempDir()
	existingFile := filepath.Join(tmpDir, "exists.yaml")
	require.NoError(t, os.WriteFile(existingFile, []byte("test"), 0o644))

	tests := []struct {
		name                    string
		path                    pathutil.ResolvedFilePath
		ignoreMissingValueFiles bool
		expectedSkip            bool
	}{
		{
			name:         "existing file",
			path:         pathutil.ResolvedFilePath(existingFile),
			expectedSkip: false,
		},
		{
			name:                    "missing file with ignore",
			path:                    pathutil.ResolvedFilePath(filepath.Join(tmpDir, "missing.yaml")),
			ignoreMissingValueFiles: true,
			expectedSkip:            true,
		},
		{
			name:                    "missing file without ignore",
			path:                    pathutil.ResolvedFilePath(filepath.Join(tmpDir, "missing.yaml")),
			ignoreMissingValueFiles: false,
			expectedSkip:            false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := &valueFileResolver{
				ignoreMissingValueFiles: tt.ignoreMissingValueFiles,
			}

			shouldSkip := resolver.checkFileExists(tt.path)
			assert.Equal(t, tt.expectedSkip, shouldSkip)
		})
	}
}

// refRootsFor builds refSourceRoots the way refSourceResolver.resolve does, looking each ref's
// root up in paths by normalized repo URL.
func refRootsFor(refSources map[string]*v1alpha1.RefTarget, paths utilio.TempPaths) *refSourceRoots {
	refs := &refSourceRoots{roots: map[string]string{}}
	for refVar, ref := range refSources {
		refs.roots[refVar] = paths.GetPathIfExists(ref.Repo.NormalizeRepoURL())
	}
	return refs
}

func TestValueFileResolver_resolveRawPath_referenced(t *testing.T) {
	// A known ref whose source was not materialized must error out rather than fall through to
	// env substitution against the main repo.
	resolver := newValueFileResolver(
		"/app",
		"/repo",
		&v1alpha1.Env{},
		[]string{"https"},
		&refSourceRoots{roots: map[string]string{"$git": "", "$oci": ""}},
		false,
	)

	_, err := resolver.resolveRawPath("$git/values.yaml")
	require.ErrorContains(t, err, `source "$git" referenced by "$git/values.yaml" was not resolved`)

	_, err = resolver.resolveRawPath("$oci/values.yaml")
	require.ErrorContains(t, err, `source "$oci" referenced by "$oci/values.yaml" was not resolved`)
}

func TestValueFileResolver_resolveRawPath_OCIEffectiveRoot(t *testing.T) {
	// Regression: for an OCI $ref source, EffectiveRoot must point at the extracted OCI
	// directory (not the main repo root), otherwise glob matches against OCI content fail
	// the verifyGlobMatchesWithinRoot boundary check.
	ociDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(ociDir, "values.yaml"), []byte("foo: bar"), 0o644))

	resolver := newValueFileResolver(
		"/app",
		"/repo",
		&v1alpha1.Env{},
		[]string{"https"},
		&refSourceRoots{roots: map[string]string{"$oci": ociDir}},
		false,
	)

	resolved, err := resolver.resolveRawPath("$oci/values.yaml")
	require.NoError(t, err)
	assert.Equal(t, ociDir, resolved.EffectiveRoot)
}

func TestValueFileResolver_ResolveValueFiles_OCIGlob(t *testing.T) {
	// Regression: globbing over an OCI $ref source must succeed. Before the effective-root
	// fix, matches under the extracted OCI directory were rejected as "outside repository
	// root" because the glob was checked against the main repo root instead.
	repoRoot := t.TempDir()
	appPath := filepath.Join(repoRoot, "app")
	require.NoError(t, os.MkdirAll(appPath, 0o755))

	ociDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(ociDir, "a.yaml"), []byte("a: 1"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(ociDir, "b.yaml"), []byte("b: 2"), 0o644))

	resolver := newValueFileResolver(
		appPath,
		repoRoot,
		&v1alpha1.Env{},
		[]string{"https"},
		&refSourceRoots{roots: map[string]string{"$oci": ociDir}},
		false,
	)

	result, err := resolver.ResolveValueFiles([]string{"$oci/*.yaml"})
	require.NoError(t, err)
	assert.ElementsMatch(t, []pathutil.ResolvedFilePath{
		pathutil.ResolvedFilePath(filepath.Join(ociDir, "a.yaml")),
		pathutil.ResolvedFilePath(filepath.Join(ociDir, "b.yaml")),
	}, result)
}

// TestResolveRefValueFile_RejectsPathWithoutFile: a $ref entry with no file path after the ref
// name (e.g. "$ref", "$ref/") must be rejected rather than resolving to the ref source's root.
func TestResolveRefValueFile_RejectsPathWithoutFile(t *testing.T) {
	root := t.TempDir()
	for _, raw := range []string{"$ref", "$ref/", "$ref//"} {
		t.Run(raw, func(t *testing.T) {
			_, err := resolveRefValueFile(raw, &v1alpha1.Env{}, []string{"https"}, root)
			require.ErrorContains(t, err, "no file path after the ref name")
		})
	}
}

// TestResolveRefValueFile_NeverRemote: the path after "$ref/" is always relative to the referenced
// source, even when it (or its env substitution) parses as a URL. Otherwise "$ref/https://..." would
// be handed to helm as a remote value file.
func TestResolveRefValueFile_NeverRemote(t *testing.T) {
	root := t.TempDir()
	env := &v1alpha1.Env{{Name: "ARGOCD_ENV_VALUES_URL", Value: "https://example.com/values.yaml"}}
	for _, raw := range []string{"$ref/https://example.com/values.yaml", "$ref/$ARGOCD_ENV_VALUES_URL"} {
		t.Run(raw, func(t *testing.T) {
			resolved, err := resolveRefValueFile(raw, env, []string{"https"}, root)
			require.NoError(t, err)
			assert.True(t, strings.HasPrefix(string(resolved), root+string(filepath.Separator)), "resolved %q is outside %q", resolved, root)
		})
	}
}

func TestValueFileResolver_ResolveValueFiles_DoesNotLogResolvedPaths(t *testing.T) {
	// Regression: resolved OCI value files live under the randomized extraction directory.
	// Logging them leaked the reposerver filesystem layout, so only the count is logged.
	repoRoot := t.TempDir()
	appPath := filepath.Join(repoRoot, "app")
	require.NoError(t, os.MkdirAll(appPath, 0o755))

	ociDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(ociDir, "a.yaml"), []byte("a: 1"), 0o644))

	resolver := newValueFileResolver(
		appPath,
		repoRoot,
		&v1alpha1.Env{},
		[]string{"https"},
		&refSourceRoots{roots: map[string]string{"$oci": ociDir}},
		false,
	)

	hook := logtest.NewGlobal()
	t.Cleanup(hook.Reset)

	result, err := resolver.ResolveValueFiles([]string{"$oci/a.yaml"})
	require.NoError(t, err)
	require.Len(t, result, 1)

	for _, entry := range hook.AllEntries() {
		msg, err := entry.String()
		require.NoError(t, err)
		assert.NotContains(t, msg, ociDir, "log entry leaked the OCI extraction directory")
	}
}

func Test_getReferencedSourceName(t *testing.T) {
	for raw, want := range map[string]string{
		"$ref/values.yaml": "$ref",
		"$ref":             "$ref",
		"$ref/":            "$ref",
		"values.yaml":      "",
		"":                 "",
	} {
		assert.Equal(t, want, getReferencedSourceName(raw), raw)
	}
}
