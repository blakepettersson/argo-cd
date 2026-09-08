package repository

import (
	"fmt"
	goio "io"
	"os"
	"path/filepath"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	log "github.com/sirupsen/logrus"

	"github.com/argoproj/argo-cd/v3/pkg/apis/application/v1alpha1"
	"github.com/argoproj/argo-cd/v3/reposerver/cache"
	pathutil "github.com/argoproj/argo-cd/v3/util/io/path"
)

// refSourceRoots holds the sources referenced by Helm value files ("$ref/...") as materialized
// on disk for the current request: a Git checkout or an extracted OCI artifact per ref. It is
// produced by refSourceResolver.resolve and consumed by valueFileResolver. Close releases the
// underlying repo/OCI locks and must be called once the value files have been read.
type refSourceRoots struct {
	// roots maps a ref variable (e.g. "$values") to its root directory. A known ref that was not
	// materialized for this request is present with an empty root.
	roots map[string]string
	// revisions maps each referenced repository (normalized URL) to the commit SHA or OCI digest it
	// resolved to; it feeds the manifest cache key.
	revisions cache.ResolvedRevisions
	closer    goio.Closer
}

// root returns the on-disk root for refVar and whether refVar names a ref source at all.
func (r *refSourceRoots) root(refVar string) (string, bool) {
	if r == nil {
		return "", false
	}
	root, ok := r.roots[refVar]
	return root, ok
}

// resolvedRevisions returns the resolved revision per referenced repository. Safe on nil.
func (r *refSourceRoots) resolvedRevisions() cache.ResolvedRevisions {
	if r == nil {
		return nil
	}
	return r.revisions
}

// paths returns the root directories, for redacting them from user-facing output. Safe on nil.
func (r *refSourceRoots) paths() []string {
	if r == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(r.roots))
	paths := make([]string, 0, len(r.roots))
	for _, root := range r.roots {
		if _, dup := seen[root]; root == "" || dup {
			continue
		}
		seen[root] = struct{}{}
		paths = append(paths, root)
	}
	return paths
}

func (r *refSourceRoots) Close() error {
	if r == nil || r.closer == nil {
		return nil
	}
	return r.closer.Close()
}

// valueFileResolver resolves Helm value file entries to local paths or remote URLs.
type valueFileResolver struct {
	appPath                  string
	repoRoot                 string
	env                      *v1alpha1.Env
	allowedValueFilesSchemas []string
	refs                     *refSourceRoots
	ignoreMissingValueFiles  bool
}

func newValueFileResolver(appPath, repoRoot string, env *v1alpha1.Env, allowedValueFilesSchemas []string, refs *refSourceRoots, ignoreMissingValueFiles bool) *valueFileResolver {
	return &valueFileResolver{
		appPath:                  appPath,
		repoRoot:                 repoRoot,
		env:                      env,
		allowedValueFilesSchemas: allowedValueFilesSchemas,
		refs:                     refs,
		ignoreMissingValueFiles:  ignoreMissingValueFiles,
	}
}

// getResolvedValueFiles resolves a list of raw value file paths (handling local files, $ref
// sources, and glob expansion) via the valueFileResolver.
func getResolvedValueFiles(appPath, repoRoot string, env *v1alpha1.Env, allowedValueFilesSchemas []string, rawValueFiles []string, refs *refSourceRoots, ignoreMissingValueFiles bool) ([]pathutil.ResolvedFilePath, error) {
	return newValueFileResolver(appPath, repoRoot, env, allowedValueFilesSchemas, refs, ignoreMissingValueFiles).ResolveValueFiles(rawValueFiles)
}

// ResolveValueFiles resolves a list of raw value file paths to their resolved paths,
// handling local files, $ref sources, and glob expansion.
func (r *valueFileResolver) ResolveValueFiles(rawValueFiles []string) ([]pathutil.ResolvedFilePath, error) {
	// Pre-collect resolved paths for all explicit (non-glob) entries. This allows glob
	// expansion to skip files that also appear explicitly, so the explicit entry controls
	// the final position. For example, with ["*.yaml", "c.yaml"], c.yaml is excluded from
	// the glob expansion and placed at the end where it was explicitly listed.
	explicitPaths := make(map[pathutil.ResolvedFilePath]struct{})
	for _, rawValueFile := range rawValueFiles {
		resolved, err := r.resolveRawPath(rawValueFile)
		if err != nil {
			continue // resolution errors will be surfaced in the main loop below
		}
		if !isGlobPath(string(resolved.Path)) {
			explicitPaths[resolved.Path] = struct{}{}
		}
	}

	var resolvedValueFiles []pathutil.ResolvedFilePath
	seen := make(map[pathutil.ResolvedFilePath]struct{})
	appendUnique := func(p pathutil.ResolvedFilePath) {
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			resolvedValueFiles = append(resolvedValueFiles, p)
		}
	}
	for _, rawValueFile := range rawValueFiles {
		resolved, err := r.resolveRawPath(rawValueFile)
		if err != nil {
			return nil, fmt.Errorf("error resolving value file path: %w", err)
		}

		// If the resolved path contains a glob pattern, expand it to all matching files.
		// doublestar.FilepathGlob is used (consistent with AppSet generators) because it supports
		// ** for recursive matching in addition to all standard glob patterns (*,?,[).
		// Matches are returned in lexical order, which determines helm's merge precedence
		// (later files override earlier ones). Glob patterns are only expanded for local files;
		// remote value file URLs (e.g. https://...) are passed through as-is.
		// If the glob matches no files and ignoreMissingValueFiles is true, skip it silently.
		// Otherwise, return an error — consistent with how missing non-glob value files are handled.
		if !resolved.IsRemote && isGlobPath(string(resolved.Path)) {
			matches, err := doublestar.FilepathGlob(string(resolved.Path))
			if err != nil {
				return nil, fmt.Errorf("error expanding glob pattern %q: %w", rawValueFile, err)
			}
			if len(matches) == 0 {
				if r.ignoreMissingValueFiles {
					log.Debugf(" %s values file glob matched no files", rawValueFile)
					continue
				}
				return nil, &GlobNoMatchError{Pattern: rawValueFile}
			}
			if err := verifyGlobMatchesWithinRoot(matches, resolved.EffectiveRoot); err != nil {
				return nil, fmt.Errorf("glob pattern %q: %w", rawValueFile, err)
			}
			for _, match := range matches {
				// Skip files that are also listed explicitly - they will be placed
				// at their explicit position rather than the glob's position.
				if _, isExplicit := explicitPaths[pathutil.ResolvedFilePath(match)]; !isExplicit {
					appendUnique(pathutil.ResolvedFilePath(match))
				}
			}
			continue
		}

		if !resolved.IsRemote && r.checkFileExists(resolved.Path) {
			continue
		}

		appendUnique(resolved.Path)
	}
	// Log only the count: resolved paths may point inside the randomized OCI extraction
	// directories, which must not leak the reposerver filesystem layout into logs.
	log.Infof("resolved %d value files", len(resolvedValueFiles))
	return resolvedValueFiles, nil
}

// ResolveFile resolves a single file entry (e.g. a Helm file parameter) to a local path or remote
// URL, without glob expansion or an existence check.
func (r *valueFileResolver) ResolveFile(rawValueFile string) (pathutil.ResolvedFilePath, error) {
	resolved, err := r.resolveRawPath(rawValueFile)
	if err != nil {
		return "", err
	}
	return resolved.Path, nil
}

type resolveRawPathResult struct {
	Path          pathutil.ResolvedFilePath
	IsRemote      bool
	EffectiveRoot string
}

// resolveRawPath resolves a single value file entry without expanding globs or checking for
// existence. It reports whether the path is a remote URL and the root used for the glob
// symlink-boundary check: the referenced source's directory for "$ref/..." entries, otherwise
// the main repo root.
func (r *valueFileResolver) resolveRawPath(rawValueFile string) (*resolveRawPathResult, error) {
	if root, isRef := r.refs.root(getReferencedSourceName(rawValueFile)); isRef {
		resolvedPath, err := resolveRefValueFile(rawValueFile, r.env, r.allowedValueFilesSchemas, root)
		if err != nil {
			return nil, err
		}
		return &resolveRawPathResult{Path: resolvedPath, EffectiveRoot: root}, nil
	}

	// This will resolve val to an absolute path (or a URL)
	resolvedPath, isRemote, err := pathutil.ResolveValueFilePathOrUrl(
		r.appPath,
		r.repoRoot,
		r.env.Envsubst(rawValueFile),
		r.allowedValueFilesSchemas,
	)
	if err != nil {
		return nil, err
	}

	return &resolveRawPathResult{Path: resolvedPath, IsRemote: isRemote, EffectiveRoot: r.repoRoot}, nil
}

// checkFileExists checks if a file exists and determines if it should be skipped
func (r *valueFileResolver) checkFileExists(resolvedPath pathutil.ResolvedFilePath) bool {
	_, err := os.Stat(string(resolvedPath))
	if os.IsNotExist(err) {
		if r.ignoreMissingValueFiles {
			log.Debugf(" %s values file does not exist", resolvedPath)
			return true
		}
	}
	return false
}

// getReferencedSourceName returns the "$ref" variable a value file entry starts with, or "".
func getReferencedSourceName(rawValueFile string) string {
	if !strings.HasPrefix(rawValueFile, "$") {
		return ""
	}
	refName, _, _ := strings.Cut(rawValueFile, "/")
	return refName
}

// refSourceCandidates returns the Helm value files and file parameters that may reference another
// source ("$ref/...").
func refSourceCandidates(helm *v1alpha1.ApplicationSourceHelm) []string {
	if helm == nil {
		return nil
	}
	candidates := append([]string{}, helm.ValueFiles...)
	for _, fileParam := range helm.FileParameters {
		candidates = append(candidates, fileParam.Path)
	}
	return candidates
}

// resolveRefValueFile resolves a "$ref/path" value file against root, the materialized directory
// of the referenced source. An empty root means the source is known but was not materialized.
func resolveRefValueFile(rawValueFile string, env *v1alpha1.Env, allowedValueFilesSchemas []string, root string) (pathutil.ResolvedFilePath, error) {
	refVar, refPath, _ := strings.Cut(rawValueFile, "/")
	if root == "" {
		return "", fmt.Errorf("source %q referenced by %q was not resolved", refVar, rawValueFile)
	}
	// Keep the leading slash: pathutil resolves an absolute value file against root, which also
	// stops the remainder (e.g. "$ref/https://…") from being treated as a remote URL. What remains
	// must be a real file path.
	if strings.Trim(refPath, "/") == "" {
		return "", fmt.Errorf("invalid value file path %q: no file path after the ref name", rawValueFile)
	}
	resolvedPath, _, err := pathutil.ResolveValueFilePathOrUrl(root, root, env.Envsubst("/"+refPath), allowedValueFilesSchemas)
	if err != nil {
		return "", fmt.Errorf("error resolving value file path: %w", err)
	}
	return resolvedPath, nil
}

// GlobNoMatchError is returned when a glob pattern in valueFiles matches no files.
// It is a runtime condition (the files may be added later), not a spec error.
type GlobNoMatchError struct {
	Pattern string
}

func (e *GlobNoMatchError) Error() string {
	return fmt.Sprintf("values file glob %q matched no files", e.Pattern)
}

// isGlobPath reports whether path contains any glob metacharacters
// supported by doublestar: *, ?, or [. The ** pattern is covered by *.
func isGlobPath(path string) bool {
	return strings.ContainsAny(path, "*?[")
}

// verifyGlobMatchesWithinRoot verifies that every glob match, after following symlinks, stays
// inside effectiveRoot. doublestar.FilepathGlob uses os.Lstat, so it returns the symlink itself
// (inside the repo) rather than its target; Helm would still follow the link, so an escaping
// target must be caught here. os.Root performs that check in the kernel: any path component or
// symlink target that leaves the root fails the Stat.
func verifyGlobMatchesWithinRoot(matches []string, effectiveRoot string) error {
	if len(matches) == 0 {
		return nil
	}
	root, err := os.OpenRoot(effectiveRoot)
	if err != nil {
		return fmt.Errorf("error opening repo root: %w", err)
	}
	defer root.Close()
	for _, match := range matches {
		rel, err := filepath.Rel(effectiveRoot, match)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return fmt.Errorf("glob match %q resolved to outside repository root", match)
		}
		if _, err := root.Stat(rel); err != nil {
			return fmt.Errorf("glob match %q resolved to outside repository root: %w", match, err)
		}
	}
	return nil
}
