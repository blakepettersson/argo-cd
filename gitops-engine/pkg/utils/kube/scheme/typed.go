package scheme

import (
	"strings"
	"sync"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/structured-merge-diff/v6/typed"
)

// ResolveParseableType returns a ParseableType for the given GVK. For k8s
// built-in types it uses the statically defined embedded schema regardless
// of which GVKParser implementation is supplied — this keeps SSA diffs
// stable across schema sources. CRDs fall through to the parser.
//
// Returns DeducedParseableType (not suitable for calculating diffs) when
// parser is nil. Returns an error when the parser fails to load the schema
// (bad CRD, network failure, reported watch error). A nil ParseableType
// with a nil error means the GVK is not known.
func ResolveParseableType(gvk schema.GroupVersionKind, parser GVKParser) (*typed.ParseableType, error) {
	if parser == nil {
		return &typed.DeducedParseableType, nil
	}
	if pt := resolveFromStaticParser(gvk); pt != nil {
		return pt, nil
	}
	return parser.Type(gvk)
}

func resolveFromStaticParser(gvk schema.GroupVersionKind) *typed.ParseableType {
	name := getSchemeModelName(gvk)
	if name == "" {
		return nil
	}
	p := StaticParser()
	if p == nil {
		return nil
	}
	pt := p.Type(name)
	if pt.IsValid() {
		return &pt
	}
	return nil
}

var (
	schemeModelNames     map[schema.GroupVersionKind]string
	schemeModelNamesOnce sync.Once
)

// getSchemeModelName derives the OpenAPI model name for a built-in GVK from
// the k8s type registry. This replaces the prior reflection-based extraction
// from the concrete *managedfields.GvkParser (which assumed a specific
// internal field layout); deriving names from the scheme works for any
// GVKParser implementation.
func getSchemeModelName(gvk schema.GroupVersionKind) string {
	schemeModelNamesOnce.Do(func() {
		schemeModelNames = buildSchemeModelNames()
	})
	return schemeModelNames[gvk]
}

// buildSchemeModelNames builds a GVK → OpenAPI model name map from every
// external type registered in the scheme. Mapping convention:
// k8s.io/api/apps/v1.Deployment → io.k8s.api.apps.v1.Deployment.
func buildSchemeModelNames() map[schema.GroupVersionKind]string {
	results := make(map[schema.GroupVersionKind]string)
	for gvk, t := range Scheme.AllKnownTypes() {
		pkgPath := t.PkgPath()
		if !strings.HasPrefix(pkgPath, "k8s.io/api/") {
			continue
		}
		modelName := strings.Replace(pkgPath, "k8s.io/", "io.k8s.", 1)
		modelName = strings.ReplaceAll(modelName, "/", ".")
		modelName += "." + t.Name()
		results[gvk] = modelName
	}
	return results
}
