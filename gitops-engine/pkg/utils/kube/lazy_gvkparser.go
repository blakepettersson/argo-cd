package kube

import (
	"fmt"
	"sync"

	"github.com/go-logr/logr"
	openapi_v3 "github.com/google/gnostic-models/openapiv3"
	"golang.org/x/sync/singleflight"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/managedfields"
	openapiclient "k8s.io/client-go/openapi"
	"k8s.io/kube-openapi/pkg/util/proto"
	"k8s.io/kubectl/pkg/util/openapi"
	"sigs.k8s.io/structured-merge-diff/v6/typed"

	"github.com/argoproj/argo-cd/gitops-engine/v3/pkg/utils/kube/scheme"
)

var (
	_ scheme.GVKParser  = (*lazyGVKParser)(nil)
	_ openapi.Resources = (*lazyGVKParser)(nil)
)

// gvResult caches the outcome of loading a single GroupVersion's schema. Both
// the parser and the error are cached so a persistently failing GroupVersion
// (e.g. a bad CRD or a conversion webhook that is down) is not re-fetched on
// every Type() call — it fails fast from cache until the next reload rebuilds
// the parser with fresh paths. A reload carries over successful results whose
// ServerRelativeURL (it includes ?hash=) is unchanged.
//
// Type and LookupResource cache separately: the proto models LookupResource
// needs are ~2x the parser's size and only RespectIgnoreDifferences on CRDs
// asks for them, so a GroupVersion used by both is fetched twice instead.
type gvResult struct {
	parser *managedfields.GvkParser           // Type
	models proto.Models                       // LookupResource
	kinds  map[schema.GroupVersionKind]string // LookupResource: GVK -> model name
	err    error
	// path and url (ServerRelativeURL, includes ?hash=) let a reload decide
	// whether the result is still current.
	path, url string
}

const (
	parserKey = "parser:"
	modelsKey = "models:"
)

// lazyGVKParser implements scheme.GVKParser by loading OpenAPI v3 schemas
// per-GroupVersion on demand. Rather than fetching and parsing the whole
// cluster schema upfront (the eager v2 path, scheme.EagerGVKParser), it starts from
// the cheap list of GroupVersion paths returned by the v3 discovery endpoint
// and fetches a GroupVersion's schema only the first time Type() is called for
// a GVK in that GroupVersion. Parsed results are cached for later calls.
//
// This is the parser used by the informer-based cluster cache (ModeInformer);
// the legacy engine keeps the eager v2 parser. See issue #19199.
type lazyGVKParser struct {
	// paths is the immutable GroupVersion->client map captured at construction
	// from a single OpenAPIV3().Paths() call. A reload builds a fresh parser
	// with a fresh paths map rather than mutating this one, so it needs no
	// lock.
	paths map[string]openapiclient.GroupVersion
	log   logr.Logger

	// sf collapses concurrent first-time loads of the same GroupVersion into a
	// single fetch+parse; parsers caches results keyed by parserKey/modelsKey
	// plus the v3 path.
	sf      singleflight.Group
	parsers sync.Map // map[string]*gvResult
}

// newLazyGVKParser creates a lazy parser from the already-fetched GroupVersion
// paths. The paths map comes from a single cheap OpenAPIV3().Paths() call.
// Successful results from prev (may be nil) whose GroupVersion hash is
// unchanged are reused, so a CRD event doesn't drop every loaded schema.
func newLazyGVKParser(paths map[string]openapiclient.GroupVersion, log logr.Logger, prev *lazyGVKParser) *lazyGVKParser {
	p := &lazyGVKParser{
		paths: paths,
		log:   log,
	}
	if prev == nil {
		return p
	}
	prev.parsers.Range(func(k, v any) bool {
		r := v.(*gvResult)
		if gv, ok := paths[r.path]; ok && r.err == nil && r.url != "" && gv.ServerRelativeURL() == r.url {
			p.parsers.Store(k, r)
		}
		return true
	})
	return p
}

// Type resolves a GVK to its ParseableType, lazily loading the schema for the
// GVK's GroupVersion on first access. It returns an error if the schema could
// not be loaded (bad CRD, network failure); the error is cached so it does not
// retry on every call. A nil ParseableType with a nil error means the GVK is
// not known to the cluster.
func (p *lazyGVKParser) Type(gvk schema.GroupVersionKind) (*typed.ParseableType, error) {
	path := gvPathForGVK(gvk)

	// The GroupVersion isn't served by this cluster — nothing to load.
	if _, ok := p.paths[path]; !ok {
		return nil, nil
	}

	r := p.load(parserKey, path)
	if r.err != nil {
		return nil, r.err
	}
	return r.parser.Type(gvk), nil
}

// LookupResource implements openapi.Resources, loading per GroupVersion like
// Type. A load failure is logged by load and reported as unknown,
// matching the eager v2 document's nil for GVKs it doesn't have.
func (p *lazyGVKParser) LookupResource(gvk schema.GroupVersionKind) proto.Schema {
	path := gvPathForGVK(gvk)
	if _, ok := p.paths[path]; !ok {
		return nil
	}
	r := p.load(modelsKey, path)
	if r.err != nil {
		return nil
	}
	name, ok := r.kinds[gvk]
	if !ok {
		return nil
	}
	return r.models.LookupModel(name)
}

// GetConsumes implements openapi.Resources. Argo CD never calls it.
func (p *lazyGVKParser) GetConsumes(schema.GroupVersionKind, string) []string {
	return nil
}

// load returns the cached parserKey or modelsKey result for a GroupVersion
// path, fetching it on first use. singleflight collapses concurrent loads.
func (p *lazyGVKParser) load(kind, path string) *gvResult {
	key := kind + path
	if cached, ok := p.parsers.Load(key); ok {
		return cached.(*gvResult)
	}
	result, _, _ := p.sf.Do(key, func() (any, error) {
		if cached, ok := p.parsers.Load(key); ok {
			return cached, nil
		}
		r := p.loadGV(path, kind == modelsKey)
		r.path, r.url = path, p.paths[path].ServerRelativeURL()
		if r.err != nil {
			p.log.Info("Failed to load OpenAPI v3 schema for GroupVersion, skipping", "path", path, "error", r.err)
		}
		p.parsers.Store(key, r)
		// nil error so singleflight hands the cached result to every waiter.
		return r, nil
	})
	return result.(*gvResult)
}

// loadGV fetches and parses a single GroupVersion, returning either its
// GvkParser or (wantModels) its proto models indexed by GVK.
func (p *lazyGVKParser) loadGV(path string, wantModels bool) *gvResult {
	gv, ok := p.paths[path]
	if !ok {
		return &gvResult{err: fmt.Errorf("unknown path: %s", path)}
	}

	jsonBytes, err := gv.Schema("application/json")
	if err != nil {
		return &gvResult{err: fmt.Errorf("failed to get schema: %w", err)}
	}

	doc, err := openapi_v3.ParseDocument(jsonBytes)
	if err != nil {
		return &gvResult{err: fmt.Errorf("failed to parse document: %w", err)}
	}

	models, err := proto.NewOpenAPIV3Data(doc)
	if err != nil {
		return &gvResult{err: fmt.Errorf("failed to convert to models: %w", err)}
	}

	// The v3 proto path produces map[string]any for nested extension values,
	// but managedfields.NewGVKParser (and the schema converter) expect
	// map[any]any — which is what the v2 proto path produces. Normalize in
	// place so the x-kubernetes-group-version-kind / x-kubernetes-unions
	// extensions parse correctly.
	normalizeV3Extensions(models)

	if wantModels {
		kinds := map[schema.GroupVersionKind]string{}
		for _, name := range models.ListModels() {
			for _, gvk := range modelGVKs(models.LookupModel(name)) {
				kinds[gvk] = name
			}
		}
		return &gvResult{models: models, kinds: kinds}
	}
	parser, err := managedfields.NewGVKParser(models, false)
	if err != nil {
		return &gvResult{err: fmt.Errorf("failed to create GVK parser: %w", err)}
	}
	return &gvResult{parser: parser}
}

// modelGVKs reads x-kubernetes-group-version-kind off a model, after
// normalizeV3Extensions has turned its maps into map[any]any.
func modelGVKs(m proto.Schema) []schema.GroupVersionKind {
	if m == nil {
		return nil
	}
	list, _ := m.GetExtensions()["x-kubernetes-group-version-kind"].([]any)
	gvks := make([]schema.GroupVersionKind, 0, len(list))
	for _, item := range list {
		e, ok := item.(map[any]any)
		if !ok {
			continue
		}
		group, _ := e["group"].(string)
		version, _ := e["version"].(string)
		kind, _ := e["kind"].(string)
		if kind != "" {
			gvks = append(gvks, schema.GroupVersionKind{Group: group, Version: version, Kind: kind})
		}
	}
	return gvks
}

// gvPathForGVK derives the OpenAPI v3 discovery path for a GroupVersionKind.
// The core group (empty group) maps to "api/{version}"; named groups map to
// "apis/{group}/{version}". These match the keys returned by
// OpenAPIV3().Paths().
func gvPathForGVK(gvk schema.GroupVersionKind) string {
	if gvk.Group == "" {
		return "api/" + gvk.Version
	}
	return "apis/" + gvk.Group + "/" + gvk.Version
}

// normalizeV3Extensions fixes a compatibility issue between OpenAPI v3 proto
// models and managedfields.NewGVKParser. The v3 path (proto.NewOpenAPIV3Data)
// produces map[string]any for nested values in schema extensions like
// x-kubernetes-group-version-kind and x-kubernetes-unions, whereas the
// upstream GVK parser and schema converter expect map[any]any (what the v2
// proto path produces). This normalizes all extension values in place.
func normalizeV3Extensions(models proto.Models) {
	for _, name := range models.ListModels() {
		m := models.LookupModel(name)
		if m == nil {
			continue
		}
		exts := m.GetExtensions()
		for key, val := range exts {
			exts[key] = deepConvertStringKeysToAny(val)
		}
	}
}

// deepConvertStringKeysToAny recursively converts map[string]any to map[any]any
// within a value tree.
func deepConvertStringKeysToAny(v any) any {
	switch val := v.(type) {
	case map[string]any:
		result := make(map[any]any, len(val))
		for k, v := range val {
			result[k] = deepConvertStringKeysToAny(v)
		}
		return result
	case []any:
		for i, item := range val {
			val[i] = deepConvertStringKeysToAny(item)
		}
		return val
	default:
		return v
	}
}
