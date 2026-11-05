package kube

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime/schema"
	openapiclient "k8s.io/client-go/openapi"
	"k8s.io/klog/v2/textlogger"
	"k8s.io/kube-openapi/pkg/util/proto"
)

func TestGvPathForGVK(t *testing.T) {
	tests := []struct {
		name     string
		gvk      schema.GroupVersionKind
		expected string
	}{
		{
			name:     "core group",
			gvk:      schema.GroupVersionKind{Group: "", Version: "v1", Kind: "ConfigMap"},
			expected: "api/v1",
		},
		{
			name:     "named group",
			gvk:      schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"},
			expected: "apis/apps/v1",
		},
		{
			name:     "subdomain group",
			gvk:      schema.GroupVersionKind{Group: "visibility.kueue.x-k8s.io", Version: "v1beta1", Kind: "ClusterQueue"},
			expected: "apis/visibility.kueue.x-k8s.io/v1beta1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, gvPathForGVK(tt.gvk))
		})
	}
}

func TestLazyGVKParser_UnknownGV(t *testing.T) {
	// A GVK whose GroupVersion isn't in paths returns (nil, nil) without any
	// network call.
	paths := map[string]openapiclient.GroupVersion{
		"api/v1": &fakeGroupVersion{schemaBytes: validCoreV1Schema},
	}
	parser := newLazyGVKParser(paths, textlogger.NewLogger(textlogger.NewConfig()))

	result, err := parser.Type(schema.GroupVersionKind{Group: "nonexistent.io", Version: "v1", Kind: "Foo"})
	assert.Nil(t, result, "unknown GV should return nil")
	assert.NoError(t, err, "unknown GV should not return an error")
}

func TestLazyGVKParser_CachesPerGV(t *testing.T) {
	// After fetching a GV once, subsequent Type() calls for the same GV use
	// the cached parser (no re-fetch).
	callCount := atomic.Int32{}
	paths := map[string]openapiclient.GroupVersion{
		"api/v1": &countingFakeGroupVersion{
			inner:     &fakeGroupVersion{schemaBytes: validCoreV1Schema},
			callCount: &callCount,
		},
	}
	parser := newLazyGVKParser(paths, textlogger.NewLogger(textlogger.NewConfig()))

	cm, err := parser.Type(schema.GroupVersionKind{Group: "", Version: "v1", Kind: "ConfigMap"})
	require.NoError(t, err)
	require.NotNil(t, cm)
	assert.Equal(t, int32(1), callCount.Load(), "should have fetched once")

	// A different kind in the same GV should use the cache.
	_, err = parser.Type(schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"})
	require.NoError(t, err)
	assert.Equal(t, int32(1), callCount.Load(), "should still be one fetch (cached)")
}

func TestLazyGVKParser_LookupResource(t *testing.T) {
	// LookupResource serves strategic-merge patch meta, cached per
	// GroupVersion apart from Type's parser.
	callCount := atomic.Int32{}
	paths := map[string]openapiclient.GroupVersion{
		"api/v1": &countingFakeGroupVersion{
			inner:     &fakeGroupVersion{schemaBytes: validCoreV1Schema},
			callCount: &callCount,
		},
		"apis/unavailable.io/v1": &fakeGroupVersion{err: errors.New("connection refused")},
	}
	parser := newLazyGVKParser(paths, textlogger.NewLogger(textlogger.NewConfig()))

	cm := parser.LookupResource(schema.GroupVersionKind{Version: "v1", Kind: "ConfigMap"})
	require.NotNil(t, cm)
	kind, ok := cm.(*proto.Kind)
	require.True(t, ok, "got %T", cm)
	assert.Contains(t, kind.Fields, "data")

	require.NotNil(t, parser.LookupResource(schema.GroupVersionKind{Version: "v1", Kind: "ConfigMap"}))
	assert.Equal(t, int32(1), callCount.Load(), "models are cached")

	// Type keeps its own, smaller cache entry.
	for range 2 {
		_, err := parser.Type(schema.GroupVersionKind{Version: "v1", Kind: "ConfigMap"})
		require.NoError(t, err)
	}
	assert.Equal(t, int32(2), callCount.Load(), "parser is cached separately")

	assert.Nil(t, parser.LookupResource(schema.GroupVersionKind{Version: "v1", Kind: "Missing"}))
	assert.Nil(t, parser.LookupResource(schema.GroupVersionKind{Group: "nope.io", Version: "v1", Kind: "X"}))
	assert.Nil(t, parser.LookupResource(schema.GroupVersionKind{Group: "unavailable.io", Version: "v1", Kind: "X"}))
}

func TestLazyGVKParser_ConcurrentAccess(t *testing.T) {
	// Many goroutines requesting the same GV result in a single fetch thanks
	// to singleflight.
	callCount := atomic.Int32{}
	paths := map[string]openapiclient.GroupVersion{
		"api/v1": &countingFakeGroupVersion{
			inner:     &fakeGroupVersion{schemaBytes: validCoreV1Schema},
			callCount: &callCount,
		},
	}
	parser := newLazyGVKParser(paths, textlogger.NewLogger(textlogger.NewConfig()))

	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			_, _ = parser.Type(schema.GroupVersionKind{Group: "", Version: "v1", Kind: "ConfigMap"})
		})
	}
	wg.Wait()

	// A final resolve confirms the cached parser is usable, and that the
	// concurrent burst above triggered exactly one fetch.
	result, err := parser.Type(schema.GroupVersionKind{Group: "", Version: "v1", Kind: "ConfigMap"})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, int32(1), callCount.Load(), "concurrent requests for the same GV should result in a single fetch")
}

func TestLazyGVKParser_FetchFailureCached(t *testing.T) {
	// A failed fetch is cached — subsequent calls return the same error without
	// retrying. The cache is discarded when the cluster cache rebuilds a fresh
	// lazyGVKParser (e.g. on a CRD change).
	callCount := atomic.Int32{}
	paths := map[string]openapiclient.GroupVersion{
		"api/v1": &retryableFakeGroupVersion{
			schemas: []schemaResult{
				{err: assert.AnError},     // first call fails
				{data: validCoreV1Schema}, // would succeed if retried
			},
			callCount: &callCount,
		},
	}
	parser := newLazyGVKParser(paths, textlogger.NewLogger(textlogger.NewConfig()))

	result, err := parser.Type(schema.GroupVersionKind{Group: "", Version: "v1", Kind: "ConfigMap"})
	assert.Nil(t, result, "should return nil on fetch failure")
	require.Error(t, err, "should return error on fetch failure")
	assert.Equal(t, int32(1), callCount.Load())

	result, err = parser.Type(schema.GroupVersionKind{Group: "", Version: "v1", Kind: "ConfigMap"})
	assert.Nil(t, result, "should return nil from cached error")
	require.Error(t, err, "should return cached error")
	assert.Equal(t, int32(1), callCount.Load(), "should NOT have retried")
}

func TestLazyGVKParser_BadSchemaDoesNotAffectOtherGVs(t *testing.T) {
	// The key win of per-GroupVersion lazy loading: a broken schema in one GV
	// is isolated to that GV. In the eager v2 path a single dangling $ref (the
	// Kueue visibility bug, kubernetes-sigs/kueue#8873) poisons the whole
	// cluster's schema load, breaking diffs for unrelated apps.
	paths := map[string]openapiclient.GroupVersion{
		"api/v1":                                 &fakeGroupVersion{schemaBytes: validCoreV1Schema},
		"apis/visibility.kueue.x-k8s.io/v1beta1": &fakeGroupVersion{schemaBytes: badCRDSchema},
		"apis/broken.example.io/v1":              &fakeGroupVersion{schemaBytes: []byte(`not valid json at all`)},
		"apis/unavailable.io/v1beta1":            &fakeGroupVersion{err: errors.New("connection refused")},
	}
	parser := newLazyGVKParser(paths, textlogger.NewLogger(textlogger.NewConfig()))

	// The valid GV resolves fine despite the broken siblings.
	cmType, err := parser.Type(schema.GroupVersionKind{Group: "", Version: "v1", Kind: "ConfigMap"})
	require.NoError(t, err)
	assert.NotNil(t, cmType, "ConfigMap should resolve from the valid GV")

	// Dangling $ref → error, scoped to that GV.
	badType, err := parser.Type(schema.GroupVersionKind{Group: "visibility.kueue.x-k8s.io", Version: "v1beta1", Kind: "PendingWorkloadsSummary"})
	assert.Nil(t, badType)
	require.Error(t, err, "bad CRD schema should return an error")

	// Unparseable bytes → error, scoped to that GV.
	garbageType, err := parser.Type(schema.GroupVersionKind{Group: "broken.example.io", Version: "v1", Kind: "Foo"})
	assert.Nil(t, garbageType)
	require.Error(t, err, "garbage bytes should return an error")

	// Fetch failure (e.g. aggregated API / conversion webhook down) → error,
	// scoped to that GV.
	unavailableType, err := parser.Type(schema.GroupVersionKind{Group: "unavailable.io", Version: "v1beta1", Kind: "Foo"})
	assert.Nil(t, unavailableType)
	require.Error(t, err, "fetch failure should return an error")
}

// fakeGroupVersion implements openapiclient.GroupVersion for testing.
type fakeGroupVersion struct {
	schemaBytes []byte
	err         error
}

func (f *fakeGroupVersion) Schema(_ string) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.schemaBytes, nil
}

func (f *fakeGroupVersion) ServerRelativeURL() string {
	return ""
}

// countingFakeGroupVersion wraps a fakeGroupVersion and counts Schema calls.
type countingFakeGroupVersion struct {
	inner     *fakeGroupVersion
	callCount *atomic.Int32
}

func (f *countingFakeGroupVersion) Schema(contentType string) ([]byte, error) {
	f.callCount.Add(1)
	return f.inner.Schema(contentType)
}

func (f *countingFakeGroupVersion) ServerRelativeURL() string {
	return ""
}

// schemaResult represents one call's return value.
type schemaResult struct {
	data []byte
	err  error
}

// retryableFakeGroupVersion returns different results on successive calls, so a
// test can assert that a cached failure is not retried.
type retryableFakeGroupVersion struct {
	schemas   []schemaResult
	callCount *atomic.Int32
}

func (f *retryableFakeGroupVersion) Schema(_ string) ([]byte, error) {
	idx := int(f.callCount.Add(1)) - 1
	if idx >= len(f.schemas) {
		idx = len(f.schemas) - 1
	}
	return f.schemas[idx].data, f.schemas[idx].err
}

func (f *retryableFakeGroupVersion) ServerRelativeURL() string {
	return ""
}

// validCoreV1Schema is a minimal OpenAPI v3 schema for core/v1 ConfigMap.
var validCoreV1Schema = []byte(`{
  "openapi": "3.0.0",
  "info": {"title": "Kubernetes", "version": "v1.30.0"},
  "paths": {},
  "components": {
    "schemas": {
      "io.k8s.api.core.v1.ConfigMap": {
        "type": "object",
        "x-kubernetes-group-version-kind": [
          {"group": "", "kind": "ConfigMap", "version": "v1"}
        ],
        "properties": {
          "apiVersion": {"type": "string"},
          "kind": {"type": "string"},
          "metadata": {"type": "object"},
          "data": {
            "type": "object",
            "additionalProperties": {"type": "string"}
          }
        }
      }
    }
  }
}`)

// badCRDSchema simulates the Kueue visibility API bug (kubernetes-sigs/kueue#8873):
// a schema with a $ref pointing to a model that doesn't exist in the document.
// In v2 this kind of broken schema poisons the entire cluster's OpenAPI parsing.
var badCRDSchema = []byte(`{
  "openapi": "3.0.0",
  "info": {"title": "Kueue Visibility", "version": "v0.16.0"},
  "paths": {},
  "components": {
    "schemas": {
      "io.x-k8s.sigs.kueue.visibility.v1beta1.PendingWorkloadsSummary": {
        "type": "object",
        "x-kubernetes-group-version-kind": [
          {"group": "visibility.kueue.x-k8s.io", "kind": "PendingWorkloadsSummary", "version": "v1beta1"}
        ],
        "properties": {
          "items": {
            "type": "array",
            "items": {
              "$ref": "#/components/schemas/io.x-k8s.sigs.kueue.visibility.v1beta1.PendingWorkload"
            }
          }
        }
      }
    }
  }
}`)
