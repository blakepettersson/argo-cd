package scheme

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/managedfields"
	"sigs.k8s.io/structured-merge-diff/v6/typed"
)

// GVKParser resolves a GroupVersionKind to its structured-merge-diff
// ParseableType. The legacy cluster cache loads the whole OpenAPI v2 document
// eagerly (EagerGVKParser); informer mode loads OpenAPI v3 per GroupVersion on
// demand (#19199).
//
// Type returns the ParseableType for the given GVK, or an error if the
// schema could not be loaded (bad CRD, network failure, conversion-webhook
// down). A nil ParseableType with a nil error means the GVK is simply not
// known to the cluster.
type GVKParser interface {
	Type(gvk schema.GroupVersionKind) (*typed.ParseableType, error)
}

// EagerGVKParser adapts a fully loaded *managedfields.GvkParser, whose Type
// never errors.
type EagerGVKParser struct {
	Parser *managedfields.GvkParser
}

func (e EagerGVKParser) Type(gvk schema.GroupVersionKind) (*typed.ParseableType, error) {
	return e.Parser.Type(gvk), nil
}
