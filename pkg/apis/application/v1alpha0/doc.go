// Package v1alpha0 contains the v1alpha0 version of Repository CRD types.
// This package is separate from v1alpha1 to avoid name collisions with internal Repository types.
// The v1alpha0 designation indicates this is a parallel API representation (CRD schema)
// rather than an evolution of the v1alpha1 API.
//
// +k8s:deepcopy-gen=package,register
// +groupName=argoproj.io
package v1alpha0