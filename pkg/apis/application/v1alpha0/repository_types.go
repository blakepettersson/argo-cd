package v1alpha0

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Repository is a repository holding application configurations (CRD representation)
// Note: This is the CRD type with kubebuilder markers and nested spec structure.
// The internal Repository type (flat structure) is in ../repository_types.go
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +kubebuilder:resource:path=repositories,shortName=repo;repos
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="URL",type=string,JSONPath=`.spec.url`
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.spec.type`
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.connectionState.status`
// +kubebuilder:printcolumn:name="Message",type=string,JSONPath=`.status.connectionState.message`,priority=1
// +kubebuilder:printcolumn:name="Last Attempt",type=date,JSONPath=`.status.connectionState.attemptedAt`,priority=1
// +kubebuilder:printcolumn:name="Project",type=string,JSONPath=`.spec.project`,priority=10
type Repository struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata" protobuf:"bytes,1,opt,name=metadata"`
	Spec              RepositorySpec   `json:"spec" protobuf:"bytes,2,opt,name=spec"`
	Status            RepositoryStatus `json:"status,omitempty" protobuf:"bytes,3,opt,name=status"`
}

// RepositoryList is a list of Repository resources
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type RepositoryList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata" protobuf:"bytes,1,opt,name=metadata"`
	Items           []Repository `json:"items" protobuf:"bytes,2,rep,name=items"`
}

// RepositorySpec defines the desired state of a Repository
// +kubebuilder:validation:XValidation:rule="!has(self.git) || !has(self.type) || self.type == 'git'",message="git configuration can only be set when type is 'git'"
// +kubebuilder:validation:XValidation:rule="!has(self.helm) || !has(self.type) || self.type == 'helm'",message="helm configuration can only be set when type is 'helm'"
// +kubebuilder:validation:XValidation:rule="!has(self.oci) || !has(self.type) || self.type == 'oci'",message="oci configuration can only be set when type is 'oci'"
type RepositorySpec struct {
	// URL is the URL to the repository
	// +kubebuilder:validation:Required
	URL string `json:"url" protobuf:"bytes,1,opt,name=url"`

	// Type specifies the type of the repository. Can be "git", "helm", or "oci".
	// +kubebuilder:validation:Enum=git;helm;oci
	// +kubebuilder:default=git
	// +optional
	Type string `json:"type,omitempty" protobuf:"bytes,2,opt,name=type"`

	// Project is the ArgoCD project that this repository belongs to
	// +optional
	Project string `json:"project,omitempty" protobuf:"bytes,3,opt,name=project"`

	// SecretRef is a reference to a Secret containing credentials for this repository
	// +optional
	SecretRef *SecretReference `json:"secretRef,omitempty" protobuf:"bytes,4,opt,name=secretRef"`

	// Insecure specifies whether to skip TLS certificate or SSH host key verification
	// +optional
	Insecure bool `json:"insecure,omitempty" protobuf:"varint,5,opt,name=insecure"`

	// Proxy specifies the HTTP/HTTPS proxy URL for this repository
	// +optional
	Proxy string `json:"proxy,omitempty" protobuf:"bytes,6,opt,name=proxy"`

	// NoProxy specifies a comma-separated list of hosts that should not use the proxy
	// +optional
	NoProxy string `json:"noProxy,omitempty" protobuf:"bytes,7,opt,name=noProxy"`

	// ForceHttpBasicAuth forces basic authentication for HTTP connections
	// +optional
	ForceHttpBasicAuth bool `json:"forceHttpBasicAuth,omitempty" protobuf:"varint,8,opt,name=forceHttpBasicAuth"`

	// Git contains Git-specific repository configuration
	// +optional
	Git *GitRepositoryConfig `json:"git,omitempty" protobuf:"bytes,9,opt,name=git"`

	// Helm contains Helm-specific repository configuration
	// +optional
	Helm *HelmRepositoryConfig `json:"helm,omitempty" protobuf:"bytes,10,opt,name=helm"`

	// OCI contains OCI-specific repository configuration
	// +optional
	OCI *OCIRepositoryConfig `json:"oci,omitempty" protobuf:"bytes,11,opt,name=oci"`
}

// SecretReference contains a reference to a Secret
type SecretReference struct {
	// Name is the name of the secret
	// +kubebuilder:validation:Required
	Name string `json:"name" protobuf:"bytes,1,opt,name=name"`
}

// GitRepositoryConfig contains Git-specific configuration
type GitRepositoryConfig struct {
	// EnableLFS enables Git LFS support for this repository
	// +optional
	EnableLFS bool `json:"enableLFS,omitempty" protobuf:"varint,1,opt,name=enableLFS"`

	// Depth specifies the depth for shallow clones. A value of 0 indicates a full clone.
	// +optional
	// +kubebuilder:validation:Minimum=0
	Depth int64 `json:"depth,omitempty" protobuf:"varint,2,opt,name=depth"`

	// GithubAppId specifies the ID of the GitHub app used to access the repo
	// +optional
	GithubAppId int64 `json:"githubAppID,omitempty" protobuf:"bytes,16,opt,name=githubAppID"`

	// GithubAppInstallationId specifies the installation ID of the GitHub App used to access the repo
	// +optional
	GithubAppInstallationId int64 `json:"githubAppInstallationID,omitempty" protobuf:"bytes,17,opt,name=githubAppInstallationID"`

	// GithubAppEnterpriseBaseURL specifies the base URL of GitHub Enterprise installation. If empty will default to https://api.github.com
	// +optional
	GitHubAppEnterpriseBaseURL string `json:"githubAppEnterpriseBaseUrl,omitempty" protobuf:"bytes,18,opt,name=githubAppEnterpriseBaseUrl"`
}

// HelmRepositoryConfig contains Helm-specific configuration
type HelmRepositoryConfig struct {
	// Name is the name of the Helm repository
	// +optional
	Name string `json:"name,omitempty" protobuf:"bytes,1,opt,name=name"`

	// EnableOCI enables OCI support for Helm charts
	// +optional
	EnableOCI bool `json:"enableOCI,omitempty" protobuf:"varint,2,opt,name=enableOCI"`
}

// OCIRepositoryConfig contains OCI-specific configuration
type OCIRepositoryConfig struct {
	// InsecureSkipTLS skips TLS verification entirely (forces HTTP instead of HTTPS)
	// +optional
	InsecureSkipTLS bool `json:"insecureSkipTLS,omitempty" protobuf:"varint,1,opt,name=insecureSkipTLS"`
}

// RepositoryStatus defines the observed state of a Repository
type RepositoryStatus struct {
	// ConnectionState contains the aggregate connection state across all clusters
	// +optional
	ConnectionState *AggregateConnectionState `json:"connectionState,omitempty" protobuf:"bytes,1,opt,name=connectionState"`

	// ClusterConnectionStates contains per-cluster connection states.
	// Each controlplane manages its own entry using its name as the field manager.
	// +optional
	// +listType=map
	// +listMapKey=name
	ClusterConnectionStates []ClusterConnectionState `json:"clusterConnectionStates,omitempty" protobuf:"bytes,2,rep,name=clusterConnectionStates"`

	// Conditions represents the latest available observations of the repository's state
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" protobuf:"bytes,3,rep,name=conditions"`
}

// AggregateConnectionState represents the overall connection state across all clusters
type AggregateConnectionState struct {
	// Status is the connection status (Successful, Failed, Degraded, Unknown)
	// +kubebuilder:validation:Enum=Successful;Failed;Degraded;Unknown
	Status ConnectionStatus `json:"status" protobuf:"bytes,1,opt,name=status"`

	// Message contains human-readable information about the connection status
	// +optional
	Message string `json:"message,omitempty" protobuf:"bytes,2,opt,name=message"`

	// AttemptedAt is the timestamp of the last connection attempt
	// +optional
	AttemptedAt *metav1.Time `json:"attemptedAt,omitempty" protobuf:"bytes,3,opt,name=attemptedAt"`

	// TotalClusters is the total number of clusters managing this repository
	// +optional
	TotalClusters int32 `json:"totalClusters,omitempty" protobuf:"varint,4,opt,name=totalClusters"`

	// SuccessfulClusters is the number of clusters that successfully connected
	// +optional
	SuccessfulClusters int32 `json:"successfulClusters,omitempty" protobuf:"varint,5,opt,name=successfulClusters"`

	// FailedClusters is the number of clusters that failed to connect
	// +optional
	FailedClusters int32 `json:"failedClusters,omitempty" protobuf:"varint,6,opt,name=failedClusters"`
}

// ClusterConnectionState represents the connection state for a specific cluster/controlplane
type ClusterConnectionState struct {
	// Name is the name of the cluster or controlplane (e.g., "argocd-application-controller")
	// +kubebuilder:validation:Required
	Name string `json:"name" protobuf:"bytes,1,opt,name=name"`

	// ConnectionState is the connection state for this cluster
	// +kubebuilder:validation:Required
	ConnectionState ClusterConnectionStateDetail `json:"connectionState" protobuf:"bytes,2,opt,name=connectionState"`
}

// ClusterConnectionStateDetail represents the connection state details for a cluster
type ClusterConnectionStateDetail struct {
	// Status is the connection status
	// +kubebuilder:validation:Enum=Successful;Failed;Unknown
	Status ConnectionStatus `json:"status" protobuf:"bytes,1,opt,name=status"`

	// Message contains details about the connection status
	// +optional
	Message string `json:"message,omitempty" protobuf:"bytes,2,opt,name=message"`

	// AttemptedAt is the timestamp of the last connection attempt
	// +optional
	AttemptedAt *metav1.Time `json:"attemptedAt,omitempty" protobuf:"bytes,3,opt,name=attemptedAt"`
}

// ConnectionStatus is the status of a connection attempt
type ConnectionStatus string

const (
	// ConnectionStatusSuccessful indicates the repository connection succeeded
	ConnectionStatusSuccessful ConnectionStatus = "Successful"
	// ConnectionStatusFailed indicates the repository connection failed
	ConnectionStatusFailed ConnectionStatus = "Failed"
	// ConnectionStatusDegraded indicates mixed results across clusters (some succeeded, some failed)
	ConnectionStatusDegraded ConnectionStatus = "Degraded"
	// ConnectionStatusUnknown indicates the connection status is not yet known
	ConnectionStatusUnknown ConnectionStatus = "Unknown"
)

// RepositoryConditionType represents the type of repository condition
type RepositoryConditionType string

const (
	// RepositoryConditionReady indicates the repository is ready for use
	RepositoryConditionReady RepositoryConditionType = "Ready"
)

// Repository condition reasons
const (
	// ReasonConnectionSuccessful indicates all clusters connected successfully
	ReasonConnectionSuccessful = "ConnectionSuccessful"
	// ReasonConnectionFailed indicates all clusters failed to connect
	ReasonConnectionFailed = "ConnectionFailed"
	// ReasonConnectionFailedInSomeClusters indicates some clusters failed to connect
	ReasonConnectionFailedInSomeClusters = "ConnectionFailedInSomeClusters"
	// ReasonCredentialsValid indicates credentials were verified successfully
	ReasonCredentialsValid = "CredentialsValid"
	// ReasonCredentialsInvalid indicates authentication failed
	ReasonCredentialsInvalid = "CredentialsInvalid"
	// ReasonCredentialsMissing indicates the referenced secret was not found
	ReasonCredentialsMissing = "CredentialsMissing"
)

// Repository event reasons (for Kubernetes events)
const (
	// EventReasonRepositoryCreated is emitted when a new repository is registered
	EventReasonRepositoryCreated = "RepositoryCreated"
	// EventReasonRepositoryUpdated is emitted when a repository specification changes
	EventReasonRepositoryUpdated = "RepositoryUpdated"
	// EventReasonConnectionSuccessful is emitted when the repository becomes accessible
	EventReasonConnectionSuccessful = "ConnectionSuccessful"
	// EventReasonConnectionFailed is emitted when the repository cannot be connected
	EventReasonConnectionFailed = "ConnectionFailed"
	// EventReasonConnectionRecovered is emitted when connection is restored after failure
	EventReasonConnectionRecovered = "ConnectionRecovered"
	// EventReasonCredentialsValid is emitted when credentials are verified
	EventReasonCredentialsValid = "CredentialsValid"
	// EventReasonCredentialsInvalid is emitted when authentication fails
	EventReasonCredentialsInvalid = "CredentialsInvalid"
	// EventReasonCredentialsUpdated is emitted when a secret reference changes
	EventReasonCredentialsUpdated = "CredentialsUpdated"
	// EventReasonCredentialsMissing is emitted when the referenced secret is not found
	EventReasonCredentialsMissing = "CredentialsMissing"
)

// RepositoryCredential holds repository credential templates (CRD representation)
// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +kubebuilder:resource:path=repositorycredentials,shortName=repocreds
// +kubebuilder:printcolumn:name="URL Pattern",type=string,JSONPath=`.spec.url`
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.spec.type`
type RepositoryCredential struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata" protobuf:"bytes,1,opt,name=metadata"`
	Spec              RepositoryCredentialSpec `json:"spec" protobuf:"bytes,2,opt,name=spec"`
}

// RepositoryCredentialList is a list of RepositoryCredential resources
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type RepositoryCredentialList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata" protobuf:"bytes,1,opt,name=metadata"`
	Items           []RepositoryCredential `json:"items" protobuf:"bytes,2,rep,name=items"`
}

// RepositoryCredentialSpec defines the desired state of RepositoryCredential
// +kubebuilder:validation:XValidation:rule="!has(self.git) || !has(self.type) || self.type == 'git'",message="git configuration can only be set when type is 'git'"
// +kubebuilder:validation:XValidation:rule="!has(self.helm) || !has(self.type) || self.type == 'helm'",message="helm configuration can only be set when type is 'helm'"
// +kubebuilder:validation:XValidation:rule="!has(self.oci) || !has(self.type) || self.type == 'oci'",message="oci configuration can only be set when type is 'oci'"
type RepositoryCredentialSpec struct {
	// URL is the URL pattern that these credentials match
	// +kubebuilder:validation:Required
	URL string `json:"url" protobuf:"bytes,1,opt,name=url"`

	// Type specifies the type of the repository credentials. Can be "git", "helm", or "oci".
	// +kubebuilder:validation:Enum=git;helm;oci
	// +kubebuilder:default=git
	// +optional
	Type string `json:"type,omitempty" protobuf:"bytes,2,opt,name=type"`

	// SecretRef is a reference to a Secret containing credentials
	// +optional
	SecretRef *SecretReference `json:"secretRef,omitempty" protobuf:"bytes,3,opt,name=secretRef"`

	// Insecure specifies whether to skip TLS certificate or SSH host key verification
	// +optional
	Insecure bool `json:"insecure,omitempty" protobuf:"varint,4,opt,name=insecure"`

	// Proxy specifies the HTTP/HTTPS proxy URL for this repository
	// +optional
	Proxy string `json:"proxy,omitempty" protobuf:"bytes,5,opt,name=proxy"`

	// NoProxy specifies a comma-separated list of hosts that should not use the proxy
	// +optional
	NoProxy string `json:"noProxy,omitempty" protobuf:"bytes,6,opt,name=noProxy"`

	// ForceHttpBasicAuth forces basic authentication for HTTP connections
	// +optional
	ForceHttpBasicAuth bool `json:"forceHttpBasicAuth,omitempty" protobuf:"varint,7,opt,name=forceHttpBasicAuth"`

	// Git contains Git-specific repository configuration
	// +optional
	Git *GitRepositoryConfig `json:"git,omitempty" protobuf:"bytes,8,opt,name=git"`

	// Helm contains Helm-specific repository configuration
	// +optional
	Helm *HelmRepositoryConfig `json:"helm,omitempty" protobuf:"bytes,9,opt,name=helm"`

	// OCI contains OCI-specific repository configuration
	// +optional
	OCI *OCIRepositoryConfig `json:"oci,omitempty" protobuf:"bytes,10,opt,name=oci"`
}
