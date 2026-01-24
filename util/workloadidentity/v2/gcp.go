// Package workloadidentity provides credential resolution for cloud provider workload identity.
//
// # GCP Workload Identity Setup
//
// This package supports GCP Workload Identity Federation for authenticating to GCP services
// (Artifact Registry, GCR) using Kubernetes service account tokens.
//
// ## Required GCP Setup
//
// 1. Create a Workload Identity Pool and OIDC provider that trusts your Kubernetes cluster:
//
//	# Create the pool
//	gcloud iam workload-identity-pools create <POOL_NAME> \
//	    --location="global" \
//	    --display-name="<DISPLAY_NAME>"
//
//	# Create an OIDC provider trusting your cluster's issuer
//	gcloud iam workload-identity-pools providers create-oidc <PROVIDER_NAME> \
//	    --location="global" \
//	    --workload-identity-pool="<POOL_NAME>" \
//	    --issuer-uri="<CLUSTER_OIDC_ISSUER>" \
//	    --attribute-mapping="google.subject=assertion.sub"
//
// For GKE, the issuer URI is:
//
//	https://container.googleapis.com/v1/projects/<PROJECT>/locations/<LOCATION>/clusters/<CLUSTER>
//
// 2. Create a GCP service account for the ArgoCD project:
//
//	gcloud iam service-accounts create argocd-project-<PROJECT_NAME>
//
// 3. Grant the federated identity permission to impersonate the GCP service account:
//
//	gcloud iam service-accounts add-iam-policy-binding \
//	    <GCP_SA>@<PROJECT>.iam.gserviceaccount.com \
//	    --role="roles/iam.workloadIdentityUser" \
//	    --member="principal://iam.googleapis.com/projects/<PROJECT_NUMBER>/locations/global/workloadIdentityPools/<POOL>/subject/system:serviceaccount:<K8S_NS>:<K8S_SA>"
//
// 4. Grant the GCP service account access to Artifact Registry:
//
//	gcloud projects add-iam-policy-binding <PROJECT> \
//	    --member="serviceAccount:<GCP_SA>@<PROJECT>.iam.gserviceaccount.com" \
//	    --role="roles/artifactregistry.reader"
//
// ## Required Kubernetes ServiceAccount Annotations
//
// The Kubernetes ServiceAccount (argocd-project-<name>) needs these annotations:
//
//   - iam.gke.io/gcp-service-account: The GCP service account email to impersonate
//   - iam.gke.io/workload-identity-provider: The full WIF provider path:
//     //iam.googleapis.com/projects/<PROJECT_NUMBER>/locations/global/workloadIdentityPools/<POOL>/providers/<PROVIDER>
//
// ## Required Repository Secret Fields
//
//   - useWorkloadIdentity: "true"
//   - workloadIdentityProvider: "gcp"
//   - project: "<argocd-project-name>" (maps to argocd-project-<name> ServiceAccount)
//
// ## Authentication Flow
//
// 1. Request a K8s token for the project ServiceAccount via TokenRequest API
// 2. Exchange the K8s token with GCP STS for a federated access token
// 3. Use the federated token to impersonate the target GCP service account
// 4. Return the access token for use with Artifact Registry/GCR
package v2

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
)

const (
	// DefaultGCPSTSURL is the default Google Cloud STS endpoint for token exchange
	DefaultGCPSTSURL = "https://sts.googleapis.com/v1/token"
	// DefaultGCPIAMCredentialsURL is the IAM Credentials API endpoint for service account impersonation
	DefaultGCPIAMCredentialsURL = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken"
	// GCPMetadataTokenURL is the GKE metadata server endpoint for getting the pod's own token
	GCPMetadataTokenURL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
	// AnnotationGCPWorkloadIdentity is the annotation key for the Workload Identity Federation provider path
	AnnotationGCPWorkloadIdentity = "iam.gke.io/workload-identity-provider"
)

// resolveGCP resolves GCP Artifact Registry/GCR credentials using Workload Identity Federation.
//
// For GKE with metadata server access, it first tries using the pod's own identity to impersonate
// the target service account. If that fails (e.g., running locally or metadata server unavailable),
// it falls back to STS token exchange using the Workload Identity Federation flow.
func (r *Resolver) resolveGCP(ctx context.Context, sa *corev1.ServiceAccount, k8sToken string, config *ProviderConfig) (*Credentials, error) {
	log.Infof("resolveGCP: SA=%s/%s, annotations=%v, config.Audience=%q", sa.Namespace, sa.Name, sa.Annotations, config.Audience)

	// Get GCP service account from standard GKE annotation
	gcpSA := sa.Annotations[AnnotationGCPSA]
	if gcpSA == "" {
		return nil, fmt.Errorf("service account %s missing %s annotation", sa.Name, AnnotationGCPSA)
	}

	log.Infof("resolveGCP: target gcpSA=%q", gcpSA)

	// Try GKE metadata server first (works for GKE Workload Identity)
	accessToken, err := r.resolveGCPViaMetadata(ctx, gcpSA)
	if err != nil {
		log.Infof("resolveGCP: metadata server approach failed: %v, trying STS", err)
		// Fall back to STS token exchange (for Workload Identity Federation)
		accessToken, err = r.resolveGCPViaSTS(ctx, sa, k8sToken, gcpSA, config)
		if err != nil {
			return nil, err
		}
	}

	// For GCR/Artifact Registry, the username is always "oauth2accesstoken"
	return &Credentials{
		Username: "oauth2accesstoken",
		Password: accessToken,
	}, nil
}

// resolveGCPViaMetadata uses the GKE metadata server to get a token, then impersonates the target SA
func (r *Resolver) resolveGCPViaMetadata(ctx context.Context, targetSA string) (string, error) {
	// Get token from metadata server (this is the pod's own GCP identity)
	req, err := http.NewRequestWithContext(ctx, "GET", GCPMetadataTokenURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create metadata request: %w", err)
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("metadata request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("metadata server returned status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode metadata response: %w", err)
	}

	log.Infof("resolveGCPViaMetadata: got token from metadata server, impersonating %s", targetSA)

	// Use this token to impersonate the target service account
	return r.impersonateServiceAccount(ctx, tokenResp.AccessToken, targetSA)
}

// resolveGCPViaSTS uses STS token exchange for Workload Identity Federation
func (r *Resolver) resolveGCPViaSTS(ctx context.Context, sa *corev1.ServiceAccount, k8sToken, gcpSA string, config *ProviderConfig) (string, error) {
	// Get the workload identity provider audience
	audience := config.Audience
	if audience == "" {
		audience = sa.Annotations[AnnotationGCPWorkloadIdentity]
	}
	if audience == "" {
		return "", fmt.Errorf("workload identity provider audience not specified: set workloadIdentityAudience in repository config or add %s annotation to service account %s", AnnotationGCPWorkloadIdentity, sa.Name)
	}

	log.Infof("resolveGCPViaSTS: using audience=%q", audience)

	// Step 1: Exchange K8s token with GCP STS for a federated token
	federatedToken, err := r.exchangeTokenWithSTS(ctx, k8sToken, audience, config.TokenURL)
	if err != nil {
		return "", fmt.Errorf("STS token exchange failed: %w", err)
	}

	// Step 2: Use federated token to impersonate the GCP service account
	return r.impersonateServiceAccount(ctx, federatedToken, gcpSA)
}

// exchangeTokenWithSTS exchanges a K8s service account token for a GCP federated access token
func (r *Resolver) exchangeTokenWithSTS(ctx context.Context, k8sToken, audience, tokenURL string) (string, error) {
	if tokenURL == "" {
		tokenURL = DefaultGCPSTSURL
	}

	log.Infof("GCP STS exchange: audience=%q, tokenURL=%q", audience, tokenURL)

	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	data.Set("subject_token", k8sToken)
	data.Set("subject_token_type", "urn:ietf:params:oauth:token-type:jwt")
	data.Set("requested_token_type", "urn:ietf:params:oauth:token-type:access_token")
	data.Set("audience", audience)
	data.Set("scope", "https://www.googleapis.com/auth/cloud-platform")

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return tokenResp.AccessToken, nil
}

// impersonateServiceAccount uses a federated token to get an access token for a GCP service account
func (r *Resolver) impersonateServiceAccount(ctx context.Context, federatedToken, serviceAccountEmail string) (string, error) {
	impersonateURL := fmt.Sprintf(DefaultGCPIAMCredentialsURL, serviceAccountEmail)

	requestBody := map[string]interface{}{
		"scope": []string{"https://www.googleapis.com/auth/cloud-platform"},
	}
	bodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", impersonateURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+federatedToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"accessToken"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return tokenResp.AccessToken, nil
}
