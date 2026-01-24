package v2

// # Azure Workload Identity Setup
//
// This file implements Azure Workload Identity Federation for authenticating to Azure Container
// Registry (ACR) using Kubernetes service account tokens.
//
// ## Required Azure Setup
//
// 1. Set environment variables:
//
//	export AZURE_SUBSCRIPTION_ID=$(az account show --query id -o tsv)
//	export AZURE_TENANT_ID=$(az account show --query tenantId -o tsv)
//	export RESOURCE_GROUP="<your-resource-group>"
//	export ACR_NAME="<your-acr-name>"
//	export ARGOCD_NAMESPACE="argocd"
//	export PROJECT_NAME="default"
//
// 2. Get your cluster's OIDC issuer URL (for AKS):
//
//	export OIDC_ISSUER=$(az aks show --resource-group $RESOURCE_GROUP \
//	    --name $CLUSTER_NAME --query "oidcIssuerProfile.issuerUrl" -o tsv)
//
// 3. Create an Azure AD application:
//
//	export APP_NAME="argocd-project-${PROJECT_NAME}"
//	az ad app create --display-name $APP_NAME
//	export APP_CLIENT_ID=$(az ad app list --display-name $APP_NAME --query "[0].appId" -o tsv)
//	az ad sp create --id $APP_CLIENT_ID
//
// 4. Add federated credential (trust the K8s ServiceAccount):
//
//	cat <<EOF > federated-credential.json
//	{
//	  "name": "argocd-${PROJECT_NAME}-federated",
//	  "issuer": "${OIDC_ISSUER}",
//	  "subject": "system:serviceaccount:${ARGOCD_NAMESPACE}:argocd-project-${PROJECT_NAME}",
//	  "audiences": ["api://AzureADTokenExchange"]
//	}
//	EOF
//	az ad app federated-credential create --id $APP_CLIENT_ID --parameters federated-credential.json
//
// 5. Grant the application access to ACR:
//
//	export ACR_ID=$(az acr show --name $ACR_NAME --query id -o tsv)
//	az role assignment create --assignee $APP_CLIENT_ID --role "AcrPull" --scope $ACR_ID
//
// ## Required Kubernetes ServiceAccount Annotations
//
// The Kubernetes ServiceAccount (argocd-project-<name>) needs these annotations:
//
//   - azure.workload.identity/client-id: The Azure AD application (client) ID
//   - azure.workload.identity/tenant-id: The Azure AD tenant ID
//
// ## Required Repository Secret Fields
//
//   - useWorkloadIdentity: "true"
//   - workloadIdentityProvider: "azure"
//   - project: "<argocd-project-name>" (maps to argocd-project-<name> ServiceAccount)
//
// ## Authentication Flow
//
// 1. Request a K8s token for the project ServiceAccount via TokenRequest API
//    (with audience "api://AzureADTokenExchange")
// 2. Exchange the K8s token for an Azure access token via Azure AD OAuth endpoint
// 3. Exchange the Azure access token for an ACR refresh token
// 4. Return the ACR refresh token for use with the registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// resolveAzure resolves Azure ACR credentials using Azure Workload Identity.
//
// The flow is:
// 1. Exchange K8s JWT for Azure access token (via Azure AD/Entra ID)
// 2. Exchange Azure access token for ACR refresh token
// 3. Return credentials for ACR authentication
func (r *Resolver) resolveAzure(ctx context.Context, sa *corev1.ServiceAccount, k8sToken, repoURL string, config *ProviderConfig) (*Credentials, error) {
	// Get Azure client ID and tenant ID from standard Azure Workload Identity annotations on service account
	clientID := sa.Annotations[AnnotationAzureClientID]
	if clientID == "" {
		return nil, fmt.Errorf("service account %s missing %s annotation", sa.Name, AnnotationAzureClientID)
	}

	tenantID := sa.Annotations[AnnotationAzureTenantID]
	if tenantID == "" {
		return nil, fmt.Errorf("service account %s missing %s annotation", sa.Name, AnnotationAzureTenantID)
	}

	// Get OAuth endpoint (allow override for sovereign clouds) from repository config
	tokenURL := config.TokenURL
	if tokenURL == "" {
		tokenURL = fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantID)
	} else {
		// Replace {tenantID} placeholder in custom endpoint
		tokenURL = strings.ReplaceAll(tokenURL, "{tenantID}", tenantID)
	}

	// Step 1: Exchange K8s JWT for Azure access token using client credentials flow
	azureToken, err := r.getAzureAccessToken(ctx, tokenURL, clientID, k8sToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get Azure access token: %w", err)
	}

	// Step 2: Exchange Azure access token for ACR refresh token
	acrToken, err := r.getACRRefreshToken(ctx, repoURL, azureToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get ACR refresh token: %w", err)
	}

	// ACR uses a special username format with the refresh token as password
	return &Credentials{
		Username: "00000000-0000-0000-0000-000000000000", // ACR service principal ID
		Password: acrToken,
	}, nil
}

// getAzureAccessToken exchanges a K8s JWT for an Azure access token
func (r *Resolver) getAzureAccessToken(ctx context.Context, tokenURL, clientID, k8sToken string) (string, error) {
	// Prepare OAuth 2.0 client credentials request with JWT bearer assertion
	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	data.Set("client_assertion", k8sToken)
	data.Set("scope", "https://management.azure.com/.default")
	data.Set("grant_type", "client_credentials")

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Execute request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return tokenResp.AccessToken, nil
}

// getACRRefreshToken exchanges an Azure access token for an ACR refresh token
func (r *Resolver) getACRRefreshToken(ctx context.Context, repoURL, azureAccessToken string) (string, error) {
	// Extract registry hostname from repo URL
	registry := extractACRRegistry(repoURL)

	// ACR token exchange endpoint
	exchangeURL := fmt.Sprintf("https://%s/oauth2/exchange", registry)

	// Prepare exchange request
	data := url.Values{}
	data.Set("grant_type", "access_token")
	data.Set("service", registry)
	data.Set("access_token", azureAccessToken)

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", exchangeURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create ACR exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Execute request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute ACR exchange request: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("ACR exchange failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse response
	var acrResp struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&acrResp); err != nil {
		return "", fmt.Errorf("failed to decode ACR response: %w", err)
	}

	return acrResp.RefreshToken, nil
}

// extractACRRegistry extracts the registry hostname from an ACR repository URL
// Example: myregistry.azurecr.io/charts → myregistry.azurecr.io
func extractACRRegistry(repoURL string) string {
	// Remove oci:// prefix if present
	repoURL = strings.TrimPrefix(repoURL, "oci://")

	// Take the hostname part (before the first slash)
	parts := strings.Split(repoURL, "/")
	if len(parts) > 0 {
		return parts[0]
	}

	return repoURL
}
