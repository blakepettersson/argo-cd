# Azure Workload Identity for ArgoCD

This guide explains how to configure ArgoCD to use Azure Workload Identity Federation for authentication with Azure Container Registry (ACR).

## Overview

The Azure provider enables ArgoCD to authenticate to ACR using Azure Workload Identity. This provides:

- **Zero static credentials**: No service principal secrets stored in Kubernetes
- **Per-project isolation**: Each ArgoCD project can use a different Azure AD application
- **Fine-grained access control**: RBAC controls which ACR repositories each project can access
- **Works with any Kubernetes cluster**: Not limited to AKS

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        ArgoCD Application Controller                         │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ 1. Resolve workload identity for project "production"                   ││
│  │    → Service account: argocd-project-production                         ││
│  │    → Azure Client ID from annotation                                    ││
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Kubernetes TokenRequest API                          │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ 2. Request K8s JWT for service account                                  ││
│  │    with audience "api://AzureADTokenExchange"                           ││
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Azure AD / Entra ID                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ 3. Client Credentials Flow with JWT Bearer Assertion                    ││
│  │    - Validates K8s JWT against federated credential config              ││
│  │    - Returns Azure access token                                         ││
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Azure ACR                                       │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ 4. Exchange Azure access token for ACR refresh token                    ││
│  │    POST /oauth2/exchange                                                ││
│  │    - Returns ACR-specific refresh token                                 ││
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           ACR Registry Access                                │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ 5. ArgoCD uses ACR refresh token to pull manifests/charts               ││
│  │    Username: 00000000-0000-0000-0000-000000000000                        ││
│  │    Password: <acr-refresh-token>                                        ││
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
```

## Prerequisites

1. **Azure subscription** with ACR enabled
2. **Azure AD permissions** to create applications and federated credentials
3. **Kubernetes cluster** with OIDC issuer (AKS, EKS, GKE, or self-managed with OIDC)

## Configuration Steps

### Step 1: Set Environment Variables

```bash
export AZURE_SUBSCRIPTION_ID=$(az account show --query id -o tsv)
export AZURE_TENANT_ID=$(az account show --query tenantId -o tsv)
export RESOURCE_GROUP="my-resource-group"
export ACR_NAME="myregistry"
export ARGOCD_NAMESPACE="argocd"
export PROJECT_NAME="production"
```

### Step 2: Get Your Kubernetes OIDC Issuer URL

For AKS:
```bash
export CLUSTER_NAME="my-aks-cluster"
export OIDC_ISSUER=$(az aks show --resource-group $RESOURCE_GROUP \
    --name $CLUSTER_NAME --query "oidcIssuerProfile.issuerUrl" -o tsv)
```

For EKS:
```bash
export OIDC_ISSUER=$(aws eks describe-cluster --name $CLUSTER_NAME \
    --query "cluster.identity.oidc.issuer" --output text)
```

For self-managed clusters:
```bash
export OIDC_ISSUER=$(kubectl get --raw /.well-known/openid-configuration | jq -r '.issuer')
```

### Step 3: Create Azure AD Application

Create an Azure AD application (service principal) for the ArgoCD project:

```bash
export APP_NAME="argocd-project-${PROJECT_NAME}"

# Create the application
az ad app create --display-name $APP_NAME

# Get the Application (Client) ID
export APP_CLIENT_ID=$(az ad app list --display-name $APP_NAME --query "[0].appId" -o tsv)

# Create a service principal for the application
az ad sp create --id $APP_CLIENT_ID
```

### Step 4: Add Federated Credential

Configure the application to trust your Kubernetes service account:

```bash
cat <<EOF > federated-credential.json
{
  "name": "argocd-${PROJECT_NAME}-federated",
  "issuer": "${OIDC_ISSUER}",
  "subject": "system:serviceaccount:${ARGOCD_NAMESPACE}:argocd-project-${PROJECT_NAME}",
  "audiences": ["api://AzureADTokenExchange"]
}
EOF

az ad app federated-credential create \
    --id $APP_CLIENT_ID \
    --parameters federated-credential.json
```

### Step 5: Grant ACR Access

Grant the application pull access to ACR:

```bash
export ACR_ID=$(az acr show --name $ACR_NAME --query id -o tsv)

az role assignment create \
    --assignee $APP_CLIENT_ID \
    --role "AcrPull" \
    --scope $ACR_ID
```

For more restrictive access, you can scope to specific repositories using ACR scope maps and tokens.

### Step 6: Create Project Service Account

Create a Kubernetes service account for the ArgoCD project with Azure annotations:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: argocd-project-production  # Format: argocd-project-<project-name>
  namespace: argocd
  annotations:
    # Required: Azure AD Application (Client) ID
    azure.workload.identity/client-id: "12345678-1234-1234-1234-123456789012"
    # Required: Azure AD Tenant ID
    azure.workload.identity/tenant-id: "87654321-4321-4321-4321-210987654321"
```

### Step 7: Create Repository Secret

Create the ArgoCD repository secret with Azure workload identity:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-acr-repo
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  type: helm  # or "oci" for generic OCI artifacts
  url: oci://myregistry.azurecr.io/charts
  project: production  # Links to argocd-project-production service account

  # Enable Azure workload identity
  workloadIdentityProvider: azure

  # Optional: Override token endpoint (for sovereign clouds)
  # workloadIdentityTokenURL: "https://login.microsoftonline.us/{tenantID}/oauth2/v2.0/token"
```

### Step 8: Create Application

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: my-app
  namespace: argocd
spec:
  project: production  # Must match the project in repository secret
  source:
    repoURL: oci://myregistry.azurecr.io/charts
    chart: my-chart
    targetRevision: 1.0.0
  destination:
    server: https://kubernetes.default.svc
    namespace: my-app
```

## Multi-Project Setup

To support multiple projects with different ACR access:

### Project A (production)

```yaml
# Service Account
apiVersion: v1
kind: ServiceAccount
metadata:
  name: argocd-project-production
  namespace: argocd
  annotations:
    azure.workload.identity/client-id: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    azure.workload.identity/tenant-id: "tttttttt-tttt-tttt-tttt-tttttttttttt"
---
# Repository Secret
apiVersion: v1
kind: Secret
metadata:
  name: prod-acr
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  type: helm
  url: oci://prodregistry.azurecr.io/charts
  project: production
  workloadIdentityProvider: azure
```

**Azure AD federated credential:**
```bash
az ad app federated-credential create --id $PROD_APP_CLIENT_ID --parameters @- <<EOF
{
  "name": "argocd-production-federated",
  "issuer": "${OIDC_ISSUER}",
  "subject": "system:serviceaccount:argocd:argocd-project-production",
  "audiences": ["api://AzureADTokenExchange"]
}
EOF
```

### Project B (staging)

```yaml
# Service Account
apiVersion: v1
kind: ServiceAccount
metadata:
  name: argocd-project-staging
  namespace: argocd
  annotations:
    azure.workload.identity/client-id: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
    azure.workload.identity/tenant-id: "tttttttt-tttt-tttt-tttt-tttttttttttt"
---
# Repository Secret
apiVersion: v1
kind: Secret
metadata:
  name: staging-acr
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  type: helm
  url: oci://stagingregistry.azurecr.io/charts
  project: staging
  workloadIdentityProvider: azure
```

## Azure Sovereign Clouds

For Azure Government, China, or Germany clouds, override the token endpoint:

```yaml
# Azure Government
workloadIdentityTokenURL: "https://login.microsoftonline.us/{tenantID}/oauth2/v2.0/token"

# Azure China (21Vianet)
workloadIdentityTokenURL: "https://login.chinacloudapi.cn/{tenantID}/oauth2/v2.0/token"

# Azure Germany (deprecated)
workloadIdentityTokenURL: "https://login.microsoftonline.de/{tenantID}/oauth2/v2.0/token"
```

Note: The `{tenantID}` placeholder is automatically replaced with the tenant ID from the service account annotation.

## Troubleshooting

### Error: "service account missing azure.workload.identity/client-id annotation"

The Kubernetes service account doesn't have the required annotation.

**Solution:**
1. Verify the service account exists: `kubectl get sa argocd-project-<project> -n argocd`
2. Add both `azure.workload.identity/client-id` and `azure.workload.identity/tenant-id` annotations

### Error: "service account missing azure.workload.identity/tenant-id annotation"

The Kubernetes service account is missing the tenant ID annotation.

**Solution:**
1. Get your tenant ID: `az account show --query tenantId -o tsv`
2. Add the `azure.workload.identity/tenant-id` annotation to the service account

### Error: "token request failed: AADSTS70021"

The federated credential doesn't exist or the subject doesn't match.

**Solution:**
1. List federated credentials: `az ad app federated-credential list --id $APP_CLIENT_ID`
2. Verify the subject matches exactly: `system:serviceaccount:<namespace>:<sa-name>`
3. Verify the issuer matches your cluster's OIDC issuer URL

### Error: "token request failed: AADSTS700016"

The application (client ID) doesn't exist in the tenant.

**Solution:**
1. Verify the application exists: `az ad app show --id $APP_CLIENT_ID`
2. Check if the service principal exists: `az ad sp show --id $APP_CLIENT_ID`
3. Create the service principal if missing: `az ad sp create --id $APP_CLIENT_ID`

### Error: "ACR exchange failed: unauthorized"

The Azure access token was obtained but ACR rejected it.

**Solution:**
1. Verify the application has `AcrPull` role on the ACR:
   ```bash
   az role assignment list --assignee $APP_CLIENT_ID --scope $ACR_ID
   ```
2. Check if the ACR is in the same tenant as the application
3. For cross-tenant scenarios, additional configuration may be needed

### Error: "failed to decode ACR response"

The ACR token exchange returned an unexpected response.

**Solution:**
1. Verify the ACR URL is correct (registry name, not repository)
2. Check ACR connectivity: `az acr check-health --name $ACR_NAME`
3. Ensure ACR is not behind a firewall blocking access

## AKS Workload Identity Add-on

For AKS clusters, you can use the Workload Identity add-on for simplified setup:

### Enable the add-on

```bash
az aks update \
    --resource-group $RESOURCE_GROUP \
    --name $CLUSTER_NAME \
    --enable-oidc-issuer \
    --enable-workload-identity
```

### Create User-Assigned Managed Identity (alternative to AD app)

```bash
export IDENTITY_NAME="argocd-project-${PROJECT_NAME}"

az identity create \
    --resource-group $RESOURCE_GROUP \
    --name $IDENTITY_NAME

export IDENTITY_CLIENT_ID=$(az identity show \
    --resource-group $RESOURCE_GROUP \
    --name $IDENTITY_NAME \
    --query clientId -o tsv)

# Create federated credential for the managed identity
az identity federated-credential create \
    --name argocd-${PROJECT_NAME}-federated \
    --identity-name $IDENTITY_NAME \
    --resource-group $RESOURCE_GROUP \
    --issuer $OIDC_ISSUER \
    --subject system:serviceaccount:${ARGOCD_NAMESPACE}:argocd-project-${PROJECT_NAME} \
    --audience api://AzureADTokenExchange

# Grant ACR access
az role assignment create \
    --assignee $IDENTITY_CLIENT_ID \
    --role "AcrPull" \
    --scope $ACR_ID
```

The service account configuration remains the same - use the managed identity's client ID in the annotation.

## Security Considerations

1. **Least privilege RBAC**: Grant only `AcrPull` role, scoped to specific registries or repositories.

2. **Federated credential validation**: Azure validates the issuer, subject, and audience claims in the K8s JWT.

3. **No secrets to rotate**: Unlike service principal secrets, federated credentials don't expire and don't need rotation.

4. **Audit logging**: Enable Azure Activity Log to monitor token exchanges and role assignments.

5. **Token lifetime**: Azure access tokens are valid for 1 hour; ACR refresh tokens have their own lifetime.

6. **Isolate applications**: Use separate Azure AD applications for each ArgoCD project to ensure isolation.

## References

- [Azure Workload Identity](https://azure.github.io/azure-workload-identity/docs/)
- [AKS Workload Identity](https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview)
- [Azure AD Federated Credentials](https://learn.microsoft.com/en-us/graph/api/resources/federatedidentitycredentials-overview)
- [ACR Authentication](https://learn.microsoft.com/en-us/azure/container-registry/container-registry-authentication)
- [Azure AD Client Credentials Flow](https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow)
