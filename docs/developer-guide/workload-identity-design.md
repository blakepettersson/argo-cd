# Cloud-Agnostic Workload Identity for ArgoCD Repositories

## Overview

This document describes the design and implementation of a cloud-agnostic workload identity authentication mechanism for ArgoCD repositories. This feature enables ArgoCD to authenticate to cloud container registries (ECR, GCR, ACR) using Kubernetes service accounts that are scoped per ArgoCD AppProject, providing fine-grained access control and eliminating the need for long-lived credentials.

## Design Goals

1. **Cloud Agnostic**: Single configuration pattern works across AWS, GCP, and Azure
2. **Kubernetes Native**: Leverages standard Kubernetes service account identity patterns
3. **Project Scoped**: Each ArgoCD Project has its own service account identity
4. **Secure**: No long-lived credentials stored in secrets; tokens are short-lived and rotated automatically
5. **Standard Annotations**: Uses cloud provider standard annotations on service accounts
6. **Extensible**: Easy to add new cloud providers or registry types

## Architecture

### Service Account Naming Convention

Each ArgoCD AppProject has a corresponding Kubernetes service account:
```
argocd-project-<project-name>
```

Examples:
- Project `default` → Service account `argocd-project-default`
- Project `my-project` → Service account `argocd-project-my-project`
- Project `production` → Service account `argocd-project-production`

### Configuration Architecture

**Key Principle**: Service accounts provide **identity** (via cloud provider role annotations), while repositories specify **how to use that identity** (provider configuration in repository fields).

**Service Account Role**:
- Provides cryptographic identity via Kubernetes JWT
- Has cloud provider role annotations (e.g., `eks.amazonaws.com/role-arn`)
- One service account can be used by multiple repositories with different providers

**Repository Role**:
- Specifies which workload identity provider to use (`workloadIdentityProvider`)
- Optionally overrides endpoints (e.g., for GovCloud: `workloadIdentityTokenURL`)
- Contains provider-specific configuration fields

### Global Credentials (Project-less Repositories)

ArgoCD supports "global" repository credentials that are not scoped to a specific project. These credentials are available to all applications regardless of their project membership.

For workload identity with global credentials, a dedicated service account is used:
```
argocd-global
```

**Configuration Example:**

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: argocd-global
  namespace: argocd
  annotations:
    # Only cloud provider role annotation - configuration lives on repository
    eks.amazonaws.com/role-arn: "arn:aws:iam::123456789012:role/argocd-global-ecr"
```

**Repository Secret Example:**

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: global-ecr-repo
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  type: helm
  url: 123456789012.dkr.ecr.us-west-2.amazonaws.com/shared-charts
  # Note: no 'project' field - this is a global credential
  useWorkloadIdentity: "true"
  workloadIdentityProvider: "aws"  # Provider config on repository
```

**Service Account Resolution Logic:**

When the app-controller processes a repository with `useWorkloadIdentity: true`:

```go
func getServiceAccountNameForRepo(repo *Repository) string {
    if repo.Project != "" {
        // Project-scoped repository
        return fmt.Sprintf("argocd-project-%s", repo.Project)
    }
    // Global repository (no project set)
    return "argocd-global"
}
```

**Security Considerations:**

Global credentials have access across all projects, so:
1. **Use sparingly**: Only use global workload identity for truly shared resources
2. **Least privilege**: The cloud IAM role for `argocd-global` should have minimal permissions
3. **Prefer project-scoped**: When possible, scope repositories to specific projects for better isolation
4. **Audit regularly**: Monitor usage of global credentials to prevent privilege creep

### High-Level Flow

```
Application (Project: my-project)
  ↓
App Controller looks up project service account: argocd-project-my-project
  ↓
Request K8s token for argocd-project-my-project (via TokenRequest API)
  ↓
Read provider config from Repository fields (workloadIdentityProvider, etc.)
  ↓
Read cloud role from service account annotations (e.g., eks.amazonaws.com/role-arn)
  ↓
Exchange K8s token with cloud provider (OIDC/OAuth flow via HTTPS)
  ↓
Get registry credentials (ECR/GCR/ACR token via HTTPS)
  ↓
Inject username/password into Repository object
  ↓
Pass enriched Repository to Repo Server
  ↓
Repo Server uses credentials (transparent - no workload identity awareness)
```

**Key Architectural Principle**: The repo-server is **completely transparent** to workload identity. It receives a Repository object with `Username` and `Password` fields populated, exactly like any other authentication method (basic auth, token, etc.). All workload identity logic lives in the app-controller.

### Detailed Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│  Step 1: Application Controller - Prepare Repository with Credentials           │
│  ┌────────────────────────────────────────────────────────────────────────────┐  │
│  │ Application Sync triggered for app in project "my-project"                 │  │
│  │ - app.Spec.Project = "my-project"                                          │  │
│  │ - app.Spec.Source.RepoURL = "123.dkr.ecr.us-west-2.amazonaws.com"        │  │
│  │                                                                             │  │
│  │ if repo.UseWorkloadIdentity {                                              │  │
│  │     // Step 1a: Construct service account name                            │  │
│  │     saName := "argocd-project-my-project"                                 │  │
│  │                                                                             │  │
│  │     // Step 1b: Fetch service account                                     │  │
│  │     sa := k8sClient.CoreV1().ServiceAccounts("argocd").                   │  │
│  │         Get(ctx, saName, metav1.GetOptions{})                             │  │
│  │                                                                             │  │
│  │     // Step 1c: Request K8s token for project service account            │  │
│  │     tokenResp := k8sClient.CoreV1().ServiceAccounts("argocd").            │  │
│  │         CreateToken(ctx, saName, &authv1.TokenRequest{...})               │  │
│  │     k8sJWT := tokenResp.Status.Token                                      │  │
│  │                                                                             │  │
│  │     // Step 1d: Detect cloud provider from annotations                    │  │
│  │     provider := detectProvider(sa.Annotations)  // "aws", "gcp", "azure"  │  │
│  │                                                                             │  │
│  │     // Step 1e: Exchange K8s JWT for cloud token (HTTPS call)            │  │
│  │     cloudToken := exchangeToken(provider, k8sJWT, sa.Annotations)         │  │
│  │                                                                             │  │
│  │     // Step 1f: Get registry credentials (HTTPS call)                     │  │
│  │     username, password := getRegistryCredentials(provider, cloudToken)    │  │
│  │                                                                             │  │
│  │     // Step 1g: Inject credentials into Repository                        │  │
│  │     enrichedRepo := repo.DeepCopy()                                       │  │
│  │     enrichedRepo.Username = username                                      │  │
│  │     enrichedRepo.Password = password                                      │  │
│  │ }                                                                           │  │
│  └────────────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────────┘
                                         ↓
┌──────────────────────────────────────────────────────────────────────────────────┐
│  Step 2: Application Controller - Call Repo Server                              │
│  ┌────────────────────────────────────────────────────────────────────────────┐  │
│  │ // Repo server receives Repository with credentials already populated      │  │
│  │ manifests := repoServerClient.GenerateManifest(ctx, &ManifestRequest{     │  │
│  │     Repo: enrichedRepo,  // ← Has Username/Password filled in             │  │
│  │     AppName: "my-app",                                                     │  │
│  │     ... other fields ...                                                   │  │
│  │ })                                                                          │  │
│  └────────────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────────┘
                                         ↓
┌──────────────────────────────────────────────────────────────────────────────────┐
│  Step 3: Repo Server - Uses Credentials (Transparent)                           │
│  ┌────────────────────────────────────────────────────────────────────────────┐  │
│  │ // Repo server has NO knowledge of workload identity                       │  │
│  │ // It just uses username/password like any other auth method               │  │
│  │                                                                             │  │
│  │ if repo.Type == "helm" {                                                   │  │
│  │     helmClient.PullChart(                                                  │  │
│  │         repo.URL,                                                          │  │
│  │         username: repo.Username,  // ← Resolved by app-controller         │  │
│  │         password: repo.Password,  // ← Resolved by app-controller         │  │
│  │     )                                                                       │  │
│  │ }                                                                           │  │
│  └────────────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────────┘
```

### OIDC Token Exchange Flows (App-Controller)

This section details how the K8s JWT is exchanged for cloud provider tokens using standard OIDC/OAuth flows over HTTPS.

#### AWS: AssumeRoleWithWebIdentity via HTTPS

```
POST https://sts.{region}.amazonaws.com/
  ?Action=AssumeRoleWithWebIdentity
  &RoleArn={roleARN from annotation}
  &WebIdentityToken={k8sJWT}
  &RoleSessionName=argocd-project-{projectName}
  &Version=2011-06-15

Response (XML):
  <AssumeRoleWithWebIdentityResponse>
    <AssumeRoleWithWebIdentityResult>
      <Credentials>
        <AccessKeyId>ASIAIOSFODNN7EXAMPLE</AccessKeyId>
        <SecretAccessKey>wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY</SecretAccessKey>
        <SessionToken>FwoGZXIvYXdzEDoaDCMxSiJN...</SessionToken>
        <Expiration>2024-01-01T12:00:00Z</Expiration>
      </Credentials>
    </AssumeRoleWithWebIdentityResult>
  </AssumeRoleWithWebIdentityResponse>

Then call ECR:
POST https://ecr.{region}.amazonaws.com/
  ?Action=GetAuthorizationToken
  &Version=2015-09-21
  (with AWS SigV4 signature using above credentials)

Response: Base64-encoded "AWS:{token}"
```

#### GCP: OAuth 2.0 Token Exchange via HTTPS

```
POST https://sts.googleapis.com/v1/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token={k8sJWT}
&subject_token_type=urn:ietf:params:oauth:token-type:jwt
&requested_token_type=urn:ietf:params:oauth:token-type:access_token
&audience=//iam.googleapis.com/{gcp-sa-email from annotation}
&scope=https://www.googleapis.com/auth/cloud-platform

Response (JSON):
  {
    "access_token": "ya29.c.Kl6iB-r90_Nc...",
    "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
    "token_type": "Bearer",
    "expires_in": 3600
  }

For GCR/Artifact Registry, use directly:
  username: oauth2accesstoken
  password: {access_token from above}
```

#### Azure: OAuth 2.0 Client Credentials Flow via HTTPS

```
POST https://login.microsoftonline.com/{tenantID}/oauth2/v2.0/token
Content-Type: application/x-www-form-urlencoded

client_id={clientID from annotation}
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&client_assertion={k8sJWT}
&scope=https://management.azure.com/.default
&grant_type=client_credentials

Response (JSON):
  {
    "token_type": "Bearer",
    "expires_in": 3599,
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc..."
  }

For ACR, exchange via ACR-specific endpoint:
POST https://{registry}.azurecr.io/oauth2/exchange
Content-Type: application/x-www-form-urlencoded

grant_type=access_token
&service={registry}.azurecr.io
&access_token={access_token from above}

Response: ACR refresh token
```

## Data Model

### Repository Type Extensions

**Location:** `pkg/apis/application/v1alpha1/repository_types.go`

```go
type Repository struct {
    // ... existing fields ...

    // UseWorkloadIdentity enables workload identity authentication
    UseWorkloadIdentity bool `json:"useWorkloadIdentity,omitempty" protobuf:"bytes,28,opt,name=useWorkloadIdentity"`

    // WorkloadIdentityProvider specifies the provider ("aws", "gcp", "azure", or custom)
    WorkloadIdentityProvider string `json:"workloadIdentityProvider,omitempty" protobuf:"bytes,29,opt,name=workloadIdentityProvider"`

    // WorkloadIdentityTokenURL optionally overrides the default token endpoint
    WorkloadIdentityTokenURL string `json:"workloadIdentityTokenURL,omitempty" protobuf:"bytes,30,opt,name=workloadIdentityTokenURL"`

    // WorkloadIdentityAudience optionally specifies a custom audience for the K8s JWT
    WorkloadIdentityAudience string `json:"workloadIdentityAudience,omitempty" protobuf:"bytes,31,opt,name=workloadIdentityAudience"`

    // WorkloadIdentityRegistryAuthURL optionally specifies a registry auth endpoint (for generic provider)
    WorkloadIdentityRegistryAuthURL string `json:"workloadIdentityRegistryAuthURL,omitempty" protobuf:"bytes,32,opt,name=workloadIdentityRegistryAuthURL"`

    // WorkloadIdentityRegistryService optionally specifies a registry service name (for generic provider)
    WorkloadIdentityRegistryService string `json:"workloadIdentityRegistryService,omitempty" protobuf:"bytes,33,opt,name=workloadIdentityRegistryService"`
}
```

### Workload Identity Provider Configuration

Provider configuration is stored in repository fields, while service accounts provide identity via cloud provider role annotations.

#### Built-in Providers (AWS, GCP, Azure)

**AWS ECR Example:**

Service Account (identity):
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: argocd-project-my-project
  namespace: argocd
  annotations:
    eks.amazonaws.com/role-arn: "arn:aws:iam::123456789012:role/my-role"
```

Repository Secret (configuration):
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-ecr-repo
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  type: helm
  url: 123456789012.dkr.ecr.us-west-2.amazonaws.com/charts
  project: my-project
  useWorkloadIdentity: "true"
  workloadIdentityProvider: "aws"
  # Optional: for GovCloud/China
  # workloadIdentityTokenURL: "https://sts.us-gov-west-1.amazonaws.com"
```

**GCP Artifact Registry Example:**

Service Account (identity):
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: argocd-project-my-project
  namespace: argocd
  annotations:
    iam.gke.io/gcp-service-account: "sa@project.iam.gserviceaccount.com"
```

Repository Secret (configuration):
```yaml
stringData:
  type: helm
  url: us-docker.pkg.dev/my-project/my-repo
  project: my-project
  useWorkloadIdentity: "true"
  workloadIdentityProvider: "gcp"
```

**Azure ACR Example:**

Service Account (identity):
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: argocd-project-my-project
  namespace: argocd
  annotations:
    azure.workload.identity/client-id: "12345678-1234-1234-1234-123456789012"
    azure.workload.identity/tenant-id: "87654321-4321-4321-4321-210987654321"
```

Repository Secret (configuration):
```yaml
stringData:
  type: helm
  url: myregistry.azurecr.io/charts
  project: my-project
  useWorkloadIdentity: "true"
  workloadIdentityProvider: "azure"
  # Optional: for Government/China clouds
  # workloadIdentityTokenURL: "https://login.microsoftonline.us/{tenantID}/oauth2/v2.0/token"
```

#### Generic Provider (Custom OIDC/OAuth via RFC 8693)

For custom registries supporting RFC 8693 token exchange (SPIFFE/SPIRE, Harbor, Quay, GitLab):

Service Account (identity - no special annotations needed):
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: argocd-project-my-project
  namespace: argocd
```

Repository Secret (configuration):
```yaml
stringData:
  type: helm
  url: harbor.example.com/myproject
  project: my-project
  useWorkloadIdentity: "true"
  workloadIdentityProvider: "generic"
  # Step 1: Token exchange (K8s JWT → identity token)
  workloadIdentityTokenURL: "https://spire-oidc.example.com/token"
  workloadIdentityAudience: "spiffe://trust-domain/harbor"
  # Step 2: Registry auth (identity token → registry credentials)
  workloadIdentityRegistryAuthURL: "https://harbor.example.com/service/token"
  workloadIdentityRegistryService: "harbor.example.com"
```

**Full Flow - Two-Step Token Exchange:**

**Step 1: Get Identity Token from SPIRE**

```
POST https://spire-oidc.example.com/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<k8s-jwt>
&subject_token_type=urn:ietf:params:oauth:token-type:jwt
&requested_token_type=urn:ietf:params:oauth:token-type:access_token
&audience=spiffe://trust-domain/harbor

Response:
{
  "access_token": "eyJhbGc...<spiffe-jwt>",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

**Step 2: Exchange Identity Token for Registry Credentials**

This follows the [Docker Registry Token Authentication spec](https://docs.docker.com/registry/spec/auth/token/):

```
GET https://harbor.example.com/service/token?service=harbor.example.com&scope=repository:myproject/myrepo:pull
Authorization: Bearer <spiffe-jwt>

Response:
{
  "token": "eyJhbGc...<harbor-registry-token>",
  "access_token": "eyJhbGc...<harbor-registry-token>",
  "expires_in": 300,
  "issued_at": "2024-01-01T12:00:00Z"
}
```

**Step 3: Use Registry Token for Docker Auth**

The app-controller injects into Repository:
- username: `` (empty, or sometimes the service account name)
- password: `<harbor-registry-token>`

The repo-server uses these credentials transparently with the registry client.

**SPIRE Server Configuration:**
```hcl
# Enable OIDC Discovery provider
oidc_discovery {
  domain = "spire-oidc.example.com"
  # Support RFC 8693 token exchange
  token_exchange {
    enabled = true
    # Accept K8s tokens from specific issuers
    trusted_issuers = ["https://kubernetes.default.svc.cluster.local"]
  }
}
```

**Harbor Configuration:**

Harbor must be configured to accept SPIFFE JWTs for authentication. This typically requires:
1. Configuring Harbor's OIDC provider to trust the SPIRE server
2. Setting up authorization policies based on SPIFFE IDs

### Service Account Annotations

Cloud provider configuration is stored on the Kubernetes service account using standard annotations:

#### AWS Annotations
```yaml
annotations:
  eks.amazonaws.com/role-arn: "arn:aws:iam::123456789012:role/my-project-ecr-access"
  # Optional: override audience (defaults to sts.amazonaws.com)
  eks.amazonaws.com/audience: "sts.amazonaws.com"
```

#### GCP Annotations
```yaml
annotations:
  iam.gke.io/gcp-service-account: "my-project@project-id.iam.gserviceaccount.com"
```

#### Azure Annotations
```yaml
annotations:
  azure.workload.identity/client-id: "12345678-1234-1234-1234-123456789012"
  azure.workload.identity/tenant-id: "87654321-4321-4321-4321-210987654321"
```

### Enhanced Credential Methods

**Location:** `pkg/apis/application/v1alpha1/repository_types.go` (to be added)

```go
// GetOCICredsWithContext returns OCI credentials with project context
func (repo *Repository) GetOCICredsWithContext(projectName string, k8sClient kubernetes.Interface) oci.Creds {
    if repo.UseWorkloadIdentity && projectName != "" {
        return oci.NewWorkloadIdentityCreds(
            repo.Repo,
            projectName,
            k8sClient,
            getCAPath(repo.Repo),
            []byte(repo.TLSClientCertData),
            []byte(repo.TLSClientCertKey),
            repo.Insecure,
        )
    }

    // Fall back to existing logic
    return repo.GetOCICreds()
}

// GetHelmCredsWithContext returns Helm credentials with project context
func (repo *Repository) GetHelmCredsWithContext(projectName string, k8sClient kubernetes.Interface) helm.Creds {
    if repo.UseWorkloadIdentity && projectName != "" {
        return helm.NewWorkloadIdentityCreds(
            repo.Repo,
            projectName,
            k8sClient,
            getCAPath(repo.Repo),
            []byte(repo.TLSClientCertData),
            []byte(repo.TLSClientCertKey),
            repo.Insecure,
        )
    }

    // Fall back to existing logic (including Azure Workload Identity)
    return repo.GetHelmCreds()
}
```

## Cloud Provider Configuration

### Prerequisites

Before configuring workload identity for any cloud provider:

1. **Enable OIDC on your cluster** (already done for EKS, GKE, and AKS by default)
2. **Configure repo server RBAC** to allow requesting tokens for project service accounts:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: argocd-repo-server-token-creator
  namespace: argocd
rules:
- apiGroups: [""]
  resources: ["serviceaccounts"]
  verbs: ["get"]
- apiGroups: [""]
  resources: ["serviceaccounts/token"]
  verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: argocd-repo-server-token-creator
  namespace: argocd
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: argocd-repo-server-token-creator
subjects:
- kind: ServiceAccount
  name: argocd-repo-server
  namespace: argocd
```

### AWS Configuration

#### Step 1: Configure OIDC Provider in AWS IAM

```bash
# Get OIDC issuer from EKS cluster
aws eks describe-cluster --name <cluster-name> --query "cluster.identity.oidc.issuer" --output text

# Create OIDC provider in IAM (if not exists)
eksctl utils associate-iam-oidc-provider --cluster=<cluster-name> --approve
```

#### Step 2: Create IAM Role with Trust Policy

Create a role that trusts the project-specific service account:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::ACCOUNT_ID:oidc-provider/oidc.eks.REGION.amazonaws.com/id/CLUSTER_ID"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "oidc.eks.REGION.amazonaws.com/id/CLUSTER_ID:sub": "system:serviceaccount:argocd:argocd-project-my-project"
        }
      }
    }
  ]
}
```

#### Step 3: Attach ECR Permissions to Role

```bash
aws iam attach-role-policy \
  --role-name argocd-my-project-ecr \
  --policy-arn arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly
```

Or create a custom policy:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ecr:GetAuthorizationToken",
        "ecr:BatchCheckLayerAvailability",
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchGetImage"
      ],
      "Resource": "*"
    }
  ]
}
```

#### Step 4: Create Kubernetes Service Account

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: argocd-project-my-project
  namespace: argocd
  annotations:
    eks.amazonaws.com/role-arn: "arn:aws:iam::123456789012:role/argocd-my-project-ecr"
```

#### Step 5: Configure Repository Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-ecr-repo
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  type: helm
  url: 123456789012.dkr.ecr.us-west-2.amazonaws.com/my-charts
  project: my-project
  useWorkloadIdentity: "true"
```

### GCP Configuration

#### Step 1: Enable Workload Identity on GKE Cluster

```bash
gcloud container clusters update CLUSTER_NAME \
    --workload-pool=PROJECT_ID.svc.id.goog
```

#### Step 2: Create GCP Service Account and Grant Permissions

```bash
# Create GCP service account
gcloud iam service-accounts create argocd-my-project \
    --project=PROJECT_ID

# Grant Artifact Registry reader role
gcloud artifacts repositories add-iam-policy-binding REPO_NAME \
    --location=REGION \
    --member="serviceAccount:argocd-my-project@PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/artifactregistry.reader"
```

#### Step 3: Bind Workload Identity

Bind the GCP service account to the Kubernetes service account:

```bash
gcloud iam service-accounts add-iam-policy-binding \
    argocd-my-project@PROJECT_ID.iam.gserviceaccount.com \
    --project=PROJECT_ID \
    --role="roles/iam.workloadIdentityUser" \
    --member="serviceAccount:PROJECT_ID.svc.id.goog[argocd/argocd-project-my-project]"
```

#### Step 4: Create Kubernetes Service Account

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: argocd-project-my-project
  namespace: argocd
  annotations:
    iam.gke.io/gcp-service-account: "argocd-my-project@PROJECT_ID.iam.gserviceaccount.com"
```

#### Step 5: Configure Repository Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-gcr-repo
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  type: helm
  url: us-docker.pkg.dev/my-project/my-repo
  project: my-project
  useWorkloadIdentity: "true"
```

### Azure Configuration

#### Step 1: Create Managed Identity

```bash
az identity create \
    --name argocd-my-project \
    --resource-group RESOURCE_GROUP \
    --location REGION
```

#### Step 2: Grant ACR Pull Permissions

```bash
# Get principal ID
PRINCIPAL_ID=$(az identity show \
    --name argocd-my-project \
    --resource-group RESOURCE_GROUP \
    --query principalId -o tsv)

# Get ACR resource ID
ACR_ID=$(az acr show \
    --name MY_REGISTRY \
    --resource-group RESOURCE_GROUP \
    --query id -o tsv)

# Assign AcrPull role
az role assignment create \
    --assignee $PRINCIPAL_ID \
    --role AcrPull \
    --scope $ACR_ID
```

#### Step 3: Create Federated Identity Credential

Link the Azure managed identity to the Kubernetes service account:

```bash
# Get OIDC issuer URL from AKS cluster
OIDC_ISSUER=$(az aks show \
    --name CLUSTER_NAME \
    --resource-group CLUSTER_RESOURCE_GROUP \
    --query "oidcIssuerProfile.issuerUrl" -o tsv)

# Create federated credential for the project-specific service account
az identity federated-credential create \
    --name argocd-my-project-fed \
    --identity-name argocd-my-project \
    --resource-group RESOURCE_GROUP \
    --issuer "$OIDC_ISSUER" \
    --subject "system:serviceaccount:argocd:argocd-project-my-project"
```

#### Step 4: Create Kubernetes Service Account

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: argocd-project-my-project
  namespace: argocd
  annotations:
    azure.workload.identity/client-id: "CLIENT_ID_OF_MANAGED_IDENTITY"
    # Optional: specify tenant if different from default
    # azure.workload.identity/tenant-id: "TENANT_ID"
```

#### Step 5: Configure Repository Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-acr-repo
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  type: helm
  url: myregistry.azurecr.io/charts
  project: my-project
  useWorkloadIdentity: "true"
```

## Implementation Components

### 1. Kubernetes TokenRequest Client

**Location:** `util/workloadidentity/tokenrequest.go` (to be created)

```go
package workloadidentity

import (
    "context"
    "time"

    authv1 "k8s.io/api/authentication/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "k8s.io/client-go/kubernetes"
)

// K8sTokenProvider generates Kubernetes service account tokens via TokenRequest API
type K8sTokenProvider interface {
    RequestToken(ctx context.Context, audience string, duration int64) (string, error)
}

type k8sTokenProvider struct {
    clientset kubernetes.Interface
    namespace string
    serviceAccount string
}

func NewK8sTokenProvider(clientset kubernetes.Interface, namespace, serviceAccount string) K8sTokenProvider {
    return &k8sTokenProvider{
        clientset: clientset,
        namespace: namespace,
        serviceAccount: serviceAccount,
    }
}

func (p *k8sTokenProvider) RequestToken(ctx context.Context, audience string, duration int64) (string, error) {
    tokenRequest := &authv1.TokenRequest{
        Spec: authv1.TokenRequestSpec{
            Audiences: []string{audience},
            ExpirationSeconds: &duration,
        },
    }

    resp, err := p.clientset.CoreV1().
        ServiceAccounts(p.namespace).
        CreateToken(ctx, p.serviceAccount, tokenRequest, metav1.CreateOptions{})

    if err != nil {
        return "", fmt.Errorf("failed to request token: %w", err)
    }

    return resp.Status.Token, nil
}
```

### 2. Cloud Provider Token Exchangers

#### AWS Provider

**Location:** `util/workloadidentity/aws.go` (to be created)

```go
package workloadidentity

import (
    "context"
    "fmt"
    "time"

    "github.com/aws/aws-sdk-go/aws"
    "github.com/aws/aws-sdk-go/aws/session"
    "github.com/aws/aws-sdk-go/service/sts"
)

type AWSTokenProvider struct {
    k8sTokenProvider K8sTokenProvider
    roleARN string
}

func NewAWSTokenProvider(k8sProvider K8sTokenProvider, roleARN string) *AWSTokenProvider {
    return &AWSTokenProvider{
        k8sTokenProvider: k8sProvider,
        roleARN: roleARN,
    }
}

func (p *AWSTokenProvider) GetToken(ctx context.Context, audience string) (*Token, error) {
    // Step 1: Get Kubernetes JWT
    k8sToken, err := p.k8sTokenProvider.RequestToken(ctx, audience, 3600)
    if err != nil {
        return nil, fmt.Errorf("failed to get k8s token: %w", err)
    }

    // Step 2: Exchange for AWS credentials
    sess := session.Must(session.NewSession())
    stsClient := sts.New(sess)

    result, err := stsClient.AssumeRoleWithWebIdentityWithContext(ctx, &sts.AssumeRoleWithWebIdentityInput{
        RoleArn:          aws.String(p.roleARN),
        WebIdentityToken: aws.String(k8sToken),
        RoleSessionName:  aws.String("argocd-repo-server"),
        DurationSeconds:  aws.Int64(3600),
    })

    if err != nil {
        return nil, fmt.Errorf("failed to assume role: %w", err)
    }

    return &Token{
        AccessToken: *result.Credentials.AccessKeyId + ":" + *result.Credentials.SecretAccessKey + ":" + *result.Credentials.SessionToken,
        ExpiresOn:   *result.Credentials.Expiration,
    }, nil
}
```

#### GCP Provider

**Location:** `util/workloadidentity/gcp.go` (to be created)

```go
package workloadidentity

import (
    "context"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "strings"
    "time"
)

type GCPTokenProvider struct {
    k8sTokenProvider K8sTokenProvider
    poolProvider string // Full resource name of workload identity pool provider
}

func NewGCPTokenProvider(k8sProvider K8sTokenProvider, poolProvider string) *GCPTokenProvider {
    return &GCPTokenProvider{
        k8sTokenProvider: k8sProvider,
        poolProvider: poolProvider,
    }
}

func (p *GCPTokenProvider) GetToken(ctx context.Context, audience string) (*Token, error) {
    // Step 1: Get Kubernetes JWT
    k8sToken, err := p.k8sTokenProvider.RequestToken(ctx, audience, 3600)
    if err != nil {
        return nil, fmt.Errorf("failed to get k8s token: %w", err)
    }

    // Step 2: Exchange for GCP access token via STS
    stsURL := "https://sts.googleapis.com/v1/token"

    data := url.Values{}
    data.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
    data.Set("subject_token", k8sToken)
    data.Set("subject_token_type", "urn:ietf:params:oauth:token-type:jwt")
    data.Set("requested_token_type", "urn:ietf:params:oauth:token-type:access_token")
    data.Set("audience", fmt.Sprintf("//iam.googleapis.com/%s", p.poolProvider))
    data.Set("scope", "https://www.googleapis.com/auth/cloud-platform")

    req, err := http.NewRequestWithContext(ctx, "POST", stsURL, strings.NewReader(data.Encode()))
    if err != nil {
        return nil, err
    }
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }

    var tokenResp struct {
        AccessToken string `json:"access_token"`
        ExpiresIn   int64  `json:"expires_in"`
    }

    if err := json.Unmarshal(body, &tokenResp); err != nil {
        return nil, err
    }

    return &Token{
        AccessToken: tokenResp.AccessToken,
        ExpiresOn:   time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
    }, nil
}
```

### 3. Registry Credential Providers

#### ECR Provider

**Location:** `util/oci/ecr.go` (to be created)

```go
package oci

import (
    "context"
    "encoding/base64"
    "fmt"
    "strings"

    "github.com/aws/aws-sdk-go/aws"
    "github.com/aws/aws-sdk-go/aws/credentials"
    "github.com/aws/aws-sdk-go/aws/session"
    "github.com/aws/aws-sdk-go/service/ecr"
)

type ECRAuthProvider struct {
    awsCredentials *credentials.Credentials
}

func NewECRAuthProvider(accessKeyID, secretAccessKey, sessionToken, region string) *ECRAuthProvider {
    creds := credentials.NewStaticCredentials(accessKeyID, secretAccessKey, sessionToken)
    return &ECRAuthProvider{awsCredentials: creds}
}

func (p *ECRAuthProvider) GetRegistryCredentials(ctx context.Context) (username, password string, err error) {
    sess, err := session.NewSession(&aws.Config{
        Credentials: p.awsCredentials,
    })
    if err != nil {
        return "", "", err
    }

    ecrClient := ecr.New(sess)
    result, err := ecrClient.GetAuthorizationTokenWithContext(ctx, &ecr.GetAuthorizationTokenInput{})
    if err != nil {
        return "", "", err
    }

    if len(result.AuthorizationData) == 0 {
        return "", "", fmt.Errorf("no authorization data returned from ECR")
    }

    authData := result.AuthorizationData[0]
    decoded, err := base64.StdEncoding.DecodeString(*authData.AuthorizationToken)
    if err != nil {
        return "", "", err
    }

    parts := strings.SplitN(string(decoded), ":", 2)
    if len(parts) != 2 {
        return "", "", fmt.Errorf("invalid authorization token format")
    }

    return parts[0], parts[1], nil
}
```

#### GCR/Artifact Registry Provider

**Location:** `util/oci/gcr.go` (to be created)

```go
package oci

import (
    "context"
)

type GCRAuthProvider struct {
    accessToken string
}

func NewGCRAuthProvider(accessToken string) *GCRAuthProvider {
    return &GCRAuthProvider{accessToken: accessToken}
}

func (p *GCRAuthProvider) GetRegistryCredentials(ctx context.Context) (username, password string, err error) {
    // For GCR/Artifact Registry, the GCP access token is used directly as password
    return "oauth2accesstoken", p.accessToken, nil
}
```

### 4. OCI Credentials Implementation

**Location:** `util/oci/creds.go` (to be modified/extended)

```go
type GenericWorkloadIdentityCreds struct {
    repoURL string
    credContext v1alpha1.CredentialContext
    provider string
    config map[string]string
    caPath string
    certData []byte
    keyData []byte
    insecure bool
}

func NewGenericWorkloadIdentityCreds(
    repoURL string,
    credContext v1alpha1.CredentialContext,
    provider string,
    config map[string]string,
    caPath string,
    certData, keyData []byte,
    insecure bool,
) *GenericWorkloadIdentityCreds {
    return &GenericWorkloadIdentityCreds{
        repoURL: repoURL,
        credContext: credContext,
        provider: provider,
        config: config,
        caPath: caPath,
        certData: certData,
        keyData: keyData,
        insecure: insecure,
    }
}

func (c *GenericWorkloadIdentityCreds) GetCredentials(ctx context.Context) (string, string, error) {
    // Generate project-scoped audience
    audience := fmt.Sprintf("argocd.argoproj.io/projects/%s", c.credContext.ProjectName)

    // Get K8s token provider
    k8sProvider := workloadidentity.NewK8sTokenProvider(
        c.credContext.K8sClientset,
        c.credContext.ServiceAccountNamespace,
        c.credContext.ServiceAccountName,
    )

    // Get cloud-specific provider
    var cloudToken *workloadidentity.Token
    var err error

    switch c.provider {
    case "aws":
        roleARN := c.config["roleARN"]
        awsProvider := workloadidentity.NewAWSTokenProvider(k8sProvider, roleARN)
        cloudToken, err = awsProvider.GetToken(ctx, audience)

    case "gcp":
        poolProvider := c.config["poolProvider"]
        gcpProvider := workloadidentity.NewGCPTokenProvider(k8sProvider, poolProvider)
        cloudToken, err = gcpProvider.GetToken(ctx, audience)

    case "azure":
        // Azure implementation
        azureProvider := workloadidentity.NewAzureTokenProvider(k8sProvider, c.config)
        cloudToken, err = azureProvider.GetToken(ctx, audience)

    default:
        return "", "", fmt.Errorf("unsupported workload identity provider: %s", c.provider)
    }

    if err != nil {
        return "", "", fmt.Errorf("failed to get cloud token: %w", err)
    }

    // Exchange cloud token for registry credentials
    return c.getRegistryCredentials(ctx, cloudToken)
}

func (c *GenericWorkloadIdentityCreds) getRegistryCredentials(ctx context.Context, token *workloadidentity.Token) (string, string, error) {
    // Parse registry type from URL
    registryType := detectRegistryType(c.repoURL)

    switch registryType {
    case "ecr":
        // Parse AWS credentials from token
        parts := strings.SplitN(token.AccessToken, ":", 3)
        provider := NewECRAuthProvider(parts[0], parts[1], parts[2], extractRegion(c.repoURL))
        return provider.GetRegistryCredentials(ctx)

    case "gcr", "artifact-registry":
        provider := NewGCRAuthProvider(token.AccessToken)
        return provider.GetRegistryCredentials(ctx)

    case "acr":
        provider := NewACRAuthProvider(token.AccessToken)
        return provider.GetRegistryCredentials(ctx)

    default:
        return "", "", fmt.Errorf("unsupported registry type: %s", registryType)
    }
}
```

## Security Benefits

1. **Project Isolation**: Each ArgoCD project gets tokens with unique audience claims, preventing cross-project token reuse
2. **Least Privilege**: Cloud IAM roles can be scoped to specific ArgoCD projects, limiting blast radius
3. **Token Reuse Prevention**: Tokens from one project cannot be used to access resources in another project
4. **Audit Trail**: Cloud provider logs show which ArgoCD project accessed which resources
5. **Defense in Depth**: Even if a token leaks, it's only valid for one project's resources
6. **No Long-Lived Credentials**: All tokens are short-lived (typically 1 hour) and automatically rotated
7. **Kubernetes Native**: Leverages Kubernetes TokenRequest API for secure token generation

## Backward Compatibility

1. **Existing Azure workload identity unchanged**: The current `UseAzureWorkloadIdentity` flow remains intact and is not affected
2. **Existing credential methods preserved**: `GetOCICreds()` and `GetHelmCreds()` continue to work as before
3. **Opt-in**: New functionality only activates when `UseGenericWorkloadIdentity = true`
4. **Graceful degradation**: If project context is unavailable, system can fall back to existing methods
5. **No breaking changes**: All existing Repository configurations continue to work

## Implementation Checklist

- [x] Add new fields to Repository and RepoCreds types
- [ ] Implement CredentialContext type
- [ ] Implement enhanced credential methods (GetOCICredsWithContext, GetHelmCredsWithContext)
- [ ] Implement K8s TokenRequest client
- [ ] Implement AWS token provider
- [ ] Implement GCP token provider
- [ ] Implement Azure token provider (new, separate from existing)
- [ ] Implement ECR auth provider
- [ ] Implement GCR/Artifact Registry auth provider
- [ ] Implement ACR auth provider (new, separate from existing)
- [ ] Implement GenericWorkloadIdentityCreds for OCI
- [ ] Implement GenericWorkloadIdentityCreds for Helm
- [ ] Update repo-server GenerateManifest to pass project context
- [ ] Add token caching with appropriate TTL
- [ ] Add comprehensive unit tests
- [ ] Add integration tests
- [ ] Update documentation
- [ ] Generate protobuf definitions

## Testing Strategy

### Unit Tests

1. Test K8s TokenRequest API mocking
2. Test AWS STS token exchange with mock AWS SDK
3. Test GCP STS token exchange with mock HTTP client
4. Test audience claim generation for different project names
5. Test credential method fallback behavior
6. Test token caching and expiration

### Integration Tests

1. Test end-to-end flow with real Kubernetes cluster (kind/minikube)
2. Test with AWS LocalStack for ECR simulation
3. Test with GCP Cloud Storage emulator
4. Test project isolation (tokens from project A can't access project B resources)
5. Test backward compatibility with existing authentication methods

### E2E Tests

1. Deploy ArgoCD with workload identity enabled
2. Create multiple projects with different IAM roles
3. Deploy Helm charts from ECR, GCR, and ACR
4. Verify proper credential isolation
5. Verify audit logs show correct project attribution

## Future Enhancements

1. **Support for additional cloud providers**: Alibaba Cloud, Oracle Cloud, etc.
2. **Support for additional registry types**: Harbor, Quay, JFrog Artifactory
3. **Custom audience patterns**: Allow users to define custom audience formats
4. **Multi-project tokens**: Support for tokens valid across multiple projects
5. **Token rotation strategies**: Configurable token refresh intervals
6. **Metrics and monitoring**: Expose Prometheus metrics for token generation and usage
7. **Automatic IAM role discovery**: Auto-detect IAM roles based on annotations

## References

- [Kubernetes TokenRequest API](https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-request-v1/)
- [AWS IRSA Documentation](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html)
- [GCP Workload Identity Documentation](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity)
- [Azure Workload Identity Documentation](https://azure.github.io/azure-workload-identity/)
- [RFC 8693 - OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)