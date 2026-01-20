# GCP Workload Identity for ArgoCD

This guide explains how to configure ArgoCD to use GCP Workload Identity Federation for authentication with Google Artifact Registry and Google Container Registry (GCR).

## Overview

The GCP provider enables ArgoCD to authenticate to Artifact Registry/GCR using Workload Identity Federation. This provides:

- **Zero static credentials**: No service account keys stored in secrets
- **Per-project isolation**: Each ArgoCD project can impersonate a different GCP service account
- **Fine-grained access control**: IAM policies control which repositories each project can access
- **Works with any Kubernetes cluster**: Not limited to GKE

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        ArgoCD Application Controller                         │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ 1. Resolve workload identity for project "production"                   ││
│  │    → Service account: argocd-project-production                         ││
│  │    → GCP SA: argocd-prod@myproject.iam.gserviceaccount.com              ││
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Kubernetes TokenRequest API                          │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ 2. Request K8s JWT for service account with WIF provider audience       ││
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              GCP STS                                         │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ 3. Token Exchange (RFC 8693)                                            ││
│  │    - Validates K8s JWT against Workload Identity Pool                   ││
│  │    - Returns federated access token                                     ││
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         GCP IAM Credentials API                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ 4. Service Account Impersonation                                        ││
│  │    - Uses federated token to impersonate target GCP SA                  ││
│  │    - Returns access token for the GCP service account                   ││
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Artifact Registry / GCR Access                            │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ 5. ArgoCD uses access token (oauth2accesstoken:token) to pull          ││
│  │    manifests/charts from Artifact Registry or GCR                       ││
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
```

## GKE Workload Identity vs Workload Identity Federation

This provider supports two authentication methods:

| Feature | GKE Workload Identity | Workload Identity Federation |
|---------|----------------------|------------------------------|
| Cluster Type | GKE only | Any Kubernetes cluster |
| Setup Complexity | Simpler | More configuration |
| Uses Metadata Server | Yes | No |
| Fallback | Yes (automatic) | Primary method |

For GKE clusters with Workload Identity enabled, the provider first tries the metadata server approach. If that fails (or on non-GKE clusters), it falls back to STS token exchange.

## Prerequisites

1. **GCP Project** with Artifact Registry or GCR enabled
2. **IAM permissions** to create service accounts and Workload Identity Pools
3. **Kubernetes cluster** with OIDC issuer URL accessible (for Workload Identity Federation)

## Configuration Steps

### Step 1: Create Workload Identity Pool and Provider

Create a Workload Identity Pool that trusts your Kubernetes cluster:

```bash
export PROJECT_ID="my-gcp-project"
export PROJECT_NUMBER=$(gcloud projects describe $PROJECT_ID --format="value(projectNumber)")
export POOL_NAME="argocd-pool"
export PROVIDER_NAME="argocd-k8s"
export K8S_ISSUER_URL="<your-cluster-oidc-issuer>"  # See below for how to find this

# Create the Workload Identity Pool
gcloud iam workload-identity-pools create $POOL_NAME \
    --project=$PROJECT_ID \
    --location="global" \
    --display-name="ArgoCD Workload Identity Pool"

# Create an OIDC provider trusting your Kubernetes cluster
gcloud iam workload-identity-pools providers create-oidc $PROVIDER_NAME \
    --project=$PROJECT_ID \
    --location="global" \
    --workload-identity-pool=$POOL_NAME \
    --issuer-uri="$K8S_ISSUER_URL" \
    --attribute-mapping="google.subject=assertion.sub"
```

**Finding your Kubernetes OIDC issuer URL:**

For GKE:
```bash
export CLUSTER_NAME="my-cluster"
export CLUSTER_LOCATION="us-central1"

# GKE issuer URL format:
echo "https://container.googleapis.com/v1/projects/$PROJECT_ID/locations/$CLUSTER_LOCATION/clusters/$CLUSTER_NAME"
```

For EKS:
```bash
aws eks describe-cluster --name $CLUSTER_NAME \
    --query "cluster.identity.oidc.issuer" --output text
```

For self-managed clusters:
```bash
kubectl get --raw /.well-known/openid-configuration | jq -r '.issuer'
```

### Step 2: Create GCP Service Account

Create a GCP service account for the ArgoCD project:

```bash
export GCP_SA_NAME="argocd-project-production"
export GCP_SA_EMAIL="${GCP_SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

gcloud iam service-accounts create $GCP_SA_NAME \
    --project=$PROJECT_ID \
    --display-name="ArgoCD Production Project"
```

### Step 3: Grant Artifact Registry Access

Grant the GCP service account read access to Artifact Registry:

```bash
# For all repositories in the project
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${GCP_SA_EMAIL}" \
    --role="roles/artifactregistry.reader"

# Or for a specific repository
export REPO_NAME="my-charts"
export REPO_LOCATION="us-central1"

gcloud artifacts repositories add-iam-policy-binding $REPO_NAME \
    --project=$PROJECT_ID \
    --location=$REPO_LOCATION \
    --member="serviceAccount:${GCP_SA_EMAIL}" \
    --role="roles/artifactregistry.reader"
```

### Step 4: Allow K8s SA to Impersonate GCP SA

Grant the federated identity permission to impersonate the GCP service account:

```bash
export ARGOCD_NAMESPACE="argocd"
export ARGOCD_PROJECT="production"
export K8S_SA_NAME="argocd-project-${ARGOCD_PROJECT}"

# Build the principal identifier for Workload Identity Federation
export PRINCIPAL="principal://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_NAME}/subject/system:serviceaccount:${ARGOCD_NAMESPACE}:${K8S_SA_NAME}"

gcloud iam service-accounts add-iam-policy-binding $GCP_SA_EMAIL \
    --project=$PROJECT_ID \
    --role="roles/iam.workloadIdentityUser" \
    --member="$PRINCIPAL"
```

### Step 5: Create Project Service Account

Create a Kubernetes service account for the ArgoCD project with GCP annotations:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: argocd-project-production  # Format: argocd-project-<project-name>
  namespace: argocd
  annotations:
    # Required: GCP service account email to impersonate
    iam.gke.io/gcp-service-account: argocd-project-production@my-gcp-project.iam.gserviceaccount.com
    # Required for non-GKE clusters: Full Workload Identity Provider path
    iam.gke.io/workload-identity-provider: //iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/argocd-pool/providers/argocd-k8s
```

### Step 6: Create Repository Secret

Create the ArgoCD repository secret with GCP workload identity:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-artifact-registry-repo
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  type: helm  # or "oci" for generic OCI artifacts
  url: oci://us-central1-docker.pkg.dev/my-gcp-project/my-charts
  project: production  # Links to argocd-project-production service account

  # Enable workload identity
  useWorkloadIdentity: "true"
  workloadIdentityProvider: "gcp"

  # Optional: Override WIF audience (defaults to annotation on SA)
  # workloadIdentityAudience: //iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/argocd-pool/providers/argocd-k8s

  # Optional: Override STS endpoint
  # workloadIdentityTokenURL: "https://sts.googleapis.com/v1/token"
```

### Step 7: Create Application

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: my-app
  namespace: argocd
spec:
  project: production  # Must match the project in repository secret
  source:
    repoURL: oci://us-central1-docker.pkg.dev/my-gcp-project/my-charts
    chart: my-chart
    targetRevision: 1.0.0
  destination:
    server: https://kubernetes.default.svc
    namespace: my-app
```

## Multi-Project Setup

To support multiple projects with different Artifact Registry access:

### Project A (production)

```yaml
# Service Account
apiVersion: v1
kind: ServiceAccount
metadata:
  name: argocd-project-production
  namespace: argocd
  annotations:
    iam.gke.io/gcp-service-account: argocd-prod@my-gcp-project.iam.gserviceaccount.com
    iam.gke.io/workload-identity-provider: //iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/argocd-pool/providers/argocd-k8s
---
# Repository Secret
apiVersion: v1
kind: Secret
metadata:
  name: prod-registry
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  type: helm
  url: oci://us-central1-docker.pkg.dev/my-gcp-project/prod-charts
  project: production
  useWorkloadIdentity: "true"
  workloadIdentityProvider: "gcp"
```

**GCP permissions:**
```bash
gcloud iam service-accounts add-iam-policy-binding argocd-prod@my-gcp-project.iam.gserviceaccount.com \
    --role="roles/iam.workloadIdentityUser" \
    --member="principal://iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/argocd-pool/subject/system:serviceaccount:argocd:argocd-project-production"
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
    iam.gke.io/gcp-service-account: argocd-staging@my-gcp-project.iam.gserviceaccount.com
    iam.gke.io/workload-identity-provider: //iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/argocd-pool/providers/argocd-k8s
---
# Repository Secret
apiVersion: v1
kind: Secret
metadata:
  name: staging-registry
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  type: helm
  url: oci://us-central1-docker.pkg.dev/my-gcp-project/staging-charts
  project: staging
  useWorkloadIdentity: "true"
  workloadIdentityProvider: "gcp"
```

## GKE Workload Identity (Simplified)

For GKE clusters with Workload Identity enabled, setup is simpler:

### Step 1: Enable GKE Workload Identity

```bash
# Enable on existing cluster
gcloud container clusters update $CLUSTER_NAME \
    --workload-pool=${PROJECT_ID}.svc.id.goog

# Or when creating a new cluster
gcloud container clusters create $CLUSTER_NAME \
    --workload-pool=${PROJECT_ID}.svc.id.goog
```

### Step 2: Bind K8s SA to GCP SA

```bash
gcloud iam service-accounts add-iam-policy-binding $GCP_SA_EMAIL \
    --role="roles/iam.workloadIdentityUser" \
    --member="serviceAccount:${PROJECT_ID}.svc.id.goog[argocd/argocd-project-production]"
```

### Step 3: Annotate K8s Service Account

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: argocd-project-production
  namespace: argocd
  annotations:
    # Only this annotation is needed for GKE Workload Identity
    iam.gke.io/gcp-service-account: argocd-prod@my-gcp-project.iam.gserviceaccount.com
```

Note: The `workload-identity-provider` annotation is not required for GKE as it uses the metadata server.

## Troubleshooting

### Error: "service account missing iam.gke.io/gcp-service-account annotation"

The Kubernetes service account doesn't have the required annotation.

**Solution:**
1. Verify the service account exists: `kubectl get sa argocd-project-<project> -n argocd`
2. Add the `iam.gke.io/gcp-service-account` annotation with the GCP SA email

### Error: "workload identity provider audience not specified"

Neither the repository secret nor the service account has the WIF audience configured.

**Solution (for non-GKE clusters):**
1. Add `workloadIdentityAudience` to the repository secret, OR
2. Add `iam.gke.io/workload-identity-provider` annotation to the service account

### Error: "STS token exchange failed: 400 Bad Request"

The K8s JWT couldn't be exchanged for a federated token.

**Solution:**
1. Verify the Workload Identity Pool OIDC provider has the correct issuer URL
2. Check the K8s cluster's OIDC issuer is publicly accessible
3. Verify the audience matches the WIF provider path

### Error: "impersonate service account failed: 403 Forbidden"

The federated identity doesn't have permission to impersonate the GCP SA.

**Solution:**
1. Verify the `roles/iam.workloadIdentityUser` binding exists
2. Check the principal format matches exactly:
   - For WIF: `principal://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL/subject/system:serviceaccount:NAMESPACE:SA_NAME`
   - For GKE: `serviceAccount:PROJECT_ID.svc.id.goog[NAMESPACE/SA_NAME]`

### Error: "metadata request failed: connection refused"

Running on non-GKE cluster where metadata server is unavailable.

**Solution:**
This is expected for non-GKE clusters. The provider automatically falls back to STS token exchange. Ensure:
1. Service account has `iam.gke.io/workload-identity-provider` annotation
2. Repository secret has `workloadIdentityAudience` set (or SA annotation)

### Error: "401 Unauthorized" at Artifact Registry

Authentication succeeded but the GCP SA doesn't have access.

**Solution:**
1. Verify the GCP service account has `roles/artifactregistry.reader`
2. Check if the repository has specific IAM policies

## Security Considerations

1. **Least privilege GCP IAM**: Grant only `artifactregistry.reader` role, scoped to specific repositories when possible.

2. **Workload Identity Pool isolation**: Consider separate pools for different trust levels (production vs development).

3. **Attribute conditions**: Add conditions to WIF providers to restrict which subjects can authenticate:
   ```bash
   gcloud iam workload-identity-pools providers update-oidc $PROVIDER_NAME \
       --attribute-condition="assertion.sub.startsWith('system:serviceaccount:argocd:')"
   ```

4. **Audit logging**: Enable Cloud Audit Logs to monitor service account impersonation.

5. **Token lifetime**: GCP access tokens are valid for 1 hour by default.

## References

- [GCP Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation)
- [GKE Workload Identity](https://cloud.google.com/kubernetes-engine/docs/concepts/workload-identity)
- [Artifact Registry Authentication](https://cloud.google.com/artifact-registry/docs/docker/authentication)
- [GCP IAM Service Account Impersonation](https://cloud.google.com/iam/docs/impersonating-service-accounts)
