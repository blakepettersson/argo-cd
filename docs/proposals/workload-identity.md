---
title: Workload Identity for Repository Authentication
authors:
  - "@blakepettersson" # Replace with actual GitHub handle
sponsors:
  - TBD
reviewers:
  - "@sabre1041"
  - TBD
approvers:
  - TBD

creation-date: 2025-01-21
last-updated: 2025-01-21
---

# Workload Identity for Repository Authentication

Enable ArgoCD to authenticate to container registries and Git repositories using cloud-native workload identity instead of static credentials.

## Summary

This proposal introduces workload identity support for ArgoCD repository authentication. Instead of storing long-lived 
credentials (passwords, tokens, service account keys) in Kubernetes secrets, ArgoCD can authenticate to registries using 
short-lived tokens obtained through cloud provider workload identity mechanisms (AWS IRSA, GCP Workload Identity, 
Azure Workload Identity) or OIDC federation (SPIFFE/SPIRE, direct K8s OIDC).

The implementation adds a new `useWorkloadIdentity` field to repository configuration and a `workloadIdentityProvider` 
field to specify which identity mechanism to use. Credentials are resolved at runtime by exchanging Kubernetes service 
account tokens for registry-specific credentials.

## Motivation

Modern cloud-native environments are moving away from static credentials toward identity-based authentication. This 
shift provides significant security benefits. While there is some ad-hoc support for it in some places, the existing 
implementations of it have a few issues.

**Current State:**
- ArgoCD stores registry credentials (username/password, tokens) in Kubernetes secrets
- These credentials are long-lived and must be manually rotated
- Credential leakage poses significant security risks
- No per-project credential isolation for multi-tenant deployments
- The existing implementation of Workload Identity is in practice scoped on the whole repo-server, meaning that there
  is no granularity between projects.
- There is only a single existing implementation for Azure, lacking support for other clouds as well as on-prem
- The repo-server is the entry point of the existing implementation, breaking its "dumbness" (it is only supposed to
  generate manifests from credentials given, not wrangle with workload identity, needing to add IAM setup to it etc.)

**Desired State:**
- Zero static credentials stored for registry access
- Automatic credential rotation through short-lived tokens
- Per-project identity isolation using Kubernetes service accounts
- Native integration with cloud provider identity systems

### Goals

1. **Eliminate static credentials**: Enable repository authentication without storing long-lived passwords or tokens in secrets.

2. **Support major cloud providers**: Implement native support for:
   - AWS IRSA (IAM Roles for Service Accounts) for ECR
   - GCP Workload Identity Federation for Artifact Registry/GCR
   - Azure Workload Identity for ACR

3. **Support SPIFFE/SPIRE**: Enable workload identity using SPIFFE JWT-SVIDs with delegated identity for per-project isolation.

4. **Support generic OIDC**: Enable authentication to any registry that supports OIDC federation (Harbor, Quay, GitLab, etc.) via RFC 8693 token exchange.

5. **Per-project isolation**: Each ArgoCD project can use a different identity, allowing fine-grained access control at the cloud IAM level.

6. **Backward compatibility**: Existing repositories with static credentials continue to work unchanged.

### Non-Goals

1. **Git repository workload identity**: While the architecture supports it, the initial implementation focuses on OCI/Helm registries. Git providers have varying OIDC support.

2. **Credential caching**: Token caching with TTL management may be added in a future enhancement.

3. **Automatic cloud IAM setup**: Users must configure cloud provider IAM roles/policies manually.

4. **EKS Pod Identity support**: The implementation uses IRSA rather than the newer EKS Pod Identity because ArgoCD needs to assume different roles per project from a single pod.

## Proposal

### Use Cases

#### Use case 1: AWS ECR with IRSA
As an operator running ArgoCD on EKS, I want to authenticate to ECR without storing AWS credentials, using IAM roles mapped to Kubernetes service accounts.

#### Use case 2: GCP Artifact Registry with Workload Identity
As an operator running ArgoCD on GKE or any Kubernetes cluster, I want to authenticate to Artifact Registry using GCP Workload Identity Federation without service account keys.

#### Use case 3: Azure ACR with Workload Identity
As an operator running ArgoCD on AKS, I want to authenticate to ACR using Azure Workload Identity without storing service principal secrets.

#### Use case 4: SPIFFE/SPIRE with Quay
As an operator using SPIRE for workload identity, I want ArgoCD to authenticate to Quay using SPIFFE JWT-SVIDs with per-project SPIFFE identities.

#### Use case 5: Multi-tenant isolation
As a platform team, I want different ArgoCD projects to use different cloud IAM roles, so project A can only access production ECR repositories while project B can only access staging repositories.

#### Use case 6: Harbor with K8s OIDC
As an operator using Harbor, I want to configure Harbor to trust my Kubernetes cluster's OIDC issuer and have ArgoCD authenticate using service account tokens directly.

### Implementation Details

#### Architecture

The implementation follows a provider-based architecture where credential resolution is pluggable:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      Repository Configuration                            │
│  useWorkloadIdentity: true                                              │
│  workloadIdentityProvider: "aws" | "gcp" | "azure" | "spiffe" | "oidc" │
│  project: "production"                                                  │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         Workload Identity Resolver                       │
│  1. Lookup service account: argocd-project-{project}                    │
│  2. Read provider annotations from service account                      │
│  3. Request K8s token via TokenRequest API                              │
│  4. Exchange token using provider-specific flow                         │
│  5. Return Credentials{Username, Password}                              │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
                    ▼               ▼               ▼
              ┌─────────┐    ┌─────────┐    ┌─────────┐
              │   AWS   │    │   GCP   │    │  Azure  │    ...
              │  (IRSA) │    │  (WIF)  │    │  (WI)   │
              └─────────┘    └─────────┘    └─────────┘
```

#### Service Account Naming Convention

Each ArgoCD project maps to a Kubernetes service account:

```
Project Name                   → Service Account Name
"production"                   → argocd-project-production
"staging"                      → argocd-project-staging
""  (non-scoped credential)    → argocd-global
```

#### Provider-Specific Flows

**AWS (IRSA):**
1. Request K8s token with audience `sts.amazonaws.com`
2. Call STS `AssumeRoleWithWebIdentity` with the K8s JWT
3. Use temporary credentials to call ECR `GetAuthorizationToken`
4. Return ECR credentials (username: AWS, password: base64-decoded token)

**GCP (Workload Identity Federation):**
1. Request K8s token with WIF provider audience
2. Exchange K8s JWT for federated token via GCP STS
3. Impersonate target GCP service account
4. Return credentials (username: oauth2accesstoken, password: access token)

**Azure (Workload Identity):**
1. Request K8s token with audience `api://AzureADTokenExchange`
2. Exchange K8s JWT for Azure access token via Azure AD
3. Exchange Azure token for ACR refresh token
4. Return ACR credentials

**SPIFFE/SPIRE:**
1. Fetch JWT-SVID for project's SPIFFE ID using delegated identity
2. If registry auth URL configured, exchange JWT for registry token
3. Return credentials

**OIDC (Generic):**
1. Request K8s token with configured audience
2. Optionally exchange via RFC 8693 token exchange
3. Authenticate to registry using Docker Registry v2 token auth
4. Return credentials

#### Repository Secret Configuration

New fields added to repository secrets:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-ecr-repo
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  type: helm
  url: oci://123456789012.dkr.ecr.us-west-2.amazonaws.com/charts
  project: production

  # Workload identity fields
  useWorkloadIdentity: "true"
  workloadIdentityProvider: "aws"  # aws, gcp, azure, spiffe, oidc

  # Optional provider-specific fields
  workloadIdentityTokenURL: ""       # Override token endpoint
  workloadIdentityAudience: ""       # Custom audience
  workloadIdentityRegistryAuthURL: "" # Registry auth endpoint (oidc provider)
  workloadIdentityRegistryService: "" # Registry service name (oidc provider)
  workloadIdentityRegistryUsername: "" # Username for Basic Auth (oidc provider)
```

#### Service Account Annotations

Provider-specific configuration is read from service account annotations:

**AWS:**
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: argocd-project-production
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/argocd-prod
```

**GCP:**
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: argocd-project-production
  annotations:
    iam.gke.io/gcp-service-account: argocd@project.iam.gserviceaccount.com
    iam.gke.io/workload-identity-provider: //iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider
```

**Azure:**
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: argocd-project-production
  annotations:
    azure.workload.identity/client-id: "client-id-uuid"
    azure.workload.identity/tenant-id: "tenant-id-uuid"
```

#### Integration Point

Workload identity resolution is integrated into `util/db/repository.go` in the `GetRepository` function:

```go
func (db *db) GetRepository(ctx context.Context, repoURL, project string) (*v1alpha1.Repository, error) {
    repository, err := db.getRepository(ctx, repoURL, project)
    if err != nil {
        return repository, err
    }

    if err := db.enrichCredsToRepo(ctx, repository); err != nil {
        return repository, err
    }

    // Resolve workload identity credentials if enabled
    if repository.UseWorkloadIdentity {
        if err := db.enrichWorkloadIdentity(ctx, repository); err != nil {
            return repository, err
        }
    }

    return repository, err
}
```

This location ensures credentials are resolved before any component (app-controller, repo-server) uses the repository.

### Detailed Examples

#### Example 1: AWS ECR with Multi-Project Setup

```yaml
# Service Account for production project
apiVersion: v1
kind: ServiceAccount
metadata:
  name: argocd-project-production
  namespace: argocd
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/argocd-prod
---
# Repository pointing to production ECR
apiVersion: v1
kind: Secret
metadata:
  name: prod-ecr
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  type: helm
  url: oci://123456789012.dkr.ecr.us-west-2.amazonaws.com/prod-charts
  project: production
  useWorkloadIdentity: "true"
  workloadIdentityProvider: "aws"
---
# Application using the repository
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: my-app
spec:
  project: production
  source:
    repoURL: oci://123456789012.dkr.ecr.us-west-2.amazonaws.com/prod-charts
    chart: my-chart
    targetRevision: 1.0.0
```

#### Example 2: SPIFFE/SPIRE with Quay Robot Federation

```yaml
# Service Account for project (SPIRE entry must exist)
apiVersion: v1
kind: ServiceAccount
metadata:
  name: argocd-project-default
  namespace: argocd
---
# Repository with SPIFFE workload identity
apiVersion: v1
kind: Secret
metadata:
  name: quay-repo
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  type: helm
  url: oci://quay.example.org/myorg/charts
  project: default
  useWorkloadIdentity: "true"
  workloadIdentityProvider: "spiffe"
  workloadIdentityAudience: "quay.example.org"
  workloadIdentityRegistryAuthURL: "https://quay.example.org/oauth2/federation/robot/token"
  workloadIdentityRegistryService: "quay.example.org"
  workloadIdentityRegistryUsername: "myorg+argocd"
```

### Security Considerations

1. **Short-lived tokens**: All credentials obtained through workload identity are short-lived (typically 1 hour), reducing the impact of credential leakage.
2. **No stored secrets**: Long-lived credentials are never stored in Kubernetes secrets, eliminating a common attack vector.
3. **Cloud IAM integration**: Access control is enforced at the cloud IAM level, providing fine-grained permissions.
4. **Per-project isolation**: Each project can have its own identity with its own IAM permissions, preventing cross-project access.
5. **SPIFFE admin delegation (N/A for other implementations) **: The SPIFFE provider requires the application-controller to have `admin: true` in its SPIRE entry to request JWTs for project service accounts. This is a privileged operation that should only be granted to trusted components.
6. **TokenRequest API (for non-SPIFFE credentials) **: The implementation uses the Kubernetes TokenRequest API which provides bound service account tokens with configurable audiences and expiration.

### Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Cloud IAM misconfiguration grants excessive access | Documentation includes least-privilege IAM policy examples |
| SPIFFE admin flag allows impersonation of any registered SPIFFE ID | Only grant admin to application-controller; document security implications |
| Token exchange failures cause sync failures | Clear error messages; fallback to existing credential mechanisms if configured |
| Complex setup for users unfamiliar with workload identity | Comprehensive documentation with step-by-step guides for each provider |

### Upgrade / Downgrade Strategy

**Upgrade:**
- The `useWorkloadIdentity` field defaults to `false`, so existing repositories continue to work unchanged
- Users opt-in to workload identity by setting `useWorkloadIdentity: "true"` and configuring the provider
- No migration required for existing deployments

**Downgrade:**
- Repositories with `useWorkloadIdentity: "true"` will fail to authenticate on older versions
- Users must set `useWorkloadIdentity: "false"` and provide static credentials before downgrading
- The field is ignored by older versions that don't recognize it

## Drawbacks

1. **Complexity**: Workload identity setup requires understanding cloud IAM concepts that may be unfamiliar to some users.
2. **Cloud provider dependency**: Each cloud provider has different setup requirements, increasing documentation and testing burden.
3. **SPIFFE/SPIRE adoption**: The SPIFFE provider requires SPIRE infrastructure which adds operational complexity.
4. **No EKS Pod Identity support**: The implementation uses IRSA instead of the newer EKS Pod Identity because ArgoCD needs per-project identity assumption, which Pod Identity doesn't support.

## Alternatives

### Alternative 1: External Secrets Operator Integration

Use External Secrets Operator to sync credentials from cloud secret managers (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault).

**Pros:**
- Works with existing ArgoCD without code changes
- Credentials can be rotated in secret manager

**Cons:**
- Still stores credentials in Kubernetes secrets (even if synced)
- Requires additional operator installation

