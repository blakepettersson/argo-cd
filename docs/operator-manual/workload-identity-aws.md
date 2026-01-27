# AWS IRSA Workload Identity for ArgoCD

This guide explains how to configure ArgoCD to use AWS IAM Roles for Service Accounts (IRSA) for workload identity authentication with Amazon ECR and AWS CodeCommit.

## Overview

The AWS provider enables ArgoCD to authenticate to AWS services using IRSA. This provides:

- **Zero static credentials**: No long-lived AWS access keys stored in secrets
- **Per-project isolation**: Each ArgoCD project can assume a different IAM role
- **Fine-grained access control**: IAM policies control which repositories each project can access
- **Automatic credential rotation**: Temporary credentials are refreshed automatically

## Supported AWS Services

| Service | Repository Type | Use Case |
|---------|-----------------|----------|
| **Amazon ECR** | OCI/Helm | Container images, Helm charts stored in ECR |
| **AWS CodeCommit** | Git | Git repositories hosted in CodeCommit |

## Architecture

### ECR Authentication Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        ArgoCD Application Controller                         │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ 1. Resolve workload identity for project "production"                   ││
│  │    → Service account: argocd-project-production                         ││
│  │    → Role ARN from annotation: arn:aws:iam::123456789012:role/argocd-prod│
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Kubernetes TokenRequest API                          │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ 2. Request K8s JWT for service account with audience "sts.amazonaws.com"││
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              AWS STS                                         │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ 3. AssumeRoleWithWebIdentity                                            ││
│  │    - Validates K8s JWT against EKS OIDC provider                        ││
│  │    - Checks IAM role trust policy                                       ││
│  │    - Returns temporary AWS credentials                                  ││
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    ▼                               ▼
┌───────────────────────────────────┐ ┌───────────────────────────────────────┐
│           AWS ECR                 │ │         AWS CodeCommit                │
│  ┌─────────────────────────────┐  │ │  ┌─────────────────────────────────┐  │
│  │ 4a. GetAuthorizationToken   │  │ │  │ 4b. Generate SigV4 signed       │  │
│  │   - Returns Docker creds    │  │ │  │     Git credentials             │  │
│  └─────────────────────────────┘  │ │  └─────────────────────────────────┘  │
└───────────────────────────────────┘ └───────────────────────────────────────┘
```

## Prerequisites

1. **EKS cluster** with OIDC provider configured
2. **IAM permissions** to create roles and policies
3. **ECR repositories** or **CodeCommit repositories** accessible from your cluster

## Configuration Steps

### Step 1: Configure EKS OIDC Provider

Ensure your EKS cluster has an OIDC provider configured:

```bash
export CLUSTER_NAME="<your-cluster-name>"
export AWS_REGION="<your-region>"

# Check if OIDC provider exists
aws eks describe-cluster --name $CLUSTER_NAME \
    --query "cluster.identity.oidc.issuer" --output text

# If not set up, create the OIDC provider
eksctl utils associate-iam-oidc-provider --cluster $CLUSTER_NAME --approve
```

Get the OIDC provider URL and account ID:

```bash
export OIDC_PROVIDER=$(aws eks describe-cluster --name $CLUSTER_NAME \
    --query "cluster.identity.oidc.issuer" --output text | sed -e "s/^https:\/\///")
export AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
```

### Step 2: Create IAM Policy

#### For ECR Access

```bash
cat <<EOF > ecr-policy.json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ecr:GetAuthorizationToken"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ecr:BatchCheckLayerAvailability",
                "ecr:GetDownloadUrlForLayer",
                "ecr:BatchGetImage"
            ],
            "Resource": "arn:aws:ecr:${AWS_REGION}:${AWS_ACCOUNT_ID}:repository/*"
        }
    ]
}
EOF

aws iam create-policy \
    --policy-name ArgoCD-ECR-ReadOnly \
    --policy-document file://ecr-policy.json
```

#### For CodeCommit Access

```bash
cat <<EOF > codecommit-policy.json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "codecommit:GitPull",
                "codecommit:GetBranch",
                "codecommit:GetCommit",
                "codecommit:GetRepository",
                "codecommit:ListBranches"
            ],
            "Resource": "arn:aws:codecommit:${AWS_REGION}:${AWS_ACCOUNT_ID}:*"
        }
    ]
}
EOF

aws iam create-policy \
    --policy-name ArgoCD-CodeCommit-ReadOnly \
    --policy-document file://codecommit-policy.json
```

For more restrictive access, limit the `Resource` to specific repositories:

```json
"Resource": [
    "arn:aws:ecr:us-west-2:123456789012:repository/production/*",
    "arn:aws:codecommit:us-west-2:123456789012:my-app-repo"
]
```

### Step 3: Create IAM Role with Trust Policy

```bash
export ARGOCD_NAMESPACE="argocd"
export PROJECT_NAME="production"
export ROLE_NAME="argocd-project-${PROJECT_NAME}"

cat <<EOF > trust-policy.json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Federated": "arn:aws:iam::${AWS_ACCOUNT_ID}:oidc-provider/${OIDC_PROVIDER}"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "${OIDC_PROVIDER}:sub": "system:serviceaccount:${ARGOCD_NAMESPACE}:argocd-project-${PROJECT_NAME}",
                    "${OIDC_PROVIDER}:aud": "sts.amazonaws.com"
                }
            }
        }
    ]
}
EOF

aws iam create-role \
    --role-name $ROLE_NAME \
    --assume-role-policy-document file://trust-policy.json

# Attach policies based on what you need
aws iam attach-role-policy \
    --role-name $ROLE_NAME \
    --policy-arn arn:aws:iam::${AWS_ACCOUNT_ID}:policy/ArgoCD-ECR-ReadOnly

aws iam attach-role-policy \
    --role-name $ROLE_NAME \
    --policy-arn arn:aws:iam::${AWS_ACCOUNT_ID}:policy/ArgoCD-CodeCommit-ReadOnly
```

### Step 4: Create Project Service Account

Create a Kubernetes service account for the ArgoCD project with the IAM role annotation:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: argocd-project-production  # Format: argocd-project-<project-name>
  namespace: argocd
  annotations:
    # Required: IAM role ARN to assume
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/argocd-project-production
```

## ECR Repository Configuration

### Repository Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-ecr-repo
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  type: helm  # or "oci" for generic OCI artifacts
  url: oci://123456789012.dkr.ecr.us-west-2.amazonaws.com/charts
  project: production  # Links to argocd-project-production service account

  # Enable AWS workload identity
  workloadIdentityProvider: aws

  # Optional: Override STS endpoint (for GovCloud, China regions)
  # workloadIdentityTokenURL: "https://sts.us-gov-west-1.amazonaws.com"
```

### Application Example

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: my-app
  namespace: argocd
spec:
  project: production  # Must match the project in repository secret
  source:
    repoURL: oci://123456789012.dkr.ecr.us-west-2.amazonaws.com/charts
    chart: my-chart
    targetRevision: 1.0.0
  destination:
    server: https://kubernetes.default.svc
    namespace: my-app
```

## CodeCommit Repository Configuration

### Repository Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-codecommit-repo
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  type: git
  url: https://git-codecommit.us-west-2.amazonaws.com/v1/repos/my-app-repo
  project: production  # Links to argocd-project-production service account

  # Enable AWS workload identity
  workloadIdentityProvider: aws

  # Optional: Override STS endpoint (for GovCloud, China regions)
  # workloadIdentityTokenURL: "https://sts.us-gov-west-1.amazonaws.com"
```

### Application Example

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: my-app
  namespace: argocd
spec:
  project: production  # Must match the project in repository secret
  source:
    repoURL: https://git-codecommit.us-west-2.amazonaws.com/v1/repos/my-app-repo
    path: manifests
    targetRevision: main
  destination:
    server: https://kubernetes.default.svc
    namespace: my-app
```

## Multi-Project Setup

### Project A (production) - ECR

```yaml
# Service Account
apiVersion: v1
kind: ServiceAccount
metadata:
  name: argocd-project-production
  namespace: argocd
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/argocd-project-production
---
# Repository Secret
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
  workloadIdentityProvider: aws
```

**IAM Trust Policy:**
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Federated": "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E"
            },
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E:sub": "system:serviceaccount:argocd:argocd-project-production",
                    "oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E:aud": "sts.amazonaws.com"
                }
            }
        }
    ]
}
```

### Project B (staging) - CodeCommit

```yaml
# Service Account
apiVersion: v1
kind: ServiceAccount
metadata:
  name: argocd-project-staging
  namespace: argocd
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/argocd-project-staging
---
# Repository Secret
apiVersion: v1
kind: Secret
metadata:
  name: staging-codecommit
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  type: git
  url: https://git-codecommit.us-west-2.amazonaws.com/v1/repos/staging-manifests
  project: staging
  workloadIdentityProvider: aws
```

### Mixed ECR and CodeCommit Setup

A single project can access both ECR and CodeCommit repositories if the IAM role has permissions for both:

```yaml
# Service Account with both ECR and CodeCommit access
apiVersion: v1
kind: ServiceAccount
metadata:
  name: argocd-project-platform
  namespace: argocd
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/argocd-project-platform
---
# ECR Repository for Helm charts
apiVersion: v1
kind: Secret
metadata:
  name: platform-ecr
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  type: helm
  url: oci://123456789012.dkr.ecr.us-west-2.amazonaws.com/platform-charts
  project: platform
  workloadIdentityProvider: aws
---
# CodeCommit Repository for manifests
apiVersion: v1
kind: Secret
metadata:
  name: platform-codecommit
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  type: git
  url: https://git-codecommit.us-west-2.amazonaws.com/v1/repos/platform-manifests
  project: platform
  workloadIdentityProvider: aws
```

## Region Detection

### ECR

The AWS region is automatically extracted from the ECR repository URL:

- `123456789012.dkr.ecr.us-west-2.amazonaws.com` → `us-west-2`
- `123456789012.dkr.ecr.eu-central-1.amazonaws.com` → `eu-central-1`

### CodeCommit

The AWS region is automatically extracted from the CodeCommit repository URL:

- `git-codecommit.us-west-2.amazonaws.com` → `us-west-2`
- `git-codecommit.eu-west-1.amazonaws.com` → `eu-west-1`

If the region cannot be determined, it defaults to `us-east-1`.

## AWS GovCloud and China Regions

For GovCloud or China regions, override the STS endpoint:

```yaml
# GovCloud
workloadIdentityTokenURL: "https://sts.us-gov-west-1.amazonaws.com"

# China (Beijing)
workloadIdentityTokenURL: "https://sts.cn-north-1.amazonaws.com.cn"

# China (Ningxia)
workloadIdentityTokenURL: "https://sts.cn-northwest-1.amazonaws.com.cn"
```

## Troubleshooting

### Error: "service account missing eks.amazonaws.com/role-arn annotation"

The Kubernetes service account doesn't have the required annotation.

**Solution:**
1. Verify the service account exists: `kubectl get sa argocd-project-<project> -n argocd`
2. Add the annotation with the IAM role ARN

### Error: "failed to assume role: AccessDenied"

The IAM trust policy doesn't allow the service account to assume the role.

**Solution:**
1. Verify the OIDC provider is correct in the trust policy
2. Check the `sub` condition matches exactly: `system:serviceaccount:<namespace>:<sa-name>`
3. Verify the `aud` condition is `sts.amazonaws.com`

### Error: "failed to get ECR authorization token: AccessDeniedException"

The IAM role doesn't have permission to call `ecr:GetAuthorizationToken`.

**Solution:**
1. Verify the IAM policy is attached to the role
2. Check the policy allows `ecr:GetAuthorizationToken` with `Resource: "*"`

### Error: "no ECR authorization data returned"

The ECR GetAuthorizationToken call succeeded but returned empty data.

**Solution:**
1. Verify you're calling ECR in the correct region
2. Check if the ECR service is available in your region

### Error: "failed to generate CodeCommit credentials"

The CodeCommit credential generation failed.

**Solution:**
1. Verify the IAM role has CodeCommit permissions
2. Check the repository URL format is correct: `https://git-codecommit.<region>.amazonaws.com/v1/repos/<repo-name>`
3. Ensure network connectivity to CodeCommit endpoints

### Error: "failed to create AWS session"

Unable to create AWS SDK session.

**Solution:**
1. Verify the AWS region is correct
2. Check network connectivity to AWS endpoints
3. For private clusters, ensure VPC endpoints are configured

## Note on EKS Pod Identity

This implementation uses IRSA (IAM Roles for Service Accounts) rather than the newer EKS Pod Identity feature. While EKS Pod Identity is simpler to set up for single-identity workloads, IRSA is required for ArgoCD's multi-tenant workload identity model because:

- ArgoCD needs to assume different IAM roles per project from a single controller pod
- IRSA allows exchanging any service account token via STS AssumeRoleWithWebIdentity
- EKS Pod Identity injects credentials at pod startup for only the pod's own service account

IRSA and EKS Pod Identity coexist on the same cluster - you can use Pod Identity for other workloads while using IRSA for ArgoCD's workload identity feature.

## Security Considerations

1. **Least privilege IAM policies**: Grant only the minimum permissions needed for each project.

2. **Repository-level restrictions**: Limit IAM policies to specific ECR repositories or CodeCommit repos when possible.

3. **Trust policy scope**: Each IAM role should only trust its specific service account.

4. **Audit logging**: Enable CloudTrail to audit AssumeRoleWithWebIdentity calls.

5. **Credential duration**: Temporary credentials are valid for 1 hour by default.

## References

- [AWS IAM Roles for Service Accounts](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html)
- [EKS OIDC Provider](https://docs.aws.amazon.com/eks/latest/userguide/enable-iam-roles-for-service-accounts.html)
- [ECR Authentication](https://docs.aws.amazon.com/AmazonECR/latest/userguide/registry_auth.html)
- [CodeCommit Authentication](https://docs.aws.amazon.com/codecommit/latest/userguide/auth-and-access-control.html)
- [AWS STS AssumeRoleWithWebIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html)