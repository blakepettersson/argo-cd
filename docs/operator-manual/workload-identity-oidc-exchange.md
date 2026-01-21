# OIDC Exchange Workload Identity for ArgoCD

This guide explains how to configure ArgoCD to use OIDC token exchange for workload identity authentication with custom OIDC providers and registries.

## Overview

The OIDC provider (`workloadIdentityProvider: "oidc"`) enables ArgoCD to authenticate to container registries using:

- **RFC 8693 OAuth 2.0 Token Exchange**: Exchange K8s JWT for an identity token
- **Direct K8s OIDC**: Use K8s service account tokens directly with OIDC-enabled registries
- **Registry Token Authentication**: Docker Registry v2 token-based authentication

This provides flexibility to integrate with:

- Custom OIDC identity providers
- Self-hosted registries (Harbor, GitLab Registry, etc.)
- Registries with OIDC federation (Quay, etc.)
- Any system supporting RFC 8693 token exchange

## Architecture

The OIDC exchange provider supports three authentication modes:

### Mode 1: Two-Step Token Exchange

```
┌─────────────────┐     ┌────────────────────┐     ┌─────────────┐
│ ArgoCD (K8s SA) │────▶│ Identity Provider  │────▶│  Registry   │
│    Token        │     │  (Token Exchange)  │     │   (Auth)    │
└─────────────────┘     └────────────────────┘     └─────────────┘
         │                       │                        │
         │ 1. K8s JWT            │ 2. Identity Token      │ 3. Registry Token
         ▼                       ▼                        ▼
    TokenRequest API      RFC 8693 Exchange       Docker Registry Auth
```

**Use when:** You have an intermediate identity provider (SPIFFE proxy, custom OAuth server).

### Mode 2: Single-Step Token Exchange

```
┌─────────────────┐     ┌────────────────────┐
│ ArgoCD (K8s SA) │────▶│  Token Exchange    │
│    Token        │     │     Service        │
└─────────────────┘     └────────────────────┘
         │                       │
         │ 1. K8s JWT            │ 2. Bearer Token
         ▼                       ▼
    TokenRequest API      RFC 8693 Exchange
```

**Use when:** Token exchange returns credentials that work directly with the registry.

### Mode 3: Direct K8s OIDC

```
┌─────────────────┐     ┌─────────────────┐
│ ArgoCD (K8s SA) │────▶│    Registry     │
│    Token        │     │   (OIDC Auth)   │
└─────────────────┘     └─────────────────┘
         │                      │
         │ 1. K8s JWT           │ 2. Registry Token
         ▼                      ▼
    TokenRequest API     Direct OIDC Validation
```

**Use when:** Registry directly trusts K8s OIDC (simplest setup, no intermediate IdP).

## Configuration Reference

### Repository Secret Fields

| Field | Required | Description |
|-------|----------|-------------|
| `useWorkloadIdentity` | Yes | Set to `"true"` to enable |
| `workloadIdentityProvider` | Yes | Set to `"oidc"` |
| `workloadIdentityTokenURL` | Mode 1,2 | RFC 8693 token exchange endpoint |
| `workloadIdentityAudience` | Mode 1,2 | Audience for token exchange |
| `workloadIdentityRegistryAuthURL` | Mode 1,3 | Docker Registry v2 auth endpoint |
| `workloadIdentityRegistryService` | Optional | Registry service name (auto-detected from URL) |
| `workloadIdentityRegistryUsername` | Optional | Username for Basic Auth (e.g., robot accounts) |
| `insecure` | Optional | Skip TLS verification |

### Mode Selection Logic

```
if tokenURL is set:
    → Mode 1 or 2 (token exchange)
    if registryAuthURL is set:
        → Mode 1 (two-step)
    else:
        → Mode 2 (single-step, token is password)
else:
    if registryAuthURL is set:
        → Mode 3 (direct K8s OIDC)
    else:
        → Error (must specify tokenURL or registryAuthURL)
```

## Setup Examples

### Harbor with K8s OIDC (Mode 3)

Configure Harbor to trust your Kubernetes cluster's OIDC issuer directly.

#### Step 1: Get K8s OIDC Issuer

```bash
# For self-managed clusters
kubectl get --raw /.well-known/openid-configuration | jq -r '.issuer'

# For EKS
aws eks describe-cluster --name $CLUSTER_NAME \
    --query "cluster.identity.oidc.issuer" --output text

# For GKE
# https://container.googleapis.com/v1/projects/$PROJECT/locations/$LOCATION/clusters/$CLUSTER
```

#### Step 2: Configure Harbor OIDC

In Harbor Administration > Configuration > Authentication:

| Setting | Value |
|---------|-------|
| Auth Mode | OIDC |
| OIDC Provider Name | Kubernetes |
| OIDC Endpoint | `<k8s-oidc-issuer-url>` |
| OIDC Client ID | `harbor` (or your chosen audience) |
| OIDC Scope | `openid` |
| Verify Certificate | `true` |
| Automatic Onboarding | `true` |
| Username Claim | `sub` |

#### Step 3: Create Service Account

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: argocd-project-default
  namespace: argocd
```

#### Step 4: Create Repository Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: harbor-repo
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  type: helm
  url: oci://harbor.example.com/library/charts
  project: default
  useWorkloadIdentity: "true"
  workloadIdentityProvider: "oidc"
  workloadIdentityAudience: "harbor"
  workloadIdentityRegistryAuthURL: "https://harbor.example.com/service/token"
  workloadIdentityRegistryService: "harbor-registry"
```

### Quay with Robot Federation (Mode 1)

Configure Quay to use robot account federation with K8s OIDC.

#### Step 1: Create Quay Robot Account

1. In Quay, navigate to your organization
2. Create a robot account (e.g., `myorg+argocd`)
3. Grant the robot read access to your repositories

#### Step 2: Configure Robot Federation

In the robot account settings, add OIDC federation:

| Setting | Value |
|---------|-------|
| Issuer | `<k8s-oidc-issuer-url>` |
| Subject | `system:serviceaccount:argocd:argocd-project-default` |

#### Step 3: Create Service Account

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: argocd-project-default
  namespace: argocd
```

#### Step 4: Create Repository Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: quay-repo
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  type: helm
  url: oci://quay.example.com/myorg/charts
  project: default
  useWorkloadIdentity: "true"
  workloadIdentityProvider: "oidc"
  workloadIdentityAudience: "quay.example.com"
  workloadIdentityRegistryAuthURL: "https://quay.example.com/oauth2/federation/robot/token"
  workloadIdentityRegistryService: "quay.example.com"
  workloadIdentityRegistryUsername: "myorg+argocd"
```

Note: When `workloadIdentityRegistryUsername` is set, the provider uses Basic Auth with the K8s JWT as the password. This is required for Quay robot federation.

### Custom Token Exchange Service (Mode 2)

For custom identity providers that implement RFC 8693.

#### Step 1: Create Service Account

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: argocd-project-default
  namespace: argocd
```

#### Step 2: Create Repository Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: custom-repo
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  type: helm
  url: oci://registry.example.com/charts
  project: default
  useWorkloadIdentity: "true"
  workloadIdentityProvider: "oidc"
  # RFC 8693 token exchange endpoint
  workloadIdentityTokenURL: "https://idp.example.com/oauth2/token"
  workloadIdentityAudience: "registry.example.com"
  # If registry also needs token exchange
  workloadIdentityRegistryAuthURL: "https://registry.example.com/v2/auth"
  workloadIdentityRegistryService: "registry.example.com"
```

### GitLab Container Registry

GitLab supports OIDC for container registry authentication.

#### Step 1: Configure GitLab OIDC

In GitLab Admin > Settings > General > Sign-in restrictions, enable OIDC authentication and configure to trust your K8s cluster.

#### Step 2: Create Repository Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: gitlab-repo
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  type: helm
  url: oci://registry.gitlab.example.com/group/project
  project: default
  useWorkloadIdentity: "true"
  workloadIdentityProvider: "oidc"
  workloadIdentityAudience: "gitlab"
  workloadIdentityRegistryAuthURL: "https://registry.gitlab.example.com/jwt/auth"
  workloadIdentityRegistryService: "container_registry"
```

## Multi-Project Setup

### Project Isolation with Different Registries

```yaml
# Production - Harbor
apiVersion: v1
kind: ServiceAccount
metadata:
  name: argocd-project-production
  namespace: argocd
---
apiVersion: v1
kind: Secret
metadata:
  name: prod-harbor
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  type: helm
  url: oci://harbor.example.com/production/charts
  project: production
  useWorkloadIdentity: "true"
  workloadIdentityProvider: "oidc"
  workloadIdentityAudience: "harbor"
  workloadIdentityRegistryAuthURL: "https://harbor.example.com/service/token"
---
# Staging - Quay
apiVersion: v1
kind: ServiceAccount
metadata:
  name: argocd-project-staging
  namespace: argocd
---
apiVersion: v1
kind: Secret
metadata:
  name: staging-quay
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  type: helm
  url: oci://quay.example.com/staging/charts
  project: staging
  useWorkloadIdentity: "true"
  workloadIdentityProvider: "oidc"
  workloadIdentityAudience: "quay.example.com"
  workloadIdentityRegistryAuthURL: "https://quay.example.com/oauth2/federation/robot/token"
  workloadIdentityRegistryUsername: "staging+argocd"
```

## RFC 8693 Token Exchange Details

The OIDC exchange provider implements RFC 8693 OAuth 2.0 Token Exchange:

**Request:**
```http
POST /oauth2/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&subject_token=<k8s-jwt>
&subject_token_type=urn:ietf:params:oauth:token-type:jwt
&requested_token_type=urn:ietf:params:oauth:token-type:access_token
&audience=<registry-audience>
```

**Response:**
```json
{
    "access_token": "<exchanged-token>",
    "token_type": "Bearer",
    "expires_in": 3600
}
```

## Docker Registry v2 Token Auth

For registry authentication, the provider implements Docker Registry v2 token authentication:

**Request (Bearer mode):**
```http
GET /service/token?service=registry&scope=repository:charts/mychart:pull HTTP/1.1
Authorization: Bearer <identity-token>
```

**Request (Basic mode, when username is set):**
```http
GET /service/token?service=registry&scope=repository:charts/mychart:pull HTTP/1.1
Authorization: Basic <base64(username:identity-token)>
```

**Response:**
```json
{
    "token": "<registry-token>",
    "expires_in": 3600
}
```

## Troubleshooting

### Error: "either workloadIdentityTokenURL or workloadIdentityRegistryAuthURL must be specified"

The repository secret doesn't have the required configuration.

**Solution:** Specify at least one of:
- `workloadIdentityTokenURL` for token exchange
- `workloadIdentityRegistryAuthURL` for direct registry auth

### Error: "workloadIdentityAudience not specified for oidc provider with tokenURL"

Token exchange requires an audience.

**Solution:** Add `workloadIdentityAudience` to the repository secret.

### Error: "token exchange failed with status 400"

The token exchange endpoint rejected the request.

**Solution:**
1. Verify the K8s JWT audience matches what the token exchange service expects
2. Check if the token exchange service trusts your K8s OIDC issuer
3. Verify the `subject` claim format is correct

### Error: "registry token request failed with status 401"

The registry rejected the identity token.

**Solution:**
1. Verify the registry trusts the identity token's issuer
2. For Basic Auth mode, check `workloadIdentityRegistryUsername` is correct
3. Verify the K8s service account subject matches the registry's OIDC config

### Error: "registry token response missing token field"

The registry returned an unexpected response format.

**Solution:**
1. Verify `workloadIdentityRegistryAuthURL` points to the correct endpoint
2. Check if the registry uses `token` or `access_token` field (both are supported)
3. Test the endpoint manually with curl

### Testing Token Exchange Manually

```bash
# Get a K8s token
TOKEN=$(kubectl create token argocd-project-default -n argocd --audience=my-audience)

# Test RFC 8693 exchange
curl -X POST https://idp.example.com/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=$TOKEN" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:jwt" \
  -d "audience=registry.example.com"

# Test registry auth (Bearer)
curl "https://registry.example.com/service/token?service=registry&scope=repository:charts/mychart:pull" \
  -H "Authorization: Bearer $TOKEN"

# Test registry auth (Basic)
curl "https://registry.example.com/service/token?service=registry&scope=repository:charts/mychart:pull" \
  -u "myrobot:$TOKEN"
```

## Security Considerations

1. **Trust chain**: Ensure each component in the chain (K8s OIDC → IdP → Registry) properly validates tokens.

2. **Audience validation**: Always set explicit audiences to prevent token reuse attacks.

3. **TLS verification**: Only set `insecure: "true"` for development environments.

4. **Subject binding**: Configure registries to validate the `sub` claim matches expected service accounts.

5. **Token lifetime**: K8s tokens requested via TokenRequest API have configurable expiration (default varies by cluster).

## References

- [RFC 8693 - OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693)
- [Docker Registry Token Authentication](https://docs.docker.com/registry/spec/auth/token/)
- [Harbor OIDC Authentication](https://goharbor.io/docs/latest/administration/configure-authentication/oidc-auth/)
- [Quay Robot Account Federation](https://docs.redhat.com/en/documentation/red_hat_quay/3/html/use_red_hat_quay/robot-account-federation)
- [Kubernetes TokenRequest API](https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-request-v1/)
