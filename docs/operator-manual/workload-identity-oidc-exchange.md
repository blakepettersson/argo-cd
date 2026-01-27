# OIDC/HTTP Template Workload Identity for ArgoCD

This guide explains how to configure ArgoCD to use OIDC token exchange and HTTP template-based authentication for workload identity with custom registries.

## Overview

The `k8s` identity provider combined with the `http` repository authenticator enables ArgoCD to authenticate to container registries using:

- **Direct K8s OIDC**: Use K8s service account tokens directly with OIDC-enabled registries
- **RFC 8693 Token Exchange**: Exchange K8s JWT for identity tokens
- **Custom HTTP Endpoints**: Template-based HTTP requests for any token exchange API

This provides flexibility to integrate with:

- Self-hosted registries (Harbor, Quay, GitLab Registry, etc.)
- Registries with OIDC federation (Quay robot federation, etc.)
- Custom identity providers
- Any system with HTTP-based token exchange

## Architecture

### K8s OIDC to Registry

```
┌─────────────────┐     ┌─────────────────┐
│ ArgoCD (K8s SA) │────▶│    Registry     │
│    Token        │     │   (OIDC Auth)   │
└─────────────────┘     └─────────────────┘
         │                      │
         │ 1. K8s JWT           │ 2. Registry Token
         ▼                      ▼
    TokenRequest API     HTTP Template Request
```

**Use when:** Registry directly trusts K8s OIDC tokens (simplest setup).

## Configuration Reference

### Repository Secret Fields

| Field | Required | Description |
|-------|----------|-------------|
| `workloadIdentityProvider` | Yes | Identity provider: `k8s`, `aws`, `gcp`, `azure`, `spiffe` |
| `workloadIdentityAudience` | Optional | Audience for the K8s JWT token |
| `workloadIdentityTokenURL` | Optional | Token URL for identity provider |
| `workloadIdentityUsername` | Optional | Username for Basic Auth (e.g., robot accounts) |
| `workloadIdentityAuthHost` | Optional | Override auth endpoint host (if different from registry) |
| `workloadIdentityPathTemplate` | Yes* | URL path template for auth request |
| `workloadIdentityBodyTemplate` | Optional | Request body template (for POST requests) |
| `workloadIdentityMethod` | Optional | HTTP method: `GET` (default) or `POST` |
| `workloadIdentityAuthType` | Optional | Auth type: `bearer` (default), `basic`, or `none` |
| `workloadIdentityParams` | Optional | Custom parameters for templates |
| `workloadIdentityResponseTokenField` | Optional | JSON field to extract from response (default: tries `access_token`, `token`, `refresh_token`) |
| `insecure` | Optional | Skip TLS verification |

*Required when using the HTTP template authenticator

### Template Variables

Templates use Go template syntax with [Sprig functions](http://masterminds.github.io/sprig/). Built-in variables:

| Variable | Description |
|----------|-------------|
| `{{ .token }}` | The identity token (K8s JWT or exchanged token) |
| `{{ .registry }}` | Registry host from repo URL |
| `{{ .repo }}` | Repository path from repo URL |
| `{{ .<param> }}` | Any custom param from `workloadIdentityParams` |

## Setup Examples

### Quay Robot Federation

Configure Quay to use robot account federation with K8s OIDC.

#### Step 1: Get K8s OIDC Issuer

```bash
# For self-managed clusters
kubectl get --raw /.well-known/openid-configuration | jq -r '.issuer'

# For EKS
aws eks describe-cluster --name $CLUSTER_NAME \
    --query "cluster.identity.oidc.issuer" --output text

# For GKE
gcloud container clusters describe $CLUSTER_NAME \
    --format="value(selfLink)"
```

#### Step 2: Create Quay Robot Account with Federation

1. In Quay, navigate to your organization
2. Create a robot account (e.g., `myorg+argocd`)
3. Grant the robot read access to your repositories
4. In robot account settings, add OIDC federation:

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
  type: oci
  url: oci://quay.example.com/myorg/charts
  project: default

  # Enable workload identity with K8s provider
  workloadIdentityProvider: k8s

  # HTTP template authenticator configuration
  workloadIdentityPathTemplate: "/oauth2/federation/robot/token"
  workloadIdentityMethod: GET
  workloadIdentityAuthType: basic
  workloadIdentityUsername: "myorg+argocd"
  workloadIdentityResponseTokenField: token
```

Note: When `workloadIdentityAuthType: basic` is set, the authenticator uses Basic Auth with `workloadIdentityUsername` and the K8s JWT as the password.

### Harbor with K8s OIDC

Configure Harbor to trust your Kubernetes cluster's OIDC issuer directly.

#### Step 1: Configure Harbor OIDC

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

#### Step 2: Create Service Account

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: argocd-project-default
  namespace: argocd
```

#### Step 3: Create Repository Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: harbor-repo
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  type: oci
  url: oci://harbor.example.com/library/charts
  project: default

  # Enable workload identity with K8s provider
  workloadIdentityProvider: k8s
  workloadIdentityAudience: harbor

  # HTTP template authenticator configuration
  workloadIdentityPathTemplate: "/service/token?service=harbor-registry&scope=repository:{{ .repo }}:pull"
  workloadIdentityMethod: GET
  workloadIdentityAuthType: bearer
  workloadIdentityResponseTokenField: token
```

### GitLab Container Registry

GitLab supports OIDC for container registry authentication.

#### Step 1: Configure GitLab OIDC

In GitLab Admin > Settings > General > Sign-in restrictions, configure OIDC to trust your K8s cluster.

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
  type: oci
  url: oci://registry.gitlab.example.com/group/project
  project: default

  # Enable workload identity with K8s provider
  workloadIdentityProvider: k8s
  workloadIdentityAudience: gitlab

  # HTTP template authenticator configuration
  workloadIdentityPathTemplate: "/jwt/auth?service=container_registry&scope=repository:{{ .repo }}:pull"
  workloadIdentityMethod: GET
  workloadIdentityAuthType: bearer
  workloadIdentityResponseTokenField: token
```

### JFrog Artifactory OIDC

JFrog Artifactory supports OIDC token exchange.

#### Step 1: Configure JFrog OIDC Provider

In Artifactory Administration > Security > Settings > OIDC, add your K8s OIDC provider.

#### Step 2: Create Repository Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: jfrog-repo
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  type: oci
  url: oci://artifactory.example.com/docker-local/charts
  project: default

  # Enable workload identity with K8s provider
  workloadIdentityProvider: k8s

  # HTTP template authenticator configuration (POST with JSON body)
  workloadIdentityAuthHost: artifactory.example.com
  workloadIdentityPathTemplate: "/access/api/v1/oidc/token"
  workloadIdentityMethod: POST
  workloadIdentityBodyTemplate: '{"grant_type":"urn:ietf:params:oauth:grant-type:token-exchange","subject_token":"{{ .token }}","provider_name":"{{ .provider }}"}'
  workloadIdentityAuthType: none
  workloadIdentityResponseTokenField: access_token
  workloadIdentityParams: |
    provider: my-k8s-oidc-provider
```

### Octo-STS (GitHub Container Registry via OIDC)

Use [Octo-STS](https://github.com/octo-sts/app) to exchange K8s tokens for GitHub tokens.

#### Step 1: Deploy Octo-STS

Follow the Octo-STS documentation to deploy it and configure the trust policy for your K8s OIDC issuer.

#### Step 2: Create Repository Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: ghcr-repo
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  type: oci
  url: oci://ghcr.io/myorg/charts
  project: default

  # Enable workload identity with K8s provider
  workloadIdentityProvider: k8s

  # HTTP template authenticator configuration
  workloadIdentityAuthHost: octo-sts.example.com
  workloadIdentityPathTemplate: "/sts/exchange?scope={{ .repo }}&identity={{ .policy }}"
  workloadIdentityMethod: GET
  workloadIdentityAuthType: bearer
  workloadIdentityResponseTokenField: token
  workloadIdentityParams: |
    policy: argocd
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
  type: oci
  url: oci://harbor.example.com/production/charts
  project: production
  workloadIdentityProvider: k8s
  workloadIdentityAudience: harbor
  workloadIdentityPathTemplate: "/service/token?service=harbor-registry&scope=repository:{{ .repo }}:pull"
  workloadIdentityMethod: GET
  workloadIdentityAuthType: bearer
  workloadIdentityResponseTokenField: token
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
  type: oci
  url: oci://quay.example.com/staging/charts
  project: staging
  workloadIdentityProvider: k8s
  workloadIdentityPathTemplate: "/oauth2/federation/robot/token"
  workloadIdentityMethod: GET
  workloadIdentityAuthType: basic
  workloadIdentityUsername: "staging+argocd"
  workloadIdentityResponseTokenField: token
```

## Troubleshooting

### Error: "pathTemplate is required for HTTP template authenticator"

The repository secret is missing the required `workloadIdentityPathTemplate` field.

**Solution:** Add `workloadIdentityPathTemplate` with the URL path for the auth endpoint.

### Error: "username is required for basic auth"

The `workloadIdentityAuthType` is set to `basic` but `workloadIdentityUsername` is missing.

**Solution:** Add `workloadIdentityUsername` to the repository secret.

### Error: "request failed with status 401"

The registry rejected the authentication request.

**Solution:**
1. Verify the registry trusts your K8s OIDC issuer
2. Check the K8s service account subject matches the registry's expected format
3. For Basic Auth mode, verify `workloadIdentityUsername` is correct
4. Test the endpoint manually with curl (see below)

### Error: "field 'token' not found or empty in response"

The auth endpoint returned a response that doesn't contain the expected token field.

**Solution:**
1. Set `workloadIdentityResponseTokenField` to the correct field name
2. Test the endpoint manually to see the actual response format

### Testing Authentication Manually

```bash
# Get a K8s token
TOKEN=$(kubectl create token argocd-project-default -n argocd --audience=my-audience)

# Test Bearer auth
curl "https://registry.example.com/service/token?service=registry&scope=repository:myrepo:pull" \
  -H "Authorization: Bearer $TOKEN"

# Test Basic auth (for Quay robot federation)
curl "https://quay.example.com/oauth2/federation/robot/token" \
  -u "myorg+robot:$TOKEN"

# Test POST with JSON body
curl -X POST "https://idp.example.com/oauth2/token" \
  -H "Content-Type: application/json" \
  -d "{\"grant_type\":\"urn:ietf:params:oauth:grant-type:token-exchange\",\"subject_token\":\"$TOKEN\"}"
```

## Security Considerations

1. **Trust chain**: Ensure each component (K8s OIDC -> Registry) properly validates tokens.

2. **Audience validation**: Set explicit `workloadIdentityAudience` to prevent token reuse attacks.

3. **TLS verification**: Only set `insecure: "true"` for development environments.

4. **Subject binding**: Configure registries to validate the `sub` claim matches expected service accounts.

5. **Token lifetime**: K8s tokens requested via TokenRequest API expire in 1 hour by default.

## References

- [RFC 8693 - OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693)
- [Docker Registry Token Authentication](https://docs.docker.com/registry/spec/auth/token/)
- [Harbor OIDC Authentication](https://goharbor.io/docs/latest/administration/configure-authentication/oidc-auth/)
- [Quay Robot Account Federation](https://docs.redhat.com/en/documentation/red_hat_quay/3/html/use_red_hat_quay/robot-account-federation)
- [Kubernetes TokenRequest API](https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-request-v1/)