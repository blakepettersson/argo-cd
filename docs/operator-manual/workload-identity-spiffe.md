# SPIFFE/SPIRE Workload Identity for ArgoCD

This guide explains how to configure ArgoCD to use SPIFFE/SPIRE for workload identity authentication with OCI registries like Quay, Harbor, or any registry that supports OIDC federation.

## Overview

The SPIFFE provider enables ArgoCD to authenticate to container registries using SPIFFE JWT-SVIDs (JSON Web Tokens) issued by SPIRE. This provides:

- **Zero static credentials**: No long-lived passwords or tokens stored in secrets
- **Per-project isolation**: Each ArgoCD project can have its own SPIFFE identity
- **Cryptographic attestation**: SPIRE validates workload identity based on Kubernetes attributes
- **Standard OIDC**: Uses standard JWT tokens that registries can validate via OIDC discovery

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        ArgoCD Application Controller                         │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ 1. Resolve workload identity for project "default"                      ││
│  │    → Service account: argocd-project-default                            ││
│  │    → SPIFFE ID: spiffe://trust-domain/ns/argocd/sa/argocd-project-default│
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SPIRE Workload API                                   │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ 2. Application-controller (with admin: true) requests JWT-SVID          ││
│  │    for the project's SPIFFE ID using delegated identity                 ││
│  │                                                                          ││
│  │ 3. SPIRE validates delegation authorization and issues JWT-SVID         ││
│  │    with subject: spiffe://trust-domain/ns/argocd/sa/argocd-project-default│
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Registry Robot Federation (e.g., Quay)                    │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ 4. ArgoCD sends: Basic Auth (robot_username : JWT-SVID)                 ││
│  │    to /oauth2/federation/robot/token                                    ││
│  │                                                                          ││
│  │ 5. Quay validates JWT against SPIRE OIDC discovery endpoint             ││
│  │    - Fetches JWKS from https://spire-oidc-discovery/.well-known/...     ││
│  │    - Validates signature, issuer, subject, audience                     ││
│  │    - Returns registry access token                                      ││
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           OCI Registry Access                                │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ 6. ArgoCD uses registry token to pull manifests/charts                  ││
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
```

## Prerequisites

1. **SPIRE deployed** with:
   - SPIFFE Workload API accessible to ArgoCD pods
   - OIDC Discovery Provider enabled and accessible to the registry
   - JWT-SVID support enabled

2. **Registry with OIDC federation support** (e.g., Quay robot federation, Harbor OIDC)

3. **ArgoCD with SPIFFE CSI driver** mounted to application-controller

## Configuration Steps

### Step 1: Mount SPIFFE Workload API Socket

The ArgoCD application-controller needs access to the SPIFFE Workload API socket. This is typically done via the SPIFFE CSI driver.

**For OpenShift GitOps**, patch the ArgoCD CR:

```yaml
apiVersion: argoproj.io/v1beta1
kind: ArgoCD
metadata:
  name: openshift-gitops
  namespace: openshift-gitops
spec:
  controller:
    env:
      - name: SPIFFE_ENDPOINT_SOCKET
        value: "unix:///spiffe-workload-api/spire-agent.sock"
    volumes:
      - name: spiffe-workload-api
        csi:
          driver: csi.spiffe.io
          readOnly: true
    volumeMounts:
      - name: spiffe-workload-api
        mountPath: /spiffe-workload-api
        readOnly: true
```

**For standard ArgoCD**, add to the application-controller StatefulSet:

```yaml
spec:
  template:
    spec:
      containers:
        - name: argocd-application-controller
          env:
            - name: SPIFFE_ENDPOINT_SOCKET
              value: "unix:///spiffe-workload-api/spire-agent.sock"
          volumeMounts:
            - name: spiffe-workload-api
              mountPath: /spiffe-workload-api
              readOnly: true
      volumes:
        - name: spiffe-workload-api
          csi:
            driver: csi.spiffe.io
            readOnly: true
```

### Step 2: Create SPIRE Entry for Application-Controller (with admin)

The application-controller needs a SPIRE entry with `admin: true` to use delegated identity. This allows it to request JWT-SVIDs on behalf of project service accounts.

```bash
# Create entry for each SPIRE agent (repeat for each agent in your cluster)
spire-server entry create \
  -spiffeID spiffe://<trust-domain>/ns/<argocd-namespace>/sa/<app-controller-sa> \
  -parentID spiffe://<trust-domain>/spire/agent/k8s_psat/cluster/<agent-id> \
  -selector k8s:ns:<argocd-namespace> \
  -selector k8s:sa:<app-controller-sa> \
  -admin
```

**Example for OpenShift GitOps:**

```bash
spire-server entry create \
  -spiffeID spiffe://example.org/ns/openshift-gitops/sa/openshift-gitops-argocd-application-controller \
  -parentID spiffe://example.org/spire/agent/k8s_psat/cluster/abc123 \
  -selector k8s:ns:openshift-gitops \
  -selector k8s:sa:openshift-gitops-argocd-application-controller \
  -jwtSVIDTTL 3600 \
  -admin
```

**Security Note**: The `admin` flag allows the workload to request SVIDs for any SPIFFE ID that has a registered entry. Only grant this to trusted components like the ArgoCD application-controller.

### Step 3: Create Project Service Account

Create a Kubernetes service account for each ArgoCD project:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: argocd-project-default  # Format: argocd-project-<project-name>
  namespace: openshift-gitops   # Same namespace as ArgoCD
```

### Step 4: Create SPIRE Entry for Project Service Account

Register the project service account with SPIRE:

```bash
# Create entry for each SPIRE agent
spire-server entry create \
  -spiffeID spiffe://<trust-domain>/ns/<argocd-namespace>/sa/argocd-project-<project> \
  -parentID spiffe://<trust-domain>/spire/agent/k8s_psat/cluster/<agent-id> \
  -selector k8s:ns:<argocd-namespace> \
  -selector k8s:sa:argocd-project-<project> \
  -jwtSVIDTTL 3600
```

**Example:**

```bash
spire-server entry create \
  -spiffeID spiffe://example.org/ns/openshift-gitops/sa/argocd-project-default \
  -parentID spiffe://example.org/spire/agent/k8s_psat/cluster/abc123 \
  -selector k8s:ns:openshift-gitops \
  -selector k8s:sa:argocd-project-default \
  -jwtSVIDTTL 3600
```

### Step 5: Configure Registry Robot Federation (Quay Example)

In Quay, configure a robot account with OIDC federation:

1. **Create a robot account** (e.g., `myorg+argocd`)

2. **Configure federation** for the robot account:
   - **Issuer**: `https://<spire-oidc-discovery-endpoint>`
   - **Subject**: `spiffe://<trust-domain>/ns/<argocd-namespace>/sa/argocd-project-<project>`

3. **Grant repository access** to the robot account

**Example Quay robot federation config:**
- Issuer: `https://spire-oidc-discovery.example.org`
- Subject: `spiffe://example.org/ns/openshift-gitops/sa/argocd-project-default`

### Step 6: Create Repository Secret

Create the ArgoCD repository secret with SPIFFE workload identity:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-oci-repo
  namespace: openshift-gitops
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  type: helm  # or "oci" for generic OCI artifacts
  url: oci://quay.example.org/myorg/charts
  project: default  # Links to argocd-project-default service account

  # Enable workload identity
  useWorkloadIdentity: "true"
  workloadIdentityProvider: "spiffe"

  # SPIFFE JWT audience (registry validates this)
  workloadIdentityAudience: "quay.example.org"

  # Registry auth endpoint for robot federation
  workloadIdentityRegistryAuthURL: "https://quay.example.org/oauth2/federation/robot/token"
  workloadIdentityRegistryService: "quay.example.org"
  workloadIdentityRegistryUsername: "myorg+argocd"  # Robot account name

  # Optional: skip TLS verification (not recommended for production)
  # insecure: "true"
```

### Step 7: Create Application

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: my-app
  namespace: openshift-gitops
spec:
  project: default  # Must match the project in repository secret
  source:
    repoURL: oci://quay.example.org/myorg/charts
    chart: my-chart
    targetRevision: 1.0.0
  destination:
    server: https://kubernetes.default.svc
    namespace: my-app
```

## Multi-Project Setup

To support multiple projects with different registry access:

### Project A (production)

```yaml
# Service Account
apiVersion: v1
kind: ServiceAccount
metadata:
  name: argocd-project-production
  namespace: openshift-gitops
---
# Repository Secret
apiVersion: v1
kind: Secret
metadata:
  name: prod-registry
  namespace: openshift-gitops
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  type: helm
  url: oci://quay.example.org/prod/charts
  project: production
  useWorkloadIdentity: "true"
  workloadIdentityProvider: "spiffe"
  workloadIdentityAudience: "quay.example.org"
  workloadIdentityRegistryAuthURL: "https://quay.example.org/oauth2/federation/robot/token"
  workloadIdentityRegistryService: "quay.example.org"
  workloadIdentityRegistryUsername: "prod+argocd"
```

**SPIRE entry:**
```bash
spire-server entry create \
  -spiffeID spiffe://example.org/ns/openshift-gitops/sa/argocd-project-production \
  -parentID spiffe://example.org/spire/agent/k8s_psat/cluster/abc123 \
  -selector k8s:ns:openshift-gitops \
  -selector k8s:sa:argocd-project-production \
  -jwtSVIDTTL 3600
```

**Quay robot federation:**
- Robot: `prod+argocd`
- Subject: `spiffe://example.org/ns/openshift-gitops/sa/argocd-project-production`

### Project B (staging)

```yaml
# Service Account
apiVersion: v1
kind: ServiceAccount
metadata:
  name: argocd-project-staging
  namespace: openshift-gitops
---
# Repository Secret
apiVersion: v1
kind: Secret
metadata:
  name: staging-registry
  namespace: openshift-gitops
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  type: helm
  url: oci://quay.example.org/staging/charts
  project: staging
  useWorkloadIdentity: "true"
  workloadIdentityProvider: "spiffe"
  workloadIdentityAudience: "quay.example.org"
  workloadIdentityRegistryAuthURL: "https://quay.example.org/oauth2/federation/robot/token"
  workloadIdentityRegistryService: "quay.example.org"
  workloadIdentityRegistryUsername: "staging+argocd"
```

## Troubleshooting

### Error: "SPIFFE_ENDPOINT_SOCKET environment variable not set"

The application-controller doesn't have the SPIFFE socket configured.

**Solution:** Ensure the CSI volume is mounted and the environment variable is set (see Step 1).

### Error: "failed to fetch JWT-SVID: no identity issued"

SPIRE doesn't have an entry for the requesting workload.

**Solution:**
1. Verify SPIRE entry exists for the application-controller
2. Verify the entry has correct selectors (namespace, service account)
3. Verify the entry has the correct parent ID (SPIRE agent)
4. Check SPIRE agent logs: `spire-agent api fetch jwt -audience test`

### Error: "failed to fetch JWT-SVID for spiffe://...sa/argocd-project-xxx"

The application-controller can fetch its own SVID but can't request delegated identity.

**Solution:**
1. Verify the application-controller's SPIRE entry has `admin: true`
2. Verify a SPIRE entry exists for the project service account's SPIFFE ID

### Error: "Token does not match robot"

The registry received the JWT but the subject doesn't match the robot federation config.

**Solution:**
1. Decode the JWT to see the actual subject claim
2. Verify the Quay robot federation subject matches exactly
3. SPIFFE ID format: `spiffe://<trust-domain>/ns/<namespace>/sa/<sa-name>`

### Error: "Unknown service key" (500 Internal Server Error)

The registry can't validate the JWT signature.

**Solution:**
1. Verify SPIRE OIDC discovery endpoint is accessible from the registry
2. Test: `curl https://<spire-oidc>/.well-known/openid-configuration`
3. Test: `curl https://<spire-oidc>/keys`
4. Verify the issuer in Quay robot federation matches SPIRE's OIDC issuer

### Error: 401 Unauthorized at manifest endpoint

Authentication succeeded but the robot account doesn't have access.

**Solution:**
1. Verify the robot account has read access to the repository
2. Check the scope in the token request matches the repository path

## SPIRE Entry Management

### Listing entries

```bash
spire-server entry show -spiffeID spiffe://example.org/ns/openshift-gitops/sa/argocd-project-default
```

### Updating entries (add admin flag)

```bash
spire-server entry update \
  -entryID <entry-id> \
  -spiffeID spiffe://example.org/ns/openshift-gitops/sa/openshift-gitops-argocd-application-controller \
  -parentID spiffe://example.org/spire/agent/k8s_psat/cluster/abc123 \
  -selector k8s:ns:openshift-gitops \
  -selector k8s:sa:openshift-gitops-argocd-application-controller \
  -jwtSVIDTTL 3600 \
  -admin
```

### Deleting entries

```bash
spire-server entry delete -entryID <entry-id>
```

## Security Considerations

1. **`admin: true` is privileged**: Only the application-controller should have this flag. It allows requesting SVIDs for any registered SPIFFE ID.

2. **SPIRE entry registration**: Only register SPIFFE IDs that ArgoCD should be able to impersonate (project service accounts).

3. **Registry permissions**: Each robot account should only have access to repositories needed by that project.

4. **Network security**: Ensure the SPIRE OIDC discovery endpoint is only accessible to authorized registries.

5. **Token TTL**: JWT-SVIDs are short-lived (default 1 hour). Configure appropriate TTL based on your security requirements.

## References

- [SPIFFE Specification](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/)
- [SPIRE Documentation](https://spiffe.io/docs/latest/spire-about/)
- [SPIRE Delegated Identity API](https://spiffe.io/docs/latest/deploying/spire_agent/#delegated-identity-api)
- [Quay Robot Account Federation](https://docs.redhat.com/en/documentation/red_hat_quay/3/html/use_red_hat_quay/robot-account-federation)
- [go-spiffe Library](https://github.com/spiffe/go-spiffe)
