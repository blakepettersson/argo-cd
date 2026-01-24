# Workload Identity v2 - Refactored Design

## Overview

Split credential resolution into two phases:
1. **Identity Provider** - Acquire an identity token from the platform
2. **Registry Authenticator** - Exchange identity token for registry credentials

This allows mixing and matching identity sources with registry types.

## Interfaces

```go
// Token represents a token from an identity provider
type Token struct {
    // Type indicates the token format
    Type TokenType // "bearer", "aws"

    // For bearer tokens (JWT, access tokens)
    Token string

    // For AWS SigV4 signing
    AWSCredentials *AWSCredentials
}

type TokenType string

const (
    TokenTypeBearer TokenType = "bearer"  // JWT, OAuth access token
    TokenTypeAWS    TokenType = "aws"     // AWS credentials for SigV4
)

type AWSCredentials struct {
    AccessKeyID     string
    SecretAccessKey string
    SessionToken    string
    Region          string
}

// IdentityProvider acquires identity tokens from a platform
type IdentityProvider interface {
    // Name returns the provider identifier (for logging/errors)
    Name() string

    // GetIdentityToken exchanges K8s SA context for a platform identity token
    GetIdentityToken(ctx context.Context, sa *corev1.ServiceAccount, k8sToken string, config *IdentityConfig) (*IdentityToken, error)
}

// IdentityConfig holds identity provider configuration
type IdentityConfig struct {
    Audience string // Token audience override
    TokenURL string // Custom token endpoint
    Insecure bool   // Skip TLS verification
}

// RegistryAuthenticator converts identity tokens to registry credentials
type RegistryAuthenticator interface {
    // Name returns the authenticator identifier
    Name() string

    // Authenticate exchanges an identity token for registry credentials
    Authenticate(ctx context.Context, identity *IdentityToken, repoURL string, config *RegistryConfig) (*Credentials, error)
}

// RegistryConfig holds registry-specific configuration
type RegistryConfig struct {
    AuthURL  string // Registry auth endpoint (for token exchange)
    Service  string // Registry service name (for Docker token auth)
    Username string // Username for basic auth
    Insecure bool   // Skip TLS verification
}
```

## Identity Providers

### AWS (`aws`)
- Input: K8s JWT + role ARN annotation
- Process: STS AssumeRoleWithWebIdentity
- Output: `TokenTypeAWS` with temporary credentials

### GCP (`gcp`)
- Input: K8s JWT + GCP SA annotation + workload identity pool
- Process: STS token exchange → Service account impersonation
- Output: `TokenTypeBearer` with GCP access token

### Azure (`azure`)
- Input: K8s JWT + client ID + tenant ID annotations
- Process: Azure AD token exchange
- Output: `TokenTypeBearer` with Azure access token

### SPIFFE (`spiffe`)
- Input: Workload API socket
- Process: Fetch X.509 SVID or JWT SVID
- Output: `TokenTypeBearer` with SPIFFE JWT (or X.509 for mTLS)

### OIDC (`oidc`)
- Input: K8s JWT + token exchange endpoint
- Process: RFC 8693 token exchange
- Output: `TokenTypeBearer` with exchanged token

### Kubernetes (`k8s`)
- Input: K8s JWT directly
- Process: None (passthrough)
- Output: `TokenTypeBearer` with K8s JWT

## Registry Authenticators

Only 4 authenticators needed - 2 generic, 2 cloud-specific:

### Basic Auth (`basic`)
- Input: `TokenTypeBearer`
- Process: None (passthrough)
- Output: Basic auth (username: configured, password: token)
- Use for: GCR/GAR (username: `oauth2accesstoken`), any registry accepting OAuth tokens directly

### Docker v2 Token Auth (`docker`)
- Input: `TokenTypeBearer`
- Process: Standard Docker Registry v2 token auth protocol
- Output: Basic auth (username: configured or `$oauthtoken`, password: access token)
- Use for: Quay, Harbor, GHCR, GitLab Registry, Docker Hub, any Docker v2 compatible registry
- Supports:
  - Auto-discovery of auth endpoint via WWW-Authenticate header
  - Configurable service name
  - Configurable access scopes (e.g., `repository:foo/bar:pull,push`)

### ECR (`ecr`)
- Input: `TokenTypeAWS` credentials
- Process: Call `ecr:GetAuthorizationToken` API (AWS-specific, no choice)
- Output: Basic auth (username: `AWS`, password: base64-decoded token)

### ACR (`acr`)
- Input: `TokenTypeBearer` (Azure access token)
- Process: Exchange for ACR refresh token via `/oauth2/exchange` (Azure-specific)
- Output: Basic auth (username: `00000000-0000-0000-0000-000000000000`, password: refresh token)

## Configuration

Repository secret fields:
```yaml
stringData:
  # Identity Provider
  workloadIdentityProvider: "spiffe"     # aws, gcp, azure, spiffe, oidc, k8s
  workloadIdentityAudience: ""           # optional audience override
  workloadIdentityTokenURL: ""           # optional token endpoint override

  # Registry Authenticator
  workloadIdentityRegistryAuth: "docker" # ecr, acr, basic, docker
  workloadIdentityRegistryAuthURL: ""    # optional auth endpoint (for docker)
  workloadIdentityRegistryService: ""    # optional service name (for docker)
  workloadIdentityRegistryScope: ""      # optional scope e.g. "repository:foo/bar:pull"
  workloadIdentityRegistryUsername: ""   # username for basic auth
```

## Example Combinations

### SPIFFE + Quay (Docker v2 auth)
```yaml
workloadIdentityProvider: spiffe
workloadIdentityAudience: "quay.io"
workloadIdentityRegistryAuth: docker
# Auth URL auto-discovered from registry
```

### SPIFFE + Harbor with specific scope
```yaml
workloadIdentityProvider: spiffe
workloadIdentityAudience: "harbor.example.com"
workloadIdentityRegistryAuth: docker
workloadIdentityRegistryScope: "repository:myproject/myrepo:pull,push"
```

### SPIFFE + Generic Registry (Basic Auth)
```yaml
workloadIdentityProvider: spiffe
workloadIdentityRegistryAuth: basic
workloadIdentityRegistryUsername: "oauth2accesstoken"
```

### GCP Workload Identity + GAR
```yaml
workloadIdentityProvider: gcp
workloadIdentityRegistryAuth: basic
workloadIdentityRegistryUsername: "oauth2accesstoken"
```

### GCP Workload Identity + Quay (if Quay trusts GCP OIDC)
```yaml
workloadIdentityProvider: gcp
workloadIdentityRegistryAuth: docker
```

### K8s JWT + Custom Registry (trusts K8s OIDC)
```yaml
workloadIdentityProvider: k8s
workloadIdentityAudience: "my-registry"
workloadIdentityRegistryAuth: docker
# Auth URL auto-discovered, or specify explicitly:
# workloadIdentityRegistryAuthURL: "https://registry.example.com/v2/token"
```

### AWS EKS + ECR
```yaml
workloadIdentityProvider: aws
workloadIdentityRegistryAuth: ecr
# SA annotation: eks.amazonaws.com/role-arn
```

### Azure + ACR
```yaml
workloadIdentityProvider: azure
workloadIdentityRegistryAuth: acr
```

### OIDC Token Exchange + GHCR
```yaml
workloadIdentityProvider: oidc
workloadIdentityTokenURL: "https://token.example.com/exchange"
workloadIdentityRegistryAuth: docker
# GHCR uses Docker v2 auth at ghcr.io
```

## Resolver Implementation

```go
type Resolver struct {
    serviceAccounts   v1.ServiceAccountInterface
    identityProviders map[string]IdentityProvider
    registryAuths     map[string]RegistryAuthenticator
}

func (r *Resolver) ResolveCredentials(ctx context.Context, projectName, repoURL string, config *ProviderConfig) (*Credentials, error) {
    // 1. Get service account
    saName := GetServiceAccountName(projectName)
    sa, err := r.serviceAccounts.Get(ctx, saName, metav1.GetOptions{})
    if err != nil {
        return nil, fmt.Errorf("failed to get service account: %w", err)
    }

    // 2. Get K8s token (if needed by identity provider)
    var k8sToken string
    if needsK8sToken(config.Provider) {
        k8sToken, err = r.requestToken(ctx, sa, config)
        if err != nil {
            return nil, fmt.Errorf("failed to get k8s token: %w", err)
        }
    }

    // 3. Get identity token from provider
    identityProvider, ok := r.identityProviders[config.Provider]
    if !ok {
        return nil, fmt.Errorf("unknown identity provider: %s", config.Provider)
    }

    identity, err := identityProvider.GetIdentityToken(ctx, sa, k8sToken, &IdentityConfig{
        Audience: config.Audience,
        TokenURL: config.TokenURL,
        Insecure: config.Insecure,
    })
    if err != nil {
        return nil, fmt.Errorf("failed to get identity token: %w", err)
    }

    // 4. Exchange identity for registry credentials
    registryAuth, ok := r.registryAuths[config.RegistryAuth]
    if !ok {
        // Default based on provider for backwards compatibility
        registryAuth = r.defaultRegistryAuth(config.Provider)
    }

    creds, err := registryAuth.Authenticate(ctx, identity, repoURL, &RegistryConfig{
        AuthURL:  config.RegistryAuthURL,
        Service:  config.RegistryService,
        Username: config.RegistryUsername,
        Insecure: config.Insecure,
    })
    if err != nil {
        return nil, fmt.Errorf("failed to authenticate to registry: %w", err)
    }

    return creds, nil
}

// defaultRegistryAuth returns the default registry authenticator for backwards compatibility
func (r *Resolver) defaultRegistryAuth(provider string) RegistryAuthenticator {
    switch provider {
    case "aws":
        return r.registryAuths["ecr"]
    case "gcp":
        return r.registryAuths["gcr"]
    case "azure":
        return r.registryAuths["acr"]
    default:
        return r.registryAuths["basic"]
    }
}
```

## File Structure

```
util/workloadidentity/v2/
├── resolver.go              # Main resolver, orchestrates the flow
├── types.go                 # Shared types (IdentityToken, Credentials, configs)
├── token.go                 # K8s TokenRequest helpers
│
├── identity/                # Identity providers
│   ├── provider.go          # IdentityProvider interface
│   ├── aws.go               # AWS STS provider
│   ├── gcp.go               # GCP Workload Identity provider
│   ├── azure.go             # Azure AD provider
│   ├── spiffe.go            # SPIFFE Workload API provider
│   ├── oidc.go              # RFC 8693 token exchange provider
│   └── k8s.go               # Passthrough K8s JWT provider
│
├── registry/                # Registry authenticators (only 4 needed!)
│   ├── authenticator.go     # RegistryAuthenticator interface
│   ├── basic.go             # Token as password (GCR, GAR, any OAuth registry)
│   ├── docker.go            # Docker v2 token auth (Quay, Harbor, GHCR, etc.)
│   ├── ecr.go               # AWS ECR (uses AWS API)
│   └── acr.go               # Azure ACR (Azure-specific exchange)
│
└── mocks/                   # Generated mocks
```

## Migration Path

1. Add new interfaces and implementations alongside existing code
2. Update `ProviderConfig` to include `RegistryAuth` field
3. If `RegistryAuth` is empty, use `defaultRegistryAuth()` based on `Provider`
4. Existing configs continue to work unchanged
5. New configs can specify explicit combinations

## Testing

Each component can be tested independently:
- Identity providers: mock the external APIs (STS, Azure AD, etc.)
- Registry authenticators: mock the registry endpoints
- Resolver: mock both interfaces

```go
func TestResolver_SPIFFEWithBasicAuth(t *testing.T) {
    mockIdentity := &mockIdentityProvider{
        token: &IdentityToken{Type: TokenTypeBearer, Token: "spiffe-jwt"},
    }
    mockRegistry := &mockRegistryAuthenticator{
        creds: &Credentials{Username: "user", Password: "spiffe-jwt"},
    }

    resolver := &Resolver{
        identityProviders: map[string]IdentityProvider{"spiffe": mockIdentity},
        registryAuths:     map[string]RegistryAuthenticator{"basic": mockRegistry},
    }

    // Test...
}
```