package workloadidentity

import (
	"context"
	"fmt"
	"os"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	corev1 "k8s.io/api/core/v1"
)

const (
	// SpiffeEndpointSocketEnv is the environment variable for the SPIFFE Workload API socket
	SpiffeEndpointSocketEnv = "SPIFFE_ENDPOINT_SOCKET"
)

// fetchSPIFFEJWT fetches a JWT-SVID from the SPIFFE Workload API using delegated identity.
// When subjectSPIFFEID is provided, it requests a JWT for that specific identity (requires admin: true).
// When subjectSPIFFEID is empty, it fetches the workload's own JWT-SVID.
// The socket path is read from SPIFFE_ENDPOINT_SOCKET env var.
func fetchSPIFFEJWT(ctx context.Context, audience string, subjectSPIFFEID spiffeid.ID) (string, error) {
	socketPath := os.Getenv(SpiffeEndpointSocketEnv)
	if socketPath == "" {
		return "", fmt.Errorf("%s environment variable not set", SpiffeEndpointSocketEnv)
	}

	// Create workload API client
	client, err := workloadapi.New(ctx, workloadapi.WithAddr(socketPath))
	if err != nil {
		return "", fmt.Errorf("failed to create SPIFFE workload API client: %w", err)
	}
	defer func() { _ = client.Close() }()

	// Build params with audience and optional subject for delegated identity
	params := jwtsvid.Params{Audience: audience}
	if !subjectSPIFFEID.IsZero() {
		// Use delegated identity to request JWT for specific SPIFFE ID
		// This requires the calling workload to have admin: true in its SPIRE entry
		params.Subject = subjectSPIFFEID
	}

	// Fetch JWT-SVID
	svid, err := client.FetchJWTSVID(ctx, params)
	if err != nil {
		return "", fmt.Errorf("failed to fetch JWT-SVID: %w", err)
	}

	if svid == nil {
		return "", fmt.Errorf("no JWT-SVID returned from SPIFFE workload API")
	}

	return svid.Marshal(), nil
}

// resolveSPIFFE resolves credentials using SPIFFE Workload API with delegated identity.
// It fetches a JWT-SVID for the project's service account SPIFFE ID and optionally
// exchanges it for registry credentials.
//
// This follows the same pattern as AWS/GCP/Azure providers where the application-controller
// requests credentials on behalf of the project-specific service account.
//
// Requirements:
// - Application-controller's SPIRE entry must have admin: true
// - Project service accounts must have SPIRE entries with their SPIFFE IDs
func (r *Resolver) resolveSPIFFE(ctx context.Context, sa *corev1.ServiceAccount, repoURL string, config *ProviderConfig) (*Credentials, error) {
	audience := config.Audience
	if audience == "" {
		return nil, fmt.Errorf("workloadIdentityAudience is required for spiffe provider")
	}

	// Build the SPIFFE ID for the project's service account
	// Format: spiffe://<trust-domain>/ns/<namespace>/sa/<service-account-name>
	subjectSPIFFEID, err := buildSPIFFEID(ctx, sa.Namespace, sa.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to build SPIFFE ID for service account %s/%s: %w", sa.Namespace, sa.Name, err)
	}

	// Fetch JWT-SVID for the project's SPIFFE ID using delegated identity
	jwtToken, err := fetchSPIFFEJWT(ctx, audience, subjectSPIFFEID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch SPIFFE JWT for %s: %w", subjectSPIFFEID, err)
	}

	// If registry auth URL is configured, exchange JWT for registry credentials
	// This calls Quay's robot federation endpoint which validates the JWT
	// and returns a Quay-signed registry token
	if config.RegistryAuthURL != "" {
		return r.exchangeRegistryToken(ctx, config, jwtToken, repoURL)
	}

	// Otherwise return JWT as password directly (for registries that accept OIDC tokens)
	return &Credentials{
		Username: config.RegistryUsername,
		Password: jwtToken,
	}, nil
}

// buildSPIFFEID constructs a SPIFFE ID for a Kubernetes service account.
// It fetches the trust domain from the SPIFFE Workload API.
func buildSPIFFEID(ctx context.Context, namespace, serviceAccountName string) (spiffeid.ID, error) {
	socketPath := os.Getenv(SpiffeEndpointSocketEnv)
	if socketPath == "" {
		return spiffeid.ID{}, fmt.Errorf("%s environment variable not set", SpiffeEndpointSocketEnv)
	}

	// Create workload API client to fetch trust domain
	client, err := workloadapi.New(ctx, workloadapi.WithAddr(socketPath))
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("failed to create SPIFFE workload API client: %w", err)
	}
	defer func() { _ = client.Close() }()

	// Fetch X509 context to get the trust domain
	x509Ctx, err := client.FetchX509Context(ctx)
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("failed to fetch X509 context: %w", err)
	}

	if len(x509Ctx.SVIDs) == 0 {
		return spiffeid.ID{}, fmt.Errorf("no X509-SVIDs returned from SPIFFE workload API")
	}

	// Get trust domain from the workload's own SVID
	trustDomain := x509Ctx.SVIDs[0].ID.TrustDomain()

	// Build SPIFFE ID for the service account
	// Standard format: spiffe://<trust-domain>/ns/<namespace>/sa/<sa-name>
	path := fmt.Sprintf("/ns/%s/sa/%s", namespace, serviceAccountName)
	return spiffeid.FromPath(trustDomain, path)
}
