package workloadidentity

import (
	"context"
	"fmt"
	"os"

	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const (
	// SpiffeEndpointSocketEnv is the environment variable for the SPIFFE Workload API socket
	SpiffeEndpointSocketEnv = "SPIFFE_ENDPOINT_SOCKET"
)

// fetchSPIFFEJWT fetches a JWT-SVID from the SPIFFE Workload API
// The socket path is read from SPIFFE_ENDPOINT_SOCKET env var
// Returns the JWT token string for the requested audience
func fetchSPIFFEJWT(ctx context.Context, audience string) (string, error) {
	socketPath := os.Getenv(SpiffeEndpointSocketEnv)
	if socketPath == "" {
		return "", fmt.Errorf("%s environment variable not set", SpiffeEndpointSocketEnv)
	}

	// Create workload API client
	client, err := workloadapi.New(ctx, workloadapi.WithAddr(socketPath))
	if err != nil {
		return "", fmt.Errorf("failed to create SPIFFE workload API client: %w", err)
	}
	defer client.Close()

	// Fetch JWT-SVID with the requested audience
	svid, err := client.FetchJWTSVID(ctx, jwtsvid.Params{Audience: audience})
	if err != nil {
		return "", fmt.Errorf("failed to fetch JWT-SVID: %w", err)
	}

	if svid == nil {
		return "", fmt.Errorf("no JWT-SVID returned from SPIFFE workload API")
	}

	return svid.Marshal(), nil
}

// resolveSPIFFE resolves credentials using SPIFFE Workload API
// It fetches a JWT-SVID from SPIRE and optionally exchanges it for registry credentials
func (r *Resolver) resolveSPIFFE(ctx context.Context, repoURL string, config *ProviderConfig) (*Credentials, error) {
	audience := config.Audience
	if audience == "" {
		return nil, fmt.Errorf("workloadIdentityAudience is required for spiffe provider")
	}

	// Fetch JWT-SVID from SPIFFE Workload API
	jwtToken, err := fetchSPIFFEJWT(ctx, audience)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch SPIFFE JWT: %w", err)
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
