package identity

import (
	"context"
	"fmt"
	"net/url"
	"os"

	"github.com/argoproj/argo-cd/v3/util/workloadidentity/v2/repository"
	log "github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	corev1 "k8s.io/api/core/v1"
)

const (
	// DefaultSPIFFESocketPath is the default SPIFFE Workload API socket
	DefaultSPIFFESocketPath = "unix:///run/spiffe/sockets/agent.sock"
	// SpiffeEndpointSocketEnv is the environment variable for the SPIFFE Workload API socket
	SpiffeEndpointSocketEnv = "SPIFFE_ENDPOINT_SOCKET"
)

// SPIFFEProvider fetches SPIFFE JWTs from the Workload API.
// Unlike other providers, SPIFFE uses its own attestation mechanism
// and does not require a K8s service account token.
type SPIFFEProvider struct {
	// SocketPath overrides the default SPIFFE socket path
	SocketPath string
	// repoURL is used to derive default audience from registry host
	repoURL string
}

func (p *SPIFFEProvider) DefaultRepositoryAuthenticator() repository.Authenticator {
	return repository.NewHTTPTemplateAuthenticator()
}

// NewSPIFFEProvider creates a new SPIFFE identity provider
func NewSPIFFEProvider(repoURL string) *SPIFFEProvider {
	return &SPIFFEProvider{
		repoURL: repoURL,
	}
}

// GetToken fetches a SPIFFE JWT-SVID for the given audience.
// Note: requestToken is not used - SPIFFE uses its own attestation.
func (p *SPIFFEProvider) GetToken(ctx context.Context, sa *corev1.ServiceAccount, _ TokenRequester, config *Config) (*repository.Token, error) {
	// SPIFFE uses its own workload attestation, not K8s tokens

	audience := config.Audience
	if audience == "" {
		// Default to registry host from repo URL
		if p.repoURL != "" {
			if u, err := url.Parse(p.repoURL); err == nil && u.Host != "" {
				audience = u.Host
			}
		}
	}
	if audience == "" {
		return nil, fmt.Errorf("could not determine audience: set workloadIdentityAudience or provide a valid repo URL")
	}

	log.WithFields(log.Fields{
		"serviceAccount": fmt.Sprintf("%s/%s", sa.Namespace, sa.Name),
		"audience":       audience,
	}).Info("SPIFFE: fetching JWT-SVID for project identity")

	// Build the SPIFFE ID for the project's service account
	// Format: spiffe://<trust-domain>/ns/<namespace>/sa/<service-account-name>
	subjectSPIFFEID, err := buildSPIFFEID(ctx, sa.Namespace, sa.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to build SPIFFE ID for service account %s/%s: %w", sa.Namespace, sa.Name, err)
	}

	log.WithField("spiffeID", subjectSPIFFEID.String()).Debug("SPIFFE: built SPIFFE ID for service account")

	// Fetch JWT-SVID for the project's SPIFFE ID
	jwtToken, err := fetchSPIFFEJWT(ctx, audience, subjectSPIFFEID)
	if err != nil {
		log.WithFields(log.Fields{
			"spiffeID": subjectSPIFFEID.String(),
			"audience": audience,
			"error":    err.Error(),
		}).Error("SPIFFE: failed to fetch JWT-SVID")
		return nil, err
	}

	log.WithFields(log.Fields{
		"spiffeID": subjectSPIFFEID.String(),
		"audience": audience,
	}).Info("SPIFFE: successfully obtained JWT-SVID")

	return &repository.Token{
		Type:  repository.TokenTypeBearer,
		Token: jwtToken,
	}, nil
}

// buildSPIFFEID constructs a SPIFFE ID for a Kubernetes service account.
// It fetches the trust domain from the SPIFFE Workload API.
func buildSPIFFEID(ctx context.Context, namespace, serviceAccountName string) (spiffeid.ID, error) {
	socketPath := os.Getenv(SpiffeEndpointSocketEnv)
	if socketPath == "" {
		return spiffeid.ID{}, fmt.Errorf("%s environment variable not set", SpiffeEndpointSocketEnv)
	}

	log.WithField("socketPath", socketPath).Debug("SPIFFE: connecting to workload API")

	// Create workload API client to fetch trust domain
	client, err := workloadapi.New(ctx, workloadapi.WithAddr(socketPath))
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("failed to create SPIFFE workload API client: %w", err)
	}
	defer func() { _ = client.Close() }()

	// Fetch X509 context to get the trust domain
	log.Debug("SPIFFE: fetching X509 context to determine trust domain")
	x509Ctx, err := client.FetchX509Context(ctx)
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("failed to fetch X509 context: %w", err)
	}

	if len(x509Ctx.SVIDs) == 0 {
		return spiffeid.ID{}, fmt.Errorf("no X509-SVIDs returned from SPIFFE workload API")
	}

	// Get trust domain from the workload's own SVID
	trustDomain := x509Ctx.SVIDs[0].ID.TrustDomain()
	log.WithField("trustDomain", trustDomain.String()).Debug("SPIFFE: obtained trust domain")

	// Build SPIFFE ID for the service account
	// Standard format: spiffe://<trust-domain>/ns/<namespace>/sa/<sa-name>
	path := fmt.Sprintf("/ns/%s/sa/%s", namespace, serviceAccountName)
	return spiffeid.FromPath(trustDomain, path)
}

// fetchSPIFFEJWT fetches a JWT-SVID from the SPIFFE Workload API.
// The controller pod has multiple SPIFFE IDs assigned via ClusterSPIFFEID CRs (one per project).
// When subjectSPIFFEID is provided, it selects the matching SVID from the controller's own identities.
// When subjectSPIFFEID is zero, it fetches the workload's default JWT-SVID.
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

	// Build params with audience and optional subject to select a specific SVID
	params := jwtsvid.Params{Audience: audience}
	if !subjectSPIFFEID.IsZero() {
		// Select the project-specific SVID from the controller's assigned identities
		params.Subject = subjectSPIFFEID
		log.WithFields(log.Fields{
			"subject":  subjectSPIFFEID.String(),
			"audience": audience,
		}).Debug("SPIFFE: requesting JWT-SVID for project identity")
	} else {
		log.WithField("audience", audience).Debug("SPIFFE: requesting JWT-SVID for own identity")
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

// Ensure SPIFFEProvider implements Provider
var _ Provider = (*SPIFFEProvider)(nil)
