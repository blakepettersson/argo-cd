package commands

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/argoproj/argo-cd/v3/reposerver"
	"github.com/argoproj/argo-cd/v3/reposerver/cache"
	"github.com/argoproj/argo-cd/v3/reposerver/metrics"
	"github.com/argoproj/argo-cd/v3/reposerver/repository"
	"github.com/argoproj/argo-cd/v3/util/askpass"
	cacheutil "github.com/argoproj/argo-cd/v3/util/cache"
	utiltls "github.com/argoproj/argo-cd/v3/util/tls"
	traceutil "github.com/argoproj/argo-cd/v3/util/trace"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestRun_SignalHandling_GracefulShutdown(t *testing.T) {
	d := &repoServer{
		serveMetrics: func(_ string, _ http.Handler) {},
		initTracer: func(ctx context.Context, serviceName, address string, insecure bool, headers map[string]string, attrs []string) (func(), error) {
			return func() {}, nil
		},
		buildFailoverRedisClient: func(sentinelMaster, sentinelUsername, sentinelPassword, password, username string, redisDB, maxRetries int, tlsConfig *tls.Config, sentinelAddresses []string) *redis.Client {
			return &redis.Client{}
		},
		buildRedisClient: func(redisAddress, password, username string, redisDB, maxRetries int, tlsConfig *tls.Config) *redis.Client {
			return &redis.Client{}
		},
		listen: func(network, address string) (net.Listener, error) {
			return net.Listen(network, address)
		},
		newRepoServer: func(metricsServer *metrics.MetricsServer, cache *cache.Cache, config *tls.Config, initConstants repository.RepoServerInitConstants, gitCredsStore askpass.Server) (*reposerver.ArgoCDRepoServer, error) {
			return &reposerver.ArgoCDRepoServer{}, nil
		},
	}

	var err error
	doneCh := make(chan struct{})
	go func() {
		err = d.Run(t.Context(), &RepoServerConfig{
			MetricsPort:                       1234,
			MaxCombinedDirectoryManifestsSize: "10Mi",
			StreamedManifestMaxExtractedSize:  "10Mi",
			StreamedManifestMaxTarSize:        "10Mi",
			HelmManifestMaxExtractedSize:      "10Mi",
			OCIManifestMaxExtractedSize:       "10Mi",
			HelmRegistryMaxIndexSize:          "10Mi",
			InitConstants:                     &repository.RepoServerInitConstants{},
			OTELPOpts:                         &traceutil.OTELPOpts{},
			DisableTLS:                        true,
			Cache: &cache.RepoCacheConfig{
				CacheConfig: cacheutil.CacheConfig{
					CompressionStr: "gzip",
				},
				RepoCacheExpiration:      0,
				RevisionCacheExpiration:  0,
				RevisionCacheLockTimeout: 0,
			},
			TLS: &utiltls.TLSConfig{},
		})
		close(doneCh)
	}()

	// Allow some time for the notification controller to register the signal handler
	time.Sleep(50 * time.Millisecond)

	proc, err := os.FindProcess(os.Getpid())
	require.NoErrorf(t, err, "failed to find process: %v", err)
	err = proc.Signal(syscall.SIGINT)
	require.NoErrorf(t, err, "failed to send SIGINT: %v", err)

	select {
	case <-doneCh:
		require.NoError(t, err)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout: notification.Run did not exit after SIGINT")
	}
}
