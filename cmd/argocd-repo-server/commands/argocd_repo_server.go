package commands

import (
	"context"
	"crypto/tls"
	"fmt"
	"math"
	"net"
	"net/http"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/argoproj/pkg/v2/stats"
	"github.com/redis/go-redis/v9"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/health/grpc_health_v1"
	"k8s.io/apimachinery/pkg/api/resource"

	cmdutil "github.com/argoproj/argo-cd/v3/cmd/util"
	"github.com/argoproj/argo-cd/v3/common"
	"github.com/argoproj/argo-cd/v3/reposerver"
	"github.com/argoproj/argo-cd/v3/reposerver/apiclient"
	reposervercache "github.com/argoproj/argo-cd/v3/reposerver/cache"
	"github.com/argoproj/argo-cd/v3/reposerver/metrics"
	"github.com/argoproj/argo-cd/v3/reposerver/repository"
	"github.com/argoproj/argo-cd/v3/util/askpass"
	cacheutil "github.com/argoproj/argo-cd/v3/util/cache"
	"github.com/argoproj/argo-cd/v3/util/cli"
	"github.com/argoproj/argo-cd/v3/util/env"
	"github.com/argoproj/argo-cd/v3/util/errors"
	"github.com/argoproj/argo-cd/v3/util/gpg"
	"github.com/argoproj/argo-cd/v3/util/healthz"
	utilio "github.com/argoproj/argo-cd/v3/util/io"
	argotls "github.com/argoproj/argo-cd/v3/util/tls"
	traceutil "github.com/argoproj/argo-cd/v3/util/trace"
)

const (
	// CLIName is the name of the CLI
	cliName = "argocd-repo-server"
)

// RepoServerConfig holds configuration for the repository server
type RepoServerConfig struct {
	OTELPOpts                         *traceutil.OTELPOpts
	InitConstants                     *repository.RepoServerInitConstants
	ListenHost                        string
	ListenPort                        int
	MetricsHost                       string
	MetricsPort                       int
	DisableTLS                        bool
	Cache                             *reposervercache.RepoCacheConfig
	TLS                               *argotls.TLSConfig
	MaxCombinedDirectoryManifestsSize string
	StreamedManifestMaxTarSize        string
	StreamedManifestMaxExtractedSize  string
	HelmManifestMaxExtractedSize      string
	HelmRegistryMaxIndexSize          string
	OCIManifestMaxExtractedSize       string
	IsGPGEnabled                      bool
	GNUPGSourcePath                   string
}

// repoServer wraps dependencies for running the server
type repoServer struct {
	initTracer               func(ctx context.Context, serviceName, address string, insecure bool, headers map[string]string, attrs []string) (func(), error)
	serveMetrics             func(addr string, handler http.Handler)
	serve                    func(lis net.Listener) error
	listen                   func(network, address string) (net.Listener, error)
	newRepoServer            func(metricsServer *metrics.MetricsServer, cache *reposervercache.Cache, config *tls.Config, initConstants repository.RepoServerInitConstants, gitCredsStore askpass.Server) (*reposerver.ArgoCDRepoServer, error)
	buildFailoverRedisClient func(sentinelMaster, sentinelUsername, sentinelPassword, password, username string, redisDB, maxRetries int, tlsConfig *tls.Config, sentinelAddresses []string) *redis.Client
	buildRedisClient         func(redisAddress, password, username string, redisDB, maxRetries int, tlsConfig *tls.Config) *redis.Client
}

func NewRepoServer() *repoServer {
	return &repoServer{
		initTracer: traceutil.InitTracer,
		serveMetrics: func(addr string, handler http.Handler) {
			errors.CheckError(http.ListenAndServe(addr, handler))
		},
		listen: net.Listen,
		newRepoServer: func(metricsServer *metrics.MetricsServer, cache *reposervercache.Cache, config *tls.Config, initConstants repository.RepoServerInitConstants, gitCredsStore askpass.Server) (*reposerver.ArgoCDRepoServer, error) {
			return reposerver.NewServer(metricsServer, cache, config, initConstants, gitCredsStore)
		},
		buildRedisClient:         cacheutil.BuildRedisClient,
		buildFailoverRedisClient: cacheutil.BuildFailoverRedisClient,
	}
}

func (r *repoServer) Run(ctx context.Context, config *RepoServerConfig) error {
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	vers := common.GetVersion()
	vers.LogStartupInfo(
		"ArgoCD Repository Server",
		map[string]any{"port": config.ListenPort},
	)

	// Recover from panic and log the error using the configured logger instead of the default.
	defer func() {
		if r := recover(); r != nil {
			log.WithField("trace", string(debug.Stack())).Fatal("Recovered from panic: ", r)
		}
	}()

	metricsServer := metrics.NewMetricsServer()
	cache, err := config.Cache.Build(r.buildRedisClient, r.buildFailoverRedisClient, metricsServer, nil)
	errors.CheckError(err)

	maxCombinedDirectoryManifestsQuantity, err := resource.ParseQuantity(config.MaxCombinedDirectoryManifestsSize)
	errors.CheckError(err)
	streamedManifestMaxTarSizeQuantity, err := resource.ParseQuantity(config.StreamedManifestMaxTarSize)
	errors.CheckError(err)
	streamedManifestMaxExtractedSizeQuantity, err := resource.ParseQuantity(config.StreamedManifestMaxExtractedSize)
	errors.CheckError(err)
	helmManifestMaxExtractedSizeQuantity, err := resource.ParseQuantity(config.HelmManifestMaxExtractedSize)
	errors.CheckError(err)
	ociManifestMaxExtractedSizeQuantity, err := resource.ParseQuantity(config.OCIManifestMaxExtractedSize)
	errors.CheckError(err)
	helmRegistryMaxIndexSizeQuantity, err := resource.ParseQuantity(config.HelmRegistryMaxIndexSize)
	errors.CheckError(err)

	askPassServer := askpass.NewServer(askpass.SocketPath)

	config.InitConstants.MaxCombinedDirectoryManifestsSize = maxCombinedDirectoryManifestsQuantity
	config.InitConstants.StreamedManifestMaxExtractedSize = streamedManifestMaxExtractedSizeQuantity.ToDec().Value()
	config.InitConstants.StreamedManifestMaxTarSize = streamedManifestMaxTarSizeQuantity.ToDec().Value()
	config.InitConstants.HelmManifestMaxExtractedSize = helmManifestMaxExtractedSizeQuantity.ToDec().Value()
	config.InitConstants.HelmRegistryMaxIndexSize = helmRegistryMaxIndexSizeQuantity.ToDec().Value()
	config.InitConstants.OCIManifestMaxExtractedSize = ociManifestMaxExtractedSizeQuantity.ToDec().Value()

	if config.OTELPOpts.Address != "" {
		closer, err := r.initTracer(ctx, cliName, config.OTELPOpts.Address, config.OTELPOpts.Insecure, config.OTELPOpts.Headers, config.OTELPOpts.Attributes)
		errors.CheckError(err)
		defer closer()
	}

	healthz.ServeHealthCheck(http.DefaultServeMux, func(r *http.Request) error {
		if val, ok := r.URL.Query()["full"]; ok && len(val) > 0 && val[0] == "true" {
			// connect to itself to make sure repo server is able to serve connection
			// used by liveness probe to auto restart repo server
			// see https://github.com/argoproj/argo-cd/issues/5110 for more information
			conn, err := apiclient.NewConnection(fmt.Sprintf("localhost:%d", config.ListenPort), 60, &apiclient.TLSConfiguration{DisableTLS: config.DisableTLS})
			if err != nil {
				return err
			}
			defer utilio.Close(conn)
			client := grpc_health_v1.NewHealthClient(conn)
			res, err := client.Check(r.Context(), &grpc_health_v1.HealthCheckRequest{})
			if err != nil {
				return err
			}
			if res.Status != grpc_health_v1.HealthCheckResponse_SERVING {
				return fmt.Errorf("grpc health check status is '%v'", res.Status)
			}
		}
		return nil
	})
	http.Handle("/metrics", metricsServer.GetHandler())
	go r.serveMetrics(fmt.Sprintf("%s:%d", config.MetricsHost, config.MetricsPort), nil)
	go func() { errors.CheckError(askPassServer.Run()) }()

	if config.IsGPGEnabled {
		log.Infof("Initializing GnuPG keyring at %s", common.GetGnuPGHomePath())
		errors.CheckError(gpg.InitializeGnuPG())

		log.Infof("Populating GnuPG keyring with keys from %s", config.GNUPGSourcePath)
		added, removed, err := gpg.SyncKeyRingFromDirectory(config.GNUPGSourcePath)
		errors.CheckError(err)
		log.Infof("Loaded %d (and removed %d) keys from keyring", len(added), len(removed))

		go func() { errors.CheckError(reposerver.StartGPGWatcher(config.GNUPGSourcePath)) }()
	}

	listener, err := r.listen("tcp", fmt.Sprintf("%s:%d", config.ListenHost, config.ListenPort))
	errors.CheckError(err)
	log.Infof("argocd-repo-server is listening on %s", listener.Addr())
	stats.RegisterStackDumper()
	stats.StartStatsTicker(10 * time.Minute)
	stats.RegisterHeapDumper("memprofile")

	var tlsConfig *tls.Config
	if !config.DisableTLS {
		err = config.TLS.Validate()
		errors.CheckError(err)
		tlsConfig = config.TLS.AsNativeTLSConfig()
	}

	log.Println("starting grpc server")
	server, err := r.newRepoServer(metricsServer, cache, tlsConfig, *config.InitConstants, askPassServer)
	errors.CheckError(err)
	grpcServer := server.CreateGRPC()
	go func() {
		errors.CheckError(grpcServer.Serve(listener))
	}()
	<-ctx.Done()
	stop()
	log.Println("clean shutdown")
	return nil
}

// NewCommand returns a new cobra.Command for the repo server
func NewCommand() *cobra.Command {
	config := RepoServerConfig{
		IsGPGEnabled:    gpg.IsGPGEnabled(),
		GNUPGSourcePath: env.StringFromEnv(common.EnvGPGDataPath, "/app/config/gpg/source"),
		OTELPOpts:       &traceutil.OTELPOpts{},
		TLS: &argotls.TLSConfig{
			HostList: []string{"localhost", "reposerver"},
			KeyPath:  env.StringFromEnv(common.EnvAppConfigPath, common.DefaultAppConfigPath) + "/reposerver/tls/tls.key",
			CertPath: env.StringFromEnv(common.EnvAppConfigPath, common.DefaultAppConfigPath) + "/reposerver/tls/tls.crt",
		},
		InitConstants: &repository.RepoServerInitConstants{
			PauseGenerationAfterFailedGenerationAttempts: env.ParseNumFromEnv(common.EnvPauseGenerationAfterFailedAttempts, 3, 0, math.MaxInt32),
			PauseGenerationOnFailureForMinutes:           env.ParseNumFromEnv(common.EnvPauseGenerationMinutes, 60, 0, math.MaxInt32),
			PauseGenerationOnFailureForRequests:          env.ParseNumFromEnv(common.EnvPauseGenerationRequests, 0, 0, math.MaxInt32),
			SubmoduleEnabled:                             env.ParseBoolFromEnv(common.EnvGitSubmoduleEnabled, true),
		},
		Cache: &reposervercache.RepoCacheConfig{},
	}

	command := &cobra.Command{
		Use:               cliName,
		Short:             "Run ArgoCD Repository Server",
		Long:              "ArgoCD Repository Server is an internal service which maintains a local cache of the Git repository and generates Kubernetes manifests.",
		DisableAutoGenTag: true,
		RunE: func(c *cobra.Command, _ []string) error {
			cli.SetLogFormat(cmdutil.LogFormat)
			cli.SetLogLevel(cmdutil.LogLevel)
			return NewRepoServer().Run(c.Context(), &config)
		},
	}

	command.Flags().StringVar(&cmdutil.LogFormat, "logformat", env.StringFromEnv("ARGOCD_REPO_SERVER_LOGFORMAT", "json"), "Set the logging format. One of: json|text")
	command.Flags().StringVar(&cmdutil.LogLevel, "loglevel", env.StringFromEnv("ARGOCD_REPO_SERVER_LOGLEVEL", "info"), "Set the logging level. One of: debug|info|warn|error")
	command.Flags().Int64Var(&config.InitConstants.ParallelismLimit, "parallelismlimit", int64(env.ParseNumFromEnv("ARGOCD_REPO_SERVER_PARALLELISM_LIMIT", 0, 0, math.MaxInt32)), "Limit on number of concurrent manifest generate requests.")
	command.Flags().StringVar(&config.ListenHost, "address", env.StringFromEnv("ARGOCD_REPO_SERVER_LISTEN_ADDRESS", common.DefaultAddressRepoServer), "Listen address for incoming connections")
	command.Flags().IntVar(&config.ListenPort, "port", common.DefaultPortRepoServer, "Listen port for incoming connections")
	command.Flags().StringVar(&config.MetricsHost, "metrics-address", env.StringFromEnv("ARGOCD_REPO_SERVER_METRICS_LISTEN_ADDRESS", common.DefaultAddressRepoServerMetrics), "Listen address for metrics")
	command.Flags().IntVar(&config.MetricsPort, "metrics-port", common.DefaultPortRepoServerMetrics, "Metrics server port")
	command.Flags().StringVar(&config.OTELPOpts.Address, "otlp-address", env.StringFromEnv("ARGOCD_REPO_SERVER_OTLP_ADDRESS", ""), "OpenTelemetry collector address")
	command.Flags().BoolVar(&config.OTELPOpts.Insecure, "otlp-insecure", env.ParseBoolFromEnv("ARGOCD_REPO_SERVER_OTLP_INSECURE", true), "Enable insecure mode for OTLP")
	command.Flags().StringToStringVar(&config.OTELPOpts.Headers, "otlp-headers", env.ParseStringToStringFromEnv("ARGOCD_REPO_SERVER_OTLP_HEADERS", map[string]string{}, ","), "OTLP collector headers")
	command.Flags().StringSliceVar(&config.OTELPOpts.Attributes, "otlp-attrs", env.StringsFromEnv("ARGOCD_REPO_SERVER_OTLP_ATTRS", []string{}, ","), "OTLP collector attributes")
	command.Flags().BoolVar(&config.DisableTLS, "disable-tls", env.ParseBoolFromEnv("ARGOCD_REPO_SERVER_DISABLE_TLS", false), "Disable TLS for gRPC endpoint")
	command.Flags().StringVar(&config.MaxCombinedDirectoryManifestsSize, "max-combined-directory-manifests-size", env.StringFromEnv("ARGOCD_REPO_SERVER_MAX_COMBINED_DIRECTORY_MANIFESTS_SIZE", "10M"), "Max combined size of manifest files in a directory-type Application")
	command.Flags().StringArrayVar(&config.InitConstants.CMPTarExcludedGlobs, "plugin-tar-exclude", env.StringsFromEnv("ARGOCD_REPO_SERVER_PLUGIN_TAR_EXCLUSIONS", []string{}, ";"), "Globs to exclude when sending tarballs to plugins")
	command.Flags().BoolVar(&config.InitConstants.AllowOutOfBoundsSymlinks, "allow-oob-symlinks", env.ParseBoolFromEnv("ARGOCD_REPO_SERVER_ALLOW_OUT_OF_BOUNDS_SYMLINKS", false), "Allow out-of-bounds symlinks in repositories")
	command.Flags().StringVar(&config.StreamedManifestMaxTarSize, "streamed-manifest-max-tar-size", env.StringFromEnv("ARGOCD_REPO_SERVER_STREAMED_MANIFEST_MAX_TAR_SIZE", "100M"), "Max size of streamed manifest archives")
	command.Flags().StringVar(&config.StreamedManifestMaxExtractedSize, "streamed-manifest-max-extracted-size", env.StringFromEnv("ARGOCD_REPO_SERVER_STREAMED_MANIFEST_MAX_EXTRACTED_SIZE", "1G"), "Max extracted size of streamed manifest archives")
	command.Flags().StringVar(&config.HelmManifestMaxExtractedSize, "helm-manifest-max-extracted-size", env.StringFromEnv("ARGOCD_REPO_SERVER_HELM_MANIFEST_MAX_EXTRACTED_SIZE", "1G"), "Max extracted size of helm manifest archives")
	command.Flags().StringVar(&config.HelmRegistryMaxIndexSize, "helm-registry-max-index-size", env.StringFromEnv("ARGOCD_REPO_SERVER_HELM_MANIFEST_MAX_INDEX_SIZE", "1G"), "Max size of registry index file")
	command.Flags().StringVar(&config.OCIManifestMaxExtractedSize, "oci-manifest-max-extracted-size", env.StringFromEnv("ARGOCD_REPO_SERVER_OCI_MANIFEST_MAX_EXTRACTED_SIZE", "1G"), "Max extracted size of OCI manifest archives")
	command.Flags().BoolVar(&config.InitConstants.DisableOCIManifestMaxExtractedSize, "disable-oci-manifest-max-extracted-size", env.ParseBoolFromEnv("ARGOCD_REPO_SERVER_DISABLE_OCI_MANIFEST_MAX_EXTRACTED_SIZE", false), "Disable max size limit for OCI manifest archives")
	command.Flags().BoolVar(&config.InitConstants.DisableHelmManifestMaxExtractedSize, "disable-helm-manifest-max-extracted-size", env.ParseBoolFromEnv("ARGOCD_REPO_SERVER_DISABLE_HELM_MANIFEST_MAX_EXTRACTED_SIZE", false), "Disable max size limit for helm manifest archives")
	command.Flags().BoolVar(&config.InitConstants.IncludeHiddenDirectories, "include-hidden-directories", env.ParseBoolFromEnv("ARGOCD_REPO_SERVER_INCLUDE_HIDDEN_DIRECTORIES", false), "Include hidden directories in Git")
	command.Flags().BoolVar(&config.InitConstants.CMPUseManifestGeneratePaths, "plugin-use-manifest-generate-paths", env.ParseBoolFromEnv("ARGOCD_REPO_SERVER_PLUGIN_USE_MANIFEST_GENERATE_PATHS", false), "Pass manifest-generate-paths to cmpserver")
	command.Flags().StringSliceVar(&config.InitConstants.OCIMediaTypes, "oci-layer-media-types", env.StringsFromEnv("ARGOCD_REPO_SERVER_OCI_LAYER_MEDIA_TYPES", []string{"application/vnd.oci.image.layer.v1.tar", "application/vnd.oci.image.layer.v1.tar+gzip", "application/vnd.cncf.helm.chart.content.v1.tar+gzip"}, ","), "Allowed media types for OCI layers")

	config.TLS.AddTLSFlagsToConfig(command)
	reposervercache.AddCacheFlagsToConfig(command, config.Cache, "")
	return command
}
