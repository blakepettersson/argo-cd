package commands

import (
	"context"
	"crypto/tls"
	"fmt"
	"math"
	"runtime/debug"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"

	cmdutil "github.com/argoproj/argo-cd/v3/cmd/util"
	"github.com/argoproj/argo-cd/v3/common"
	"github.com/argoproj/argo-cd/v3/pkg/apis/application/v1alpha1"
	appclientset "github.com/argoproj/argo-cd/v3/pkg/client/clientset/versioned"
	"github.com/argoproj/argo-cd/v3/reposerver/apiclient"
	reposervercache "github.com/argoproj/argo-cd/v3/reposerver/cache"
	"github.com/argoproj/argo-cd/v3/server"
	servercache "github.com/argoproj/argo-cd/v3/server/cache"
	"github.com/argoproj/argo-cd/v3/util/argo"
	cacheutil "github.com/argoproj/argo-cd/v3/util/cache"
	"github.com/argoproj/argo-cd/v3/util/cli"
	"github.com/argoproj/argo-cd/v3/util/dex"
	"github.com/argoproj/argo-cd/v3/util/env"
	"github.com/argoproj/argo-cd/v3/util/errors"
	"github.com/argoproj/argo-cd/v3/util/kube"
	"github.com/argoproj/argo-cd/v3/util/templates"
	argotls "github.com/argoproj/argo-cd/v3/util/tls"
	traceutil "github.com/argoproj/argo-cd/v3/util/trace"
	"github.com/argoproj/pkg/v2/stats"
)

const (
	failureRetryCountEnv              = "ARGOCD_K8S_RETRY_COUNT"
	failureRetryPeriodMilliSecondsEnv = "ARGOCD_K8S_RETRY_DURATION_MILLISECONDS"
)

var (
	failureRetryCount              = env.ParseNumFromEnv(failureRetryCountEnv, 0, 0, 10)
	failureRetryPeriodMilliSeconds = env.ParseNumFromEnv(failureRetryPeriodMilliSecondsEnv, 100, 0, 1000)
	gitSubmoduleEnabled            = env.ParseBoolFromEnv(common.EnvGitSubmoduleEnabled, true)
)

type ServerConfig struct {
	OTELPOpts                *traceutil.OTELPOpts
	ServerOpts               *server.ArgoCDServerOpts
	ApplicationSetOpts       *server.ApplicationSetOpts
	RepoServerTLSConfig      *apiclient.TLSConfiguration
	TLS                      *argotls.TLSConfig
	CacheSrc                 func() (*servercache.Cache, error)
	RepoServerCache          *reposervercache.RepoCacheConfig
	RepoServerAddress        string
	RepoServerTimeoutSeconds int
}

type apiServer struct {
	newServer                func(ctx context.Context, opts server.ArgoCDServerOpts, appsetOpts server.ApplicationSetOpts) *server.ArgoCDServer
	initTracer               func(ctx context.Context, serviceName, address string, insecure bool, headers map[string]string, attrs []string) (func(), error)
	getNamespace             func() (string, bool, error)
	getRESTConfig            func() (*rest.Config, error)
	buildFailoverRedisClient func(sentinelMaster, sentinelUsername, sentinelPassword, password, username string, redisDB, maxRetries int, tlsConfig *tls.Config, sentinelAddresses []string) *redis.Client
	buildRedisClient         func(redisAddress, password, username string, redisDB, maxRetries int, tlsConfig *tls.Config) *redis.Client
}

func NewAPIServer(clientConfig clientcmd.ClientConfig) *apiServer {
	return &apiServer{
		newServer:                server.NewServer,
		initTracer:               traceutil.InitTracer,
		getNamespace:             clientConfig.Namespace,
		getRESTConfig:            clientConfig.ClientConfig,
		buildRedisClient:         cacheutil.BuildRedisClient,
		buildFailoverRedisClient: cacheutil.BuildFailoverRedisClient,
	}
}

func (a *apiServer) Run(ctx context.Context, config *ServerConfig) error {
	vers := common.GetVersion()
	namespace, _, err := a.getNamespace()
	if err != nil {
		return err
	}
	vers.LogStartupInfo(
		"ArgoCD API Server",
		map[string]any{
			"namespace": namespace,
			"port":      config.ServerOpts.ListenPort,
		},
	)

	// Recover from panic and log the error using the configured logger instead of the default.
	defer func() {
		if r := recover(); r != nil {
			log.WithField("trace", string(debug.Stack())).Fatal("Recovered from panic: ", r)
		}
	}()

	restCfg, err := a.getRESTConfig()
	errors.CheckError(err)
	errors.CheckError(v1alpha1.SetK8SConfigDefaults(restCfg))

	cache, err := config.CacheSrc()
	errors.CheckError(err)
	config.ServerOpts.Cache = cache

	repoServerCache, err := config.RepoServerCache.Build(a.buildRedisClient, a.buildFailoverRedisClient, nil, nil)
	errors.CheckError(err)
	config.ServerOpts.RepoServerCache = repoServerCache

	kubeclientset := kubernetes.NewForConfigOrDie(restCfg)
	config.ServerOpts.KubeClientset = kubeclientset

	appclientsetConfig, err := a.getRESTConfig()
	errors.CheckError(err)
	errors.CheckError(v1alpha1.SetK8SConfigDefaults(appclientsetConfig))
	restCfg.UserAgent = fmt.Sprintf("argocd-server/%s (%s)", vers.Version, vers.Platform)

	if failureRetryCount > 0 {
		appclientsetConfig = kube.AddFailureRetryWrapper(appclientsetConfig, failureRetryCount, failureRetryPeriodMilliSeconds)
	}
	appClientSet := appclientset.NewForConfigOrDie(appclientsetConfig)
	config.ServerOpts.AppClientset = appClientSet

	config.ServerOpts.DynamicClientset = dynamic.NewForConfigOrDie(restCfg)

	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = v1alpha1.AddToScheme(scheme)

	controllerClient, err := client.New(restCfg, client.Options{Scheme: scheme})
	errors.CheckError(err)
	controllerClient = client.NewDryRunClient(controllerClient)
	controllerClient = client.NewNamespacedClient(controllerClient, namespace)

	// Load CA information to use for validating connections to the
	// repository server, if strict TLS validation was requested.
	if !config.RepoServerTLSConfig.DisableTLS && config.RepoServerTLSConfig.StrictValidation {
		pool, err := argotls.LoadX509CertPool(
			env.StringFromEnv(common.EnvAppConfigPath, common.DefaultAppConfigPath)+"/server/tls/tls.crt",
			env.StringFromEnv(common.EnvAppConfigPath, common.DefaultAppConfigPath)+"/server/tls/ca.crt",
		)
		if err != nil {
			log.Fatalf("%v", err)
		}
		config.RepoServerTLSConfig.Certificates = pool
	}

	if !config.ServerOpts.DexTLSConfig.DisableTLS && config.ServerOpts.DexTLSConfig.StrictValidation {
		pool, err := argotls.LoadX509CertPool(
			env.StringFromEnv(common.EnvAppConfigPath, common.DefaultAppConfigPath) + "/dex/tls/ca.crt",
		)
		if err != nil {
			log.Fatalf("%v", err)
		}
		config.ServerOpts.DexTLSConfig.RootCAs = pool
		cert, err := argotls.LoadX509Cert(
			env.StringFromEnv(common.EnvAppConfigPath, common.DefaultAppConfigPath) + "/dex/tls/tls.crt",
		)
		if err != nil {
			log.Fatalf("%v", err)
		}
		config.ServerOpts.DexTLSConfig.Certificate = cert.Raw
	}
	if config.ServerOpts.RootPath != "" {
		if config.ServerOpts.BaseHRef != "" && config.ServerOpts.BaseHRef != config.ServerOpts.RootPath {
			log.Warnf("--basehref and --rootpath had conflict: basehref: %s rootpath: %s", config.ServerOpts.BaseHRef, config.ServerOpts.RootPath)
		}
		config.ServerOpts.BaseHRef = config.ServerOpts.RootPath
	}
	config.ServerOpts.RepoClientset = apiclient.NewRepoServerClientset(config.RepoServerAddress, config.RepoServerTimeoutSeconds, *config.RepoServerTLSConfig)

	stats.RegisterStackDumper()
	stats.StartStatsTicker(10 * time.Minute)
	stats.RegisterHeapDumper("memprofile")
	argocd := a.newServer(ctx, *config.ServerOpts, *config.ApplicationSetOpts)
	argocd.Init(ctx)
	for {
		var closer func()
		serverCtx, cancel := context.WithCancel(ctx)
		lns, err := argocd.Listen()
		errors.CheckError(err)
		if config.OTELPOpts.Address != "" {
			closer, err = a.initTracer(serverCtx, "argocd-server", config.OTELPOpts.Address, config.OTELPOpts.Insecure, config.OTELPOpts.Headers, config.OTELPOpts.Attributes)
			if err != nil {
				log.Fatalf("failed to initialize tracing: %v", err)
			}
		}

		argocd.Run(serverCtx, lns)
		if closer != nil {
			closer()
		}
		cancel()
		if argocd.TerminateRequested() {
			break
		}
	}

	return nil
}

// NewCommand returns a new instance of an argocd command
func NewCommand() *cobra.Command {
	var glogLevel int
	var contentTypes string
	var clientConfig clientcmd.ClientConfig
	config := &ServerConfig{
		OTELPOpts: &traceutil.OTELPOpts{},
		ApplicationSetOpts: &server.ApplicationSetOpts{
			GitSubmoduleEnabled: gitSubmoduleEnabled,
		},
		ServerOpts: &server.ArgoCDServerOpts{
			DexTLSConfig: &dex.DexTLSConfig{},
		},
		RepoServerTLSConfig: &apiclient.TLSConfiguration{},
		TLS:                 &argotls.TLSConfig{},
		RepoServerCache:     &reposervercache.RepoCacheConfig{},
	}
	command := &cobra.Command{
		Use:               cliName,
		Short:             "Run the ArgoCD API server",
		Long:              "The API server is a gRPC/REST server which exposes the API consumed by the Web UI, CLI, and CI/CD systems. This command runs API server in the foreground. It can be configured by following options.",
		DisableAutoGenTag: true,
		Run: func(c *cobra.Command, _ []string) {
			var contentTypesList []string
			if contentTypes != "" {
				contentTypesList = strings.Split(contentTypes, ";")
			}
			config.ServerOpts.ContentTypes = contentTypesList

			cli.SetLogFormat(cmdutil.LogFormat)
			cli.SetLogLevel(cmdutil.LogLevel)
			cli.SetGLogLevel(glogLevel)
			errors.CheckError(NewAPIServer(clientConfig).Run(c.Context(), config))
		},
		Example: templates.Examples(`
			# Start the Argo CD API server with default settings
			$ argocd-server

			# Start the Argo CD API server on a custom port and enable tracing
			$ argocd-server --port 8888 --otlp-address localhost:4317
		`),
	}

	clientConfig = cli.AddKubectlFlagsToCmd(command)
	command.Flags().BoolVar(&config.ServerOpts.Insecure, "insecure", env.ParseBoolFromEnv("ARGOCD_SERVER_INSECURE", false), "Run server without TLS")
	command.Flags().StringVar(&config.ServerOpts.StaticAssetsDir, "staticassets", env.StringFromEnv("ARGOCD_SERVER_STATIC_ASSETS", "/shared/app"), "Directory path that contains additional static assets")
	command.Flags().StringVar(&config.ServerOpts.BaseHRef, "basehref", env.StringFromEnv("ARGOCD_SERVER_BASEHREF", "/"), "Value for base href in index.html. Used if Argo CD is running behind reverse proxy under subpath different from /")
	command.Flags().StringVar(&config.ServerOpts.RootPath, "rootpath", env.StringFromEnv("ARGOCD_SERVER_ROOTPATH", ""), "Used if Argo CD is running behind reverse proxy under subpath different from /")
	command.Flags().StringVar(&cmdutil.LogFormat, "logformat", env.StringFromEnv("ARGOCD_SERVER_LOGFORMAT", "json"), "Set the logging format. One of: json|text")
	command.Flags().StringVar(&cmdutil.LogLevel, "loglevel", env.StringFromEnv("ARGOCD_SERVER_LOG_LEVEL", "info"), "Set the logging level. One of: debug|info|warn|error")
	command.Flags().IntVar(&glogLevel, "gloglevel", 0, "Set the glog logging level")
	command.Flags().StringVar(&config.RepoServerAddress, "repo-server", env.StringFromEnv("ARGOCD_SERVER_REPO_SERVER", common.DefaultRepoServerAddr), "Repo server address")
	command.Flags().StringVar(&config.ServerOpts.DexServerAddr, "dex-server", env.StringFromEnv("ARGOCD_SERVER_DEX_SERVER", common.DefaultDexServerAddr), "Dex server address")
	command.Flags().BoolVar(&config.ServerOpts.DisableAuth, "disable-auth", env.ParseBoolFromEnv("ARGOCD_SERVER_DISABLE_AUTH", false), "Disable client authentication")
	command.Flags().StringVar(&contentTypes, "api-content-types", env.StringFromEnv("ARGOCD_API_CONTENT_TYPES", "application/json", env.StringFromEnvOpts{AllowEmpty: true}), "Semicolon separated list of allowed content types for non-GET API requests. Any content type is allowed if empty.")
	command.Flags().BoolVar(&config.ServerOpts.EnableGZip, "enable-gzip", env.ParseBoolFromEnv("ARGOCD_SERVER_ENABLE_GZIP", true), "Enable GZIP compression")
	command.AddCommand(cli.NewVersionCmd(cliName))
	command.Flags().StringVar(&config.ServerOpts.ListenHost, "address", env.StringFromEnv("ARGOCD_SERVER_LISTEN_ADDRESS", common.DefaultAddressAPIServer), "Listen on given address")
	command.Flags().IntVar(&config.ServerOpts.ListenPort, "port", common.DefaultPortAPIServer, "Listen on given port")
	command.Flags().StringVar(&config.ServerOpts.MetricsHost, env.StringFromEnv("ARGOCD_SERVER_METRICS_LISTEN_ADDRESS", "metrics-address"), common.DefaultAddressAPIServerMetrics, "Listen for metrics on given address")
	command.Flags().IntVar(&config.ServerOpts.MetricsPort, "metrics-port", common.DefaultPortArgoCDAPIServerMetrics, "Start metrics on given port")
	command.Flags().StringVar(&config.OTELPOpts.Address, "otlp-address", env.StringFromEnv("ARGOCD_SERVER_OTLP_ADDRESS", ""), "OpenTelemetry collector address to send traces to")
	command.Flags().BoolVar(&config.OTELPOpts.Insecure, "otlp-insecure", env.ParseBoolFromEnv("ARGOCD_SERVER_OTLP_INSECURE", true), "OpenTelemetry collector insecure mode")
	command.Flags().StringToStringVar(&config.OTELPOpts.Headers, "otlp-headers", env.ParseStringToStringFromEnv("ARGOCD_SERVER_OTLP_HEADERS", map[string]string{}, ","), "List of OpenTelemetry collector extra headers sent with traces, headers are comma-separated key-value pairs (e.g. key1=value1,key2=value2)")
	command.Flags().StringSliceVar(&config.OTELPOpts.Attributes, "otlp-attrs", env.StringsFromEnv("ARGOCD_SERVER_OTLP_ATTRS", []string{}, ","), "List of OpenTelemetry collector extra attrs when sending traces, each attribute is separated by a colon (e.g. key:value)")
	command.Flags().IntVar(&config.RepoServerTimeoutSeconds, "repo-server-timeout-seconds", env.ParseNumFromEnv("ARGOCD_SERVER_REPO_SERVER_TIMEOUT_SECONDS", 60, 0, math.MaxInt64), "Repo server RPC call timeout seconds")
	command.Flags().StringVar(&config.ServerOpts.XFrameOptions, "x-frame-options", env.StringFromEnv("ARGOCD_SERVER_X_FRAME_OPTIONS", "sameorigin"), "Set X-Frame-Options header in HTTP responses to `value`. To disable, set to \"\".")
	command.Flags().StringVar(&config.ServerOpts.ContentSecurityPolicy, "content-security-policy", env.StringFromEnv("ARGOCD_SERVER_CONTENT_SECURITY_POLICY", "frame-ancestors 'self';"), "Set Content-Security-Policy header in HTTP responses to `value`. To disable, set to \"\".")
	command.Flags().BoolVar(&config.RepoServerTLSConfig.DisableTLS, "repo-server-plaintext", env.ParseBoolFromEnv("ARGOCD_SERVER_REPO_SERVER_PLAINTEXT", false), "Use a plaintext client (non-TLS) to connect to repository server")
	command.Flags().BoolVar(&config.RepoServerTLSConfig.StrictValidation, "repo-server-strict-tls", env.ParseBoolFromEnv("ARGOCD_SERVER_REPO_SERVER_STRICT_TLS", false), "Perform strict validation of TLS certificates when connecting to repo server")
	command.Flags().BoolVar(&config.ServerOpts.DexTLSConfig.DisableTLS, "dex-server-plaintext", env.ParseBoolFromEnv("ARGOCD_SERVER_DEX_SERVER_PLAINTEXT", false), "Use a plaintext client (non-TLS) to connect to dex server")
	command.Flags().BoolVar(&config.ServerOpts.DexTLSConfig.StrictValidation, "dex-server-strict-tls", env.ParseBoolFromEnv("ARGOCD_SERVER_DEX_SERVER_STRICT_TLS", false), "Perform strict validation of TLS certificates when connecting to dex server")
	command.Flags().StringSliceVar(&config.ServerOpts.ApplicationNamespaces, "application-namespaces", env.StringsFromEnv("ARGOCD_APPLICATION_NAMESPACES", []string{}, ","), "List of additional namespaces where application resources can be managed")
	command.Flags().BoolVar(&config.ServerOpts.EnableProxyExtension, "enable-proxy-extension", env.ParseBoolFromEnv("ARGOCD_SERVER_ENABLE_PROXY_EXTENSION", false), "Enable Proxy Extension feature")
	command.Flags().IntVar(&config.ServerOpts.WebhookParallelism, "webhook-parallelism-limit", env.ParseNumFromEnv("ARGOCD_SERVER_WEBHOOK_PARALLELISM_LIMIT", 50, 1, 1000), "Number of webhook requests processed concurrently")
	command.Flags().StringSliceVar(&config.ServerOpts.EnableK8sEvent, "enable-k8s-event", env.StringsFromEnv("ARGOCD_ENABLE_K8S_EVENT", argo.DefaultEnableEventList(), ","), "Enable ArgoCD to use k8s events. For disabling all events, set the value to `none`. For enabling specific events, set the value to `event reason`.")
	command.Flags().BoolVar(&config.ServerOpts.HydratorEnabled, "hydrator-enabled", env.ParseBoolFromEnv("ARGOCD_HYDRATOR_ENABLED", false), "Feature flag to enable Hydrator. Default: \"false\"")
	command.Flags().BoolVar(&config.ServerOpts.SyncWithReplaceAllowed, "sync-with-replace-allowed", env.ParseBoolFromEnv("ARGOCD_SYNC_WITH_REPLACE_ALLOWED", true), "Whether to allow users to select replace for syncs from UI/CLI")

	// Flags related to the applicationSet component.
	command.Flags().StringVar(&config.ApplicationSetOpts.ScmRootCAPath, "appset-scm-root-ca-path", env.StringFromEnv("ARGOCD_APPLICATIONSET_CONTROLLER_SCM_ROOT_CA_PATH", ""), "Provide Root CA Path for self-signed TLS Certificates")
	command.Flags().BoolVar(&config.ApplicationSetOpts.EnableScmProviders, "appset-enable-scm-providers", env.ParseBoolFromEnv("ARGOCD_APPLICATIONSET_CONTROLLER_ENABLE_SCM_PROVIDERS", true), "Enable retrieving information from SCM providers, used by Git/PR generators (Default: true)")
	command.Flags().StringSliceVar(&config.ApplicationSetOpts.AllowedScmProviders, "appset-allowed-scm-providers", env.StringsFromEnv("ARGOCD_APPLICATIONSET_CONTROLLER_ALLOWED_SCM_PROVIDERS", []string{}, ","), "List of allowed custom SCM provider API URLs; empty = all")
	command.Flags().BoolVar(&config.ApplicationSetOpts.EnableNewGitFileGlobbing, "appset-enable-new-git-file-globbing", env.ParseBoolFromEnv("ARGOCD_APPLICATIONSET_CONTROLLER_ENABLE_NEW_GIT_FILE_GLOBBING", false), "Enable new globbing in Git files generator.")

	config.TLS.AddTLSFlagsToConfig(command)

	config.CacheSrc = servercache.AddCacheFlagsToCmd(command, cacheutil.Options{
		OnClientCreated: func(client *redis.Client) {
			config.ServerOpts.RedisClient = client
		},
	})
	reposervercache.AddCacheFlagsToConfig(command, config.RepoServerCache, "repo-server-")
	return command
}
