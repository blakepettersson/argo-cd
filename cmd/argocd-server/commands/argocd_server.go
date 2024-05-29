package commands

import (
	"context"
	"fmt"
	cacheutil "github.com/argoproj/argo-cd/v2/util/cache"
	flag "github.com/spf13/pflag"
	"k8s.io/client-go/rest"
	"math"
	"strings"
	"time"

	"github.com/argoproj/pkg/stats"
	"github.com/redis/go-redis/v9"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	cmdutil "github.com/argoproj/argo-cd/v2/cmd/util"
	"github.com/argoproj/argo-cd/v2/common"
	"github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
	appclientset "github.com/argoproj/argo-cd/v2/pkg/client/clientset/versioned"
	"github.com/argoproj/argo-cd/v2/reposerver/apiclient"
	reposervercache "github.com/argoproj/argo-cd/v2/reposerver/cache"
	"github.com/argoproj/argo-cd/v2/server"
	servercache "github.com/argoproj/argo-cd/v2/server/cache"
	"github.com/argoproj/argo-cd/v2/util/cli"
	"github.com/argoproj/argo-cd/v2/util/dex"
	"github.com/argoproj/argo-cd/v2/util/env"
	"github.com/argoproj/argo-cd/v2/util/errors"
	"github.com/argoproj/argo-cd/v2/util/kube"
	"github.com/argoproj/argo-cd/v2/util/templates"
	"github.com/argoproj/argo-cd/v2/util/tls"
	traceutil "github.com/argoproj/argo-cd/v2/util/trace"
)

const (
	failureRetryCountEnv              = "ARGOCD_K8S_RETRY_COUNT"
	failureRetryPeriodMilliSecondsEnv = "ARGOCD_K8S_RETRY_DURATION_MILLISECONDS"
)

var (
	failureRetryCount              = env.ParseNumFromEnv(failureRetryCountEnv, 0, 0, 10)
	failureRetryPeriodMilliSeconds = env.ParseNumFromEnv(failureRetryPeriodMilliSecondsEnv, 100, 0, 1000)
)

type ServerConfig struct {
	flags                    *flag.FlagSet
	pflags                   *flag.FlagSet
	redisClient              *redis.Client
	insecure                 bool
	listenHost               string
	listenPort               int
	metricsHost              string
	metricsPort              int
	otlpAddress              string
	otlpInsecure             bool
	otlpHeaders              map[string]string
	otlpAttrs                []string
	glogLevel                int
	clientConfig             clientcmd.ClientConfig
	repoServerTimeoutSeconds int
	baseHRef                 string
	rootPath                 string
	repoServerAddress        string
	dexServerAddress         string
	disableAuth              bool
	contentTypes             string
	enableGZip               bool
	tlsConfigCustomizerSrc   func() (tls.ConfigCustomizer, error)
	cacheSrc                 func() (*servercache.Cache, error)
	repoServerCacheSrc       func() (*reposervercache.Cache, error)
	frameOptions             string
	contentSecurityPolicy    string
	repoServerPlaintext      bool
	repoServerStrictTLS      bool
	dexServerPlaintext       bool
	dexServerStrictTLS       bool
	staticAssetsDir          string
	applicationNamespaces    []string
	enableProxyExtension     bool
	config                   *rest.Config
	namespace                string
}

func NewServerConfig(flags, pflags *flag.FlagSet) *ServerConfig {
	return &ServerConfig{flags: flags, pflags: pflags}
}

func (c *ServerConfig) WithDefaultFlags() *ServerConfig {
	c.flags.BoolVar(&c.insecure, "insecure", env.ParseBoolFromEnv("ARGOCD_SERVER_INSECURE", false), "Run server without TLS")
	c.flags.StringVar(&c.staticAssetsDir, "staticassets", env.StringFromEnv("ARGOCD_SERVER_STATIC_ASSETS", "/shared/app"), "Directory path that contains additional static assets")
	c.flags.StringVar(&c.baseHRef, "basehref", env.StringFromEnv("ARGOCD_SERVER_BASEHREF", "/"), "Value for base href in index.html. Used if Argo CD is running behind reverse proxy under subpath different from /")
	c.flags.StringVar(&c.rootPath, "rootpath", env.StringFromEnv("ARGOCD_SERVER_ROOTPATH", ""), "Used if Argo CD is running behind reverse proxy under subpath different from /")
	c.flags.StringVar(&cmdutil.LogFormat, "logformat", env.StringFromEnv("ARGOCD_SERVER_LOGFORMAT", "text"), "Set the logging format. One of: text|json")
	c.flags.StringVar(&cmdutil.LogLevel, "loglevel", env.StringFromEnv("ARGOCD_SERVER_LOG_LEVEL", "info"), "Set the logging level. One of: debug|info|warn|error")
	c.flags.IntVar(&c.glogLevel, "gloglevel", 0, "Set the glog logging level")
	c.flags.StringVar(&c.repoServerAddress, "repo-server", env.StringFromEnv("ARGOCD_SERVER_REPO_SERVER", common.DefaultRepoServerAddr), "Repo server address")
	c.flags.StringVar(&c.dexServerAddress, "dex-server", env.StringFromEnv("ARGOCD_SERVER_DEX_SERVER", common.DefaultDexServerAddr), "Dex server address")
	c.flags.BoolVar(&c.disableAuth, "disable-auth", env.ParseBoolFromEnv("ARGOCD_SERVER_DISABLE_AUTH", false), "Disable client authentication")
	c.flags.StringVar(&c.contentTypes, "api-content-types", env.StringFromEnv("ARGOCD_API_CONTENT_TYPES", "application/json", env.StringFromEnvOpts{AllowEmpty: true}), "Semicolon separated list of allowed content types for non GET api requests. Any content type is allowed if empty.")
	c.flags.BoolVar(&c.enableGZip, "enable-gzip", env.ParseBoolFromEnv("ARGOCD_SERVER_ENABLE_GZIP", true), "Enable GZIP compression")
	c.flags.StringVar(&c.listenHost, "address", env.StringFromEnv("ARGOCD_SERVER_LISTEN_ADDRESS", common.DefaultAddressAPIServer), "Listen on given address")
	c.flags.IntVar(&c.listenPort, "port", common.DefaultPortAPIServer, "Listen on given port")
	c.flags.StringVar(&c.metricsHost, env.StringFromEnv("ARGOCD_SERVER_METRICS_LISTEN_ADDRESS", "metrics-address"), common.DefaultAddressAPIServerMetrics, "Listen for metrics on given address")
	c.flags.IntVar(&c.metricsPort, "metrics-port", common.DefaultPortArgoCDAPIServerMetrics, "Start metrics on given port")
	c.flags.StringVar(&c.otlpAddress, "otlp-address", env.StringFromEnv("ARGOCD_SERVER_OTLP_ADDRESS", ""), "OpenTelemetry collector address to send traces to")
	c.flags.BoolVar(&c.otlpInsecure, "otlp-insecure", env.ParseBoolFromEnv("ARGOCD_SERVER_OTLP_INSECURE", true), "OpenTelemetry collector insecure mode")
	c.flags.StringToStringVar(&c.otlpHeaders, "otlp-headers", env.ParseStringToStringFromEnv("ARGOCD_SERVER_OTLP_HEADERS", map[string]string{}, ","), "List of OpenTelemetry collector extra headers sent with traces, headers are comma-separated key-value pairs(e.g. key1=value1,key2=value2)")
	c.flags.StringSliceVar(&c.otlpAttrs, "otlp-attrs", env.StringsFromEnv("ARGOCD_SERVER_OTLP_ATTRS", []string{}, ","), "List of OpenTelemetry collector extra attrs when send traces, each attribute is separated by a colon(e.g. key:value)")
	c.flags.IntVar(&c.repoServerTimeoutSeconds, "repo-server-timeout-seconds", env.ParseNumFromEnv("ARGOCD_SERVER_REPO_SERVER_TIMEOUT_SECONDS", 60, 0, math.MaxInt64), "Repo server RPC call timeout seconds.")
	c.flags.StringVar(&c.frameOptions, "x-frame-options", env.StringFromEnv("ARGOCD_SERVER_X_FRAME_OPTIONS", "sameorigin"), "Set X-Frame-Options header in HTTP responses to `value`. To disable, set to \"\".")
	c.flags.StringVar(&c.contentSecurityPolicy, "content-security-policy", env.StringFromEnv("ARGOCD_SERVER_CONTENT_SECURITY_POLICY", "frame-ancestors 'self';"), "Set Content-Security-Policy header in HTTP responses to `value`. To disable, set to \"\".")
	c.flags.BoolVar(&c.repoServerPlaintext, "repo-server-plaintext", env.ParseBoolFromEnv("ARGOCD_SERVER_REPO_SERVER_PLAINTEXT", false), "Use a plaintext client (non-TLS) to connect to repository server")
	c.flags.BoolVar(&c.repoServerStrictTLS, "repo-server-strict-tls", env.ParseBoolFromEnv("ARGOCD_SERVER_REPO_SERVER_STRICT_TLS", false), "Perform strict validation of TLS certificates when connecting to repo server")
	c.flags.BoolVar(&c.dexServerPlaintext, "dex-server-plaintext", env.ParseBoolFromEnv("ARGOCD_SERVER_DEX_SERVER_PLAINTEXT", false), "Use a plaintext client (non-TLS) to connect to dex server")
	c.flags.BoolVar(&c.dexServerStrictTLS, "dex-server-strict-tls", env.ParseBoolFromEnv("ARGOCD_SERVER_DEX_SERVER_STRICT_TLS", false), "Perform strict validation of TLS certificates when connecting to dex server")
	c.flags.StringSliceVar(&c.applicationNamespaces, "application-namespaces", env.StringsFromEnv("ARGOCD_APPLICATION_NAMESPACES", []string{}, ","), "List of additional namespaces where application resources can be managed in")
	c.flags.BoolVar(&c.enableProxyExtension, "enable-proxy-extension", env.ParseBoolFromEnv("ARGOCD_SERVER_ENABLE_PROXY_EXTENSION", false), "Enable Proxy Extension feature")

	c.tlsConfigCustomizerSrc = tls.AddTLSFlagsToCmd(c.flags)

	c.cacheSrc = servercache.AddCacheFlagsToCmd(c.flags, cacheutil.Options{
		OnClientCreated: func(client *redis.Client) {
			c.redisClient = client
		},
	})
	c.repoServerCacheSrc = reposervercache.AddCacheFlagsToCmd(c.flags, cacheutil.Options{FlagPrefix: "repo-server-"})
	return c
}

func (c *ServerConfig) WithKubectlFlags() *ServerConfig {
	c.clientConfig = cli.AddKubectlFlagsToSet(c.pflags)
	return c
}

func (c *ServerConfig) WithK8sSettings(namespace string, config *rest.Config) *ServerConfig {
	c.config = config
	c.namespace = namespace
	return c
}

func (c *ServerConfig) CreateServer(ctx context.Context) *server.ArgoCDServer {
	vers := common.GetVersion()
	var namespace string
	var config *rest.Config
	if c.clientConfig != nil {
		ns, _, err := c.clientConfig.Namespace()
		errors.CheckError(err)
		config, err = c.clientConfig.ClientConfig()
		errors.CheckError(err)

		namespace = ns
	} else {
		config = c.config
		namespace = c.namespace
	}

	appclientsetConfig := rest.CopyConfig(config)
	errors.CheckError(v1alpha1.SetK8SConfigDefaults(config))
	errors.CheckError(v1alpha1.SetK8SConfigDefaults(appclientsetConfig))

	vers.LogStartupInfo(
		"ArgoCD API Server",
		map[string]any{
			"namespace": namespace,
			"port":      c.listenPort,
		},
	)

	cli.SetLogFormat(cmdutil.LogFormat)
	cli.SetLogLevel(cmdutil.LogLevel)
	cli.SetGLogLevel(c.glogLevel)

	tlsConfigCustomizer, err := c.tlsConfigCustomizerSrc()
	errors.CheckError(err)
	cache, err := c.cacheSrc()
	errors.CheckError(err)
	repoServerCache, err := c.repoServerCacheSrc()
	errors.CheckError(err)

	kubeclientset := kubernetes.NewForConfigOrDie(config)
	config.UserAgent = fmt.Sprintf("argocd-server/%s (%s)", vers.Version, vers.Platform)

	if failureRetryCount > 0 {
		appclientsetConfig = kube.AddFailureRetryWrapper(appclientsetConfig, failureRetryCount, failureRetryPeriodMilliSeconds)
	}
	appClientSet := appclientset.NewForConfigOrDie(appclientsetConfig)
	tlsConfig := apiclient.TLSConfiguration{
		DisableTLS:       c.repoServerPlaintext,
		StrictValidation: c.repoServerStrictTLS,
	}

	// Load CA information to use for validating connections to the
	// repository server, if strict TLS validation was requested.
	if !c.repoServerPlaintext && c.repoServerStrictTLS {
		pool, err := tls.LoadX509CertPool(
			fmt.Sprintf("%s/server/tls/tls.crt", env.StringFromEnv(common.EnvAppConfigPath, common.DefaultAppConfigPath)),
			fmt.Sprintf("%s/server/tls/ca.crt", env.StringFromEnv(common.EnvAppConfigPath, common.DefaultAppConfigPath)),
		)
		if err != nil {
			log.Fatalf("%v", err)
		}
		tlsConfig.Certificates = pool
	}

	dexTlsConfig := &dex.DexTLSConfig{
		DisableTLS:       c.dexServerPlaintext,
		StrictValidation: c.dexServerStrictTLS,
	}

	if !c.dexServerPlaintext && c.dexServerStrictTLS {
		pool, err := tls.LoadX509CertPool(
			fmt.Sprintf("%s/dex/tls/ca.crt", env.StringFromEnv(common.EnvAppConfigPath, common.DefaultAppConfigPath)),
		)
		if err != nil {
			log.Fatalf("%v", err)
		}
		dexTlsConfig.RootCAs = pool
		cert, err := tls.LoadX509Cert(
			fmt.Sprintf("%s/dex/tls/tls.crt", env.StringFromEnv(common.EnvAppConfigPath, common.DefaultAppConfigPath)),
		)
		if err != nil {
			log.Fatalf("%v", err)
		}
		dexTlsConfig.Certificate = cert.Raw
	}

	repoclientset := apiclient.NewRepoServerClientset(c.repoServerAddress, c.repoServerTimeoutSeconds, tlsConfig)
	if c.rootPath != "" {
		if c.baseHRef != "" && c.baseHRef != c.rootPath {
			log.Warnf("--basehref and --rootpath had conflict: basehref: %s rootpath: %s", c.baseHRef, c.rootPath)
		}
		c.baseHRef = c.rootPath
	}

	var contentTypesList []string
	if c.contentTypes != "" {
		contentTypesList = strings.Split(c.contentTypes, ";")
	}

	argoCDOpts := server.ArgoCDServerOpts{
		Insecure:              c.insecure,
		ListenPort:            c.listenPort,
		ListenHost:            c.listenHost,
		MetricsPort:           c.metricsPort,
		MetricsHost:           c.metricsHost,
		Namespace:             namespace,
		BaseHRef:              c.baseHRef,
		RootPath:              c.rootPath,
		KubeClientset:         kubeclientset,
		AppClientset:          appClientSet,
		RepoClientset:         repoclientset,
		DexServerAddr:         c.dexServerAddress,
		DexTLSConfig:          dexTlsConfig,
		DisableAuth:           c.disableAuth,
		ContentTypes:          contentTypesList,
		EnableGZip:            c.enableGZip,
		TLSConfigCustomizer:   tlsConfigCustomizer,
		Cache:                 cache,
		RepoServerCache:       repoServerCache,
		XFrameOptions:         c.frameOptions,
		ContentSecurityPolicy: c.contentSecurityPolicy,
		RedisClient:           c.redisClient,
		StaticAssetsDir:       c.staticAssetsDir,
		ApplicationNamespaces: c.applicationNamespaces,
		EnableProxyExtension:  c.enableProxyExtension,
	}

	stats.RegisterStackDumper()
	stats.StartStatsTicker(10 * time.Minute)
	stats.RegisterHeapDumper("memprofile")
	argocd := server.NewServer(ctx, argoCDOpts)
	argocd.Init(ctx)
	lns, err := argocd.Listen()
	errors.CheckError(err)
	var closer func()
	ctx, cancel := context.WithCancel(ctx)
	if c.otlpAddress != "" {
		closer, err = traceutil.InitTracer(ctx, "argocd-server", c.otlpAddress, c.otlpInsecure, c.otlpHeaders, c.otlpAttrs)
		if err != nil {
			log.Fatalf("failed to initialize tracing: %v", err)
		}
	}
	argocd.Run(ctx, lns, cancel, closer)
	return argocd
}

// NewCommand returns a new instance of an argocd command
func NewCommand() *cobra.Command {
	var config *ServerConfig
	var command = &cobra.Command{
		Use:               cliName,
		Short:             "Run the ArgoCD API server",
		Long:              "The API server is a gRPC/REST server which exposes the API consumed by the Web UI, CLI, and CI/CD systems.  This command runs API server in the foreground.  It can be configured by following options.",
		DisableAutoGenTag: true,
		Run: func(c *cobra.Command, args []string) {
			argocd := config.CreateServer(c.Context())
			argocd.Wait()
			argocd.Shutdown()
		},
		Example: templates.Examples(`
			# Start the Argo CD API server with default settings
			$ argocd-server
				
			# Start the Argo CD API server on a custom port and enable tracing
			$ argocd-server --port 8888 --otlp-address localhost:4317
		`),
	}

	command.AddCommand(cli.NewVersionCmd(cliName))
	config = NewServerConfig(command.Flags(), command.PersistentFlags()).WithDefaultFlags().WithKubectlFlags()
	return command
}
