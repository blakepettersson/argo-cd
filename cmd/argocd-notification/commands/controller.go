package commands

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/argoproj/argo-cd/v3/util/env"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/client-go/rest"

	"github.com/argoproj/argo-cd/v3/common"
	"github.com/argoproj/argo-cd/v3/reposerver/apiclient"
	service "github.com/argoproj/argo-cd/v3/util/notification/argocd"
	"github.com/argoproj/argo-cd/v3/util/tls"

	notificationscontroller "github.com/argoproj/argo-cd/v3/notification_controller/controller"

	"github.com/argoproj/notifications-engine/pkg/controller"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	defaultMetricsPort = 9001
)

func addK8SFlagsToCmd(cmd *cobra.Command) clientcmd.ClientConfig {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	loadingRules.DefaultClientConfig = &clientcmd.DefaultClientConfig
	overrides := clientcmd.ConfigOverrides{}
	kflags := clientcmd.RecommendedConfigOverrideFlags("")
	cmd.PersistentFlags().StringVar(&loadingRules.ExplicitPath, "kubeconfig", "", "Path to a kube config. Only required if out-of-cluster")
	clientcmd.BindOverrideFlags(&overrides, cmd.PersistentFlags(), kflags)
	return clientcmd.NewInteractiveDeferredLoadingClientConfig(loadingRules, &overrides, os.Stdin)
}

type NotificationControllerConfig struct {
	ProcessorsCount                int
	Namespace                      string
	AppLabelSelector               string
	LogLevel                       string
	LogFormat                      string
	MetricsPort                    int
	ArgoCDRepoServer               string
	ArgoCDRepoServerPlaintext      bool
	ArgoCDRepoServerStrictTLS      bool
	ConfigMapName                  string
	SecretName                     string
	ApplicationNamespaces          []string
	SelfServiceNotificationEnabled bool
	TLSCertPath                    string
	TLSCACertPath                  string
}

type notification struct {
	serveMetrics     func(addr string, handler http.Handler)
	newArgoCDService func(clientset kubernetes.Interface, namespace string, repoClientset apiclient.Clientset) (service.Service, error)
	newController    func(k8sClient kubernetes.Interface, client dynamic.Interface, argocdService service.Service, namespace string, applicationNamespaces []string, appLabelSelector string, registry *controller.MetricsRegistry, secretName string, configMapName string, selfServiceNotificationEnabled bool) notificationscontroller.NotificationController
	getNamespace     func() (string, bool, error)
	getRESTConfig    func() (*rest.Config, error)
}

func NewNotificationController(clientConfig clientcmd.ClientConfig) *notification {
	return &notification{
		getNamespace:     clientConfig.Namespace,
		getRESTConfig:    clientConfig.ClientConfig,
		newArgoCDService: service.NewArgoCDService,
		newController:    notificationscontroller.NewController,
		serveMetrics: func(addr string, handler http.Handler) {
			log.Fatal(http.ListenAndServe(addr, handler))
		},
	}
}

func (n *notification) Run(ctx context.Context, cfg *NotificationControllerConfig) error {
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	vers := common.GetVersion()
	namespace, _, err := n.getNamespace()
	if err != nil {
		return err
	}
	vers.LogStartupInfo(
		"ArgoCD Notifications Controller",
		map[string]any{"namespace": namespace},
	)

	restConfig, err := n.getRESTConfig()
	if err != nil {
		return fmt.Errorf("failed to create REST client config: %w", err)
	}
	restConfig.UserAgent = fmt.Sprintf("argocd-notifications-controller/%s (%s)", vers.Version, vers.Platform)
	dynamicClient, err := dynamic.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("failed to create dynamic client: %w", err)
	}
	k8sClient, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("failed to create Kubernetes client: %w", err)
	}
	if namespace == "" {
		namespace, _, err = n.getNamespace()
		if err != nil {
			return fmt.Errorf("failed to determine controller's host namespace: %w", err)
		}
	}

	// Recover from panic and log the error using the configured logger instead of the default.
	defer func() {
		if r := recover(); r != nil {
			log.WithField("trace", string(debug.Stack())).Fatal("Recovered from panic: ", r)
		}
	}()

	tlsConfig := apiclient.TLSConfiguration{
		DisableTLS:       cfg.ArgoCDRepoServerPlaintext,
		StrictValidation: cfg.ArgoCDRepoServerStrictTLS,
	}
	if !tlsConfig.DisableTLS && tlsConfig.StrictValidation {
		pool, err := tls.LoadX509CertPool(cfg.TLSCertPath, cfg.TLSCACertPath)
		if err != nil {
			return fmt.Errorf("failed to load repo-server certificate pool: %w", err)
		}
		tlsConfig.Certificates = pool
	}
	repoClientset := apiclient.NewRepoServerClientset(cfg.ArgoCDRepoServer, 5, tlsConfig)
	argocdService, err := n.newArgoCDService(k8sClient, cfg.Namespace, repoClientset)
	if err != nil {
		return fmt.Errorf("failed to initialize Argo CD service: %w", err)
	}
	defer argocdService.Close()

	registry := controller.NewMetricsRegistry("argocd")
	http.Handle("/metrics", promhttp.HandlerFor(prometheus.Gatherers{registry, prometheus.DefaultGatherer}, promhttp.HandlerOpts{}))
	go n.serveMetrics(fmt.Sprintf("0.0.0.0:%d", cfg.MetricsPort), http.DefaultServeMux)
	log.Infof("serving metrics on port %d", cfg.MetricsPort)
	log.Infof("loading configuration %d", cfg.MetricsPort)

	ctrl := n.newController(k8sClient, dynamicClient, argocdService, namespace, cfg.ApplicationNamespaces, cfg.AppLabelSelector, registry, cfg.SecretName, cfg.ConfigMapName, cfg.SelfServiceNotificationEnabled)
	if err = ctrl.Init(ctx); err != nil {
		return fmt.Errorf("failed to initialize controller: %w", err)
	}

	go ctrl.Run(ctx, cfg.ProcessorsCount)
	<-ctx.Done()
	stop() // unregister the signal handler as soon as we receive a signal
	return nil
}

func NewCommand() *cobra.Command {
	var clientConfig clientcmd.ClientConfig
	cfg := &NotificationControllerConfig{
		TLSCertPath:   env.StringFromEnv(common.EnvAppConfigPath, common.DefaultAppConfigPath) + "/reposerver/tls/tls.crt",
		TLSCACertPath: env.StringFromEnv(common.EnvAppConfigPath, common.DefaultAppConfigPath) + "/reposerver/tls/ca.crt",
	}
	cmd := &cobra.Command{
		Use:   "controller",
		Short: "Starts Argo CD Notifications controller",
		RunE: func(cmd *cobra.Command, _ []string) error {
			level, err := log.ParseLevel(cfg.LogLevel)
			if err != nil {
				return fmt.Errorf("failed to parse log level: %w", err)
			}
			log.SetLevel(level)
			switch strings.ToLower(cfg.LogFormat) {
			case "json":
				log.SetFormatter(&log.JSONFormatter{})
			case "text":
				if os.Getenv("FORCE_LOG_COLORS") == "1" {
					log.SetFormatter(&log.TextFormatter{ForceColors: true})
				}
			default:
				return fmt.Errorf("unknown log format '%s'", cfg.LogFormat)
			}

			return NewNotificationController(clientConfig).Run(cmd.Context(), cfg)
		},
	}
	clientConfig = addK8SFlagsToCmd(cmd)
	cmd.Flags().IntVar(&cfg.ProcessorsCount, "processors-count", 1, "Processors count.")
	cmd.Flags().StringVar(&cfg.AppLabelSelector, "app-label-selector", "", "App label selector.")
	cmd.Flags().StringVar(&cfg.Namespace, "namespace", "", "Namespace which notification handles. Current namespace if empty.")
	cmd.Flags().StringVar(&cfg.LogLevel, "loglevel", env.StringFromEnv("ARGOCD_NOTIFICATIONS_CONTROLLER_LOGLEVEL", "info"), "Set the logging level. One of: debug|info|warn|error")
	cmd.Flags().StringVar(&cfg.LogFormat, "logformat", env.StringFromEnv("ARGOCD_NOTIFICATIONS_CONTROLLER_LOGFORMAT", "json"), "Set the logging format. One of: json|text")
	cmd.Flags().IntVar(&cfg.MetricsPort, "metrics-port", defaultMetricsPort, "Metrics port")
	cmd.Flags().StringVar(&cfg.ArgoCDRepoServer, "argocd-repo-server", common.DefaultRepoServerAddr, "Argo CD repo server address")
	cmd.Flags().BoolVar(&cfg.ArgoCDRepoServerPlaintext, "argocd-repo-server-plaintext", env.ParseBoolFromEnv("ARGOCD_NOTIFICATION_CONTROLLER_REPO_SERVER_PLAINTEXT", false), "Use a plaintext client (non-TLS) to connect to repository server")
	cmd.Flags().BoolVar(&cfg.ArgoCDRepoServerStrictTLS, "argocd-repo-server-strict-tls", false, "Perform strict validation of TLS certificates when connecting to repo server")
	cmd.Flags().StringVar(&cfg.ConfigMapName, "config-map-name", "argocd-notifications-cm", "Set notifications ConfigMap name")
	cmd.Flags().StringVar(&cfg.SecretName, "secret-name", "argocd-notifications-secret", "Set notifications Secret name")
	cmd.Flags().StringSliceVar(&cfg.ApplicationNamespaces, "application-namespaces", env.StringsFromEnv("ARGOCD_APPLICATION_NAMESPACES", []string{}, ","), "List of additional namespaces that this notification should send notifications for")
	cmd.Flags().BoolVar(&cfg.SelfServiceNotificationEnabled, "self-service-notification-enabled", env.ParseBoolFromEnv("ARGOCD_NOTIFICATION_CONTROLLER_SELF_SERVICE_NOTIFICATION_ENABLED", false), "Allows the Argo CD notification notification to pull notification config from the namespace that the resource is in. This is useful for self-service notification.")
	return cmd
}
