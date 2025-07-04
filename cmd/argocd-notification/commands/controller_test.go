package commands

import (
	"context"
	"net/http"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/argoproj/notifications-engine/pkg/controller"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	notificationscontroller "github.com/argoproj/argo-cd/v3/notification_controller/controller"
	"github.com/argoproj/argo-cd/v3/notification_controller/controller/mocks"
	"github.com/argoproj/argo-cd/v3/reposerver/apiclient"
	service "github.com/argoproj/argo-cd/v3/util/notification/argocd"
	serviceMock "github.com/argoproj/argo-cd/v3/util/notification/argocd/mocks"
)

func TestRun_SignalHandling_GracefulShutdown(t *testing.T) {
	d := &notification{
		getNamespace: func() (string, bool, error) {
			return "some-ns", false, nil
		},
		getRESTConfig: func() (*rest.Config, error) {
			return &rest.Config{}, nil
		},
		serveMetrics: func(_ string, _ http.Handler) {},
		newArgoCDService: func(clientset kubernetes.Interface, namespace string, repoClientset apiclient.Clientset) (service.Service, error) {
			return &serviceMock.Service{
				CloseFunc: func() {
				},
			}, nil
		},
		newController: func(k8sClient kubernetes.Interface, client dynamic.Interface, argocdService service.Service, namespace string, applicationNamespaces []string, appLabelSelector string, registry *controller.MetricsRegistry, secretName string, configMapName string, selfServiceNotificationEnabled bool) notificationscontroller.NotificationController {
			return &mocks.NotificationController{
				InitFunc: func(_ context.Context) error {
					return nil
				},
				RunFunc: func(_ context.Context, processors int) {
				},
			}
		},
	}

	var err error
	doneCh := make(chan struct{})
	go func() {
		err = d.Run(t.Context(), &NotificationControllerConfig{
			MetricsPort: 1234,
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
