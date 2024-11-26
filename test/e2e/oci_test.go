package e2e

import (
	"testing"

	"github.com/argoproj/gitops-engine/pkg/health"
	. "github.com/argoproj/gitops-engine/pkg/sync/common"

	. "github.com/argoproj/argo-cd/v2/pkg/apis/application/v1alpha1"
	"github.com/argoproj/argo-cd/v2/test/e2e/fixture"
	. "github.com/argoproj/argo-cd/v2/test/e2e/fixture/app"
)

func TestOCIImage(t *testing.T) {
	Given(t).
		RepoURLType(fixture.RepoURLTypeOCI).
		PushImageToOCIRegistry("guestbook", "1.0.0").
		OCIRepoAdded("guestbook", "guestbook").
		Revision("1.0.0").
		OCIRegistryPath("guestbook").
		Path(".").
		When().
		CreateApp().
		Then().
		Expect(SyncStatusIs(SyncStatusCodeOutOfSync)).
		Expect(Success("")).
		When().
		Sync().
		Then().
		Expect(Success("")).
		Expect(OperationPhaseIs(OperationSucceeded)).
		Expect(SyncStatusIs(SyncStatusCodeSynced)).
		Expect(HealthIs(health.HealthStatusHealthy))
}

func TestOCIWithOCIHelmRegistryDependencies(t *testing.T) {
	Given(t).
		RepoURLType(fixture.RepoURLTypeOCI).
		PushChartToOCIRegistry("helm-values", "helm-values", "1.0.0").
		PushImageToOCIRegistry("helm-oci-with-dependencies", "1.0.0").
		OCIRepoAdded("helm-oci-with-dependencies", "helm-oci-with-dependencies").
		OCIRegistryPath("helm-oci-with-dependencies").
		Revision("1.0.0").
		Path(".").
		When().
		CreateApp().
		Then().
		When().
		Sync().
		Then().
		Expect(OperationPhaseIs(OperationSucceeded)).
		Expect(HealthIs(health.HealthStatusHealthy)).
		Expect(SyncStatusIs(SyncStatusCodeSynced))
}
