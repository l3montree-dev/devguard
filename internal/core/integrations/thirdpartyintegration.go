package integrations

import (
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/obj"
)

type thirdPartyIntegration interface {
	IntegrationEnabled(ctx core.Context) bool
	ListRepositories(ctx core.Context) ([]obj.Repository, error)

	WantsToHandleWebhook(ctx core.Context) bool
	HandleWebhook(ctx core.Context) error

	WantsToFinishInstallation(ctx core.Context) bool
	FinishInstallation(ctx core.Context) error
}
