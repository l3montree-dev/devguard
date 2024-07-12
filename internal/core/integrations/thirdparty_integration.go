package integrations

import (
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/utils"
)

// batches multiple third party integrations
type thirdPartyIntegrations struct {
	integrations []core.ThirdPartyIntegration
}

var _ core.ThirdPartyIntegration = &thirdPartyIntegrations{}

func (t *thirdPartyIntegrations) IntegrationEnabled(ctx core.Context) bool {
	return utils.Any(t.integrations, func(i core.ThirdPartyIntegration) bool {
		return i.IntegrationEnabled(ctx)
	})
}

func (t *thirdPartyIntegrations) ListRepositories(ctx core.Context) ([]core.Repository, error) {
	wg := utils.ErrGroup[[]core.Repository](-1)

	for _, i := range t.integrations {
		if i.IntegrationEnabled(ctx) {
			wg.Go(func() ([]core.Repository, error) {
				return i.ListRepositories(ctx)
			})
		}
	}

	results, err := wg.WaitAndCollect()

	return utils.Flat(results), err
}

func (t *thirdPartyIntegrations) WantsToHandleWebhook(ctx core.Context) bool {
	return utils.Any(t.integrations, func(i core.ThirdPartyIntegration) bool {
		return i.WantsToHandleWebhook(ctx)
	})
}

func (t *thirdPartyIntegrations) HandleWebhook(ctx core.Context) error {
	wg := utils.ErrGroup[struct{}](-1)

	for _, i := range t.integrations {
		if i.WantsToHandleWebhook(ctx) {
			wg.Go(func() (struct{}, error) {
				return struct{}{}, i.HandleWebhook(ctx)
			})
		}
	}

	_, err := wg.WaitAndCollect()
	return err
}

func (t *thirdPartyIntegrations) WantsToFinishInstallation(ctx core.Context) bool {
	return utils.Any(t.integrations, func(i core.ThirdPartyIntegration) bool {
		return i.WantsToFinishInstallation(ctx)
	})
}

func (t *thirdPartyIntegrations) FinishInstallation(ctx core.Context) error {
	for _, i := range t.integrations {
		if i.WantsToFinishInstallation(ctx) {
			if err := i.FinishInstallation(ctx); err != nil {
				return err
			}
		}
	}

	return nil
}

func (t *thirdPartyIntegrations) HandleEvent(event any) error {
	wg := utils.ErrGroup[struct{}](-1)
	for _, i := range t.integrations {
		wg.Go(func() (struct{}, error) {
			return struct{}{}, i.HandleEvent(event)
		})
	}

	_, err := wg.WaitAndCollect()
	return err
}

func NewThirdPartyIntegrations(integrations ...core.ThirdPartyIntegration) *thirdPartyIntegrations {
	return &thirdPartyIntegrations{
		integrations: integrations,
	}
}
