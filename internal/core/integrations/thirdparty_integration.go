package integrations

import (
	"bytes"
	"io"
	"log/slog"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
)

// batches multiple third party integrations
type thirdPartyIntegrations struct {
	integrations []core.ThirdPartyIntegration
}

var _ core.IntegrationAggregate = &thirdPartyIntegrations{}

func (t *thirdPartyIntegrations) GetIntegration(id core.IntegrationID) core.ThirdPartyIntegration {
	for _, i := range t.integrations {
		if i.GetID() == id {
			return i
		}
	}
	return nil
}

func (t *thirdPartyIntegrations) GetID() core.IntegrationID {
	return core.AggregateID
}

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
				repos, err := i.ListRepositories(ctx)
				if err != nil {
					slog.Error("error while listing repositories", "err", err)
					// swallow error
					return nil, nil
				}
				return repos, err
			})
		} else {
			slog.Debug("integration not enabled", "integration", i.GetID())
		}
	}

	results, err := wg.WaitAndCollect()
	if err != nil {
		slog.Error("error while listing repositories", "err", err)
	}

	return utils.Flat(results), nil
}

func (t *thirdPartyIntegrations) WantsToHandleWebhook(ctx core.Context) bool {
	return utils.Any(t.integrations, func(i core.ThirdPartyIntegration) bool {
		return i.WantsToHandleWebhook(ctx)
	})
}

func (t *thirdPartyIntegrations) HandleWebhook(ctx core.Context) error {
	body, err := io.ReadAll(ctx.Request().Body)
	if err != nil {
		return err
	}

	// Close the original body
	defer ctx.Request().Body.Close()

	for _, i := range t.integrations {
		// Create a new ReadCloser for the body
		// otherwise we would reread the body - which is not possible
		ctx.Request().Body = io.NopCloser(bytes.NewBuffer(body))
		if i.WantsToHandleWebhook(ctx) {
			if err := i.HandleWebhook(ctx); err != nil {
				slog.Error("error while handling webhook", "err", err)
				return err
			}
		}
	}

	return nil
}

func (t *thirdPartyIntegrations) GetUsers(org models.Org) []core.User {
	users := []core.User{}
	for _, i := range t.integrations {
		users = append(users, i.GetUsers(org)...)
	}

	return users
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
