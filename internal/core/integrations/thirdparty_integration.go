package integrations

import (
	"bytes"
	"context"
	"fmt"
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

func (t *thirdPartyIntegrations) ListGroups(ctx core.Context, userID string, providerID string) ([]models.Project, error) {
	wg := utils.ErrGroup[[]models.Project](-1)

	for _, i := range t.integrations {
		wg.Go(func() ([]models.Project, error) {
			groups, err := i.ListGroups(ctx, userID, providerID)
			if err != nil {
				slog.Error("error while listing groups", "err", err)
				// swallow error
				return nil, nil
			}
			return groups, err
		})
	}

	results, err := wg.WaitAndCollect()
	if err != nil {
		slog.Error("error while listing groups", "err", err)
	}

	return utils.Flat(results), nil
}

func (t *thirdPartyIntegrations) ListProjects(ctx core.Context, userID string, providerID string, groupID string) ([]models.Asset, error) {
	wg := utils.ErrGroup[[]models.Asset](-1)
	for _, i := range t.integrations {
		wg.Go(func() ([]models.Asset, error) {
			projects, err := i.ListProjects(ctx, userID, providerID, groupID)
			if err != nil {
				slog.Error("error while listing projects", "err", err)
				// swallow error
				return nil, nil
			}
			return projects, err
		})
	}
	results, err := wg.WaitAndCollect()
	if err != nil {
		slog.Error("error while listing projects", "err", err)
	}
	return utils.Flat(results), nil
}

func (t *thirdPartyIntegrations) HasAccessToExternalEntityProvider(ctx core.Context, externalEntityProviderID string) (bool, error) {
	for _, i := range t.integrations {
		access, unauth := i.HasAccessToExternalEntityProvider(ctx, externalEntityProviderID)
		if unauth != nil {
			// we COULD actually use this provider
			return access, unauth
		}
		if access {
			// we have access to this provider
			return true, nil
		}
	}
	return false, nil
}

func (t *thirdPartyIntegrations) GetRoleInGroup(ctx context.Context, userID string, providerID string, groupID string) (string, error) {
	for _, i := range t.integrations {
		role, err := i.GetRoleInGroup(ctx, userID, providerID, groupID)
		if err != nil {
			slog.Error("error while getting role in org", "err", err, "providerID", providerID, "orgID", groupID)
			// swallow error
			continue
		}
		if role != "" {
			return role, nil
		}
	}
	return "", fmt.Errorf("no role found for user %s in org %s with providerID %s", userID, groupID, providerID)
}

func (t *thirdPartyIntegrations) GetRoleInProject(ctx context.Context, userID string, providerID string, projectID string) (string, error) {
	for _, i := range t.integrations {
		role, err := i.GetRoleInProject(ctx, userID, providerID, projectID)
		if err != nil {
			slog.Error("error while getting role in project", "err", err, "providerID", providerID, "projectID", projectID)
			// swallow error
			continue
		}
		if role != "" {
			return role, nil
		}
	}
	return "", fmt.Errorf("no role found for user %s in project %s with providerID %s", userID, projectID, providerID)
}

func (t *thirdPartyIntegrations) ListRepositories(ctx core.Context) ([]core.Repository, error) {
	wg := utils.ErrGroup[[]core.Repository](-1)
	for _, i := range t.integrations {
		wg.Go(func() ([]core.Repository, error) {
			repos, err := i.ListRepositories(ctx)
			if err != nil {
				slog.Error("error while listing repositories", "err", err)
				// swallow error
				return nil, nil
			}
			return repos, err
		})

	}

	results, err := wg.WaitAndCollect()
	if err != nil {
		slog.Error("error while listing repositories", "err", err)
	}

	return utils.Flat(results), nil
}

func (t *thirdPartyIntegrations) ListOrgs(ctx core.Context) ([]models.Org, error) {
	wg := utils.ErrGroup[[]models.Org](-1)

	for _, i := range t.integrations {
		wg.Go(func() ([]models.Org, error) {
			orgs, err := i.ListOrgs(ctx)
			if err != nil {
				slog.Error("error while listing orgs", "err", err)
				// swallow error
				return nil, nil
			}
			return orgs, err
		})
	}

	results, err := wg.WaitAndCollect()
	if err != nil {
		slog.Error("error while listing orgs", "err", err)
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

func (t *thirdPartyIntegrations) UpdateIssue(ctx context.Context, asset models.Asset, vuln models.Vuln) error {
	wg := utils.ErrGroup[struct{}](-1)
	for _, i := range t.integrations {
		wg.Go(func() (struct{}, error) {
			return struct{}{}, i.UpdateIssue(ctx, asset, vuln)
		})
	}
	_, err := wg.WaitAndCollect()
	return err
}

func (t *thirdPartyIntegrations) CreateIssue(ctx context.Context, asset models.Asset, assetVersionName string, vuln models.Vuln, projectSlug string, orgSlug string, justification string, userID string) error {
	wg := utils.ErrGroup[struct{}](-1)
	for _, i := range t.integrations {
		wg.Go(func() (struct{}, error) {
			return struct{}{}, i.CreateIssue(ctx, asset, assetVersionName, vuln, projectSlug, orgSlug, justification, userID)
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
