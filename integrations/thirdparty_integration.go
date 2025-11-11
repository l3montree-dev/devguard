package integrations

import (
	"bytes"
	"context"
	"io"
	"log/slog"

	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/l3montree-dev/devguard/shared"
)

// batches multiple third party integrations
type thirdPartyIntegrations struct {
	integrations           []shared.ThirdPartyIntegration
	externalUserRepository shared.ExternalUserRepository
}

var _ shared.IntegrationAggregate = &thirdPartyIntegrations{}

func (t *thirdPartyIntegrations) GetIntegration(id shared.IntegrationID) shared.ThirdPartyIntegration {
	for _, i := range t.integrations {
		if i.GetID() == id {
			return i
		}
	}
	return nil
}

func (t *thirdPartyIntegrations) GetID() shared.IntegrationID {
	return shared.AggregateID
}

func (t *thirdPartyIntegrations) ListGroups(ctx context.Context, userID string, providerID string) ([]models.Project, []shared.Role, error) {
	type projectsWithRoles struct {
		projects []models.Project
		roles    []shared.Role
	}

	wg := utils.ErrGroup[projectsWithRoles](-1)

	for _, i := range t.integrations {
		wg.Go(func() (projectsWithRoles, error) {
			groups, roles, err := i.ListGroups(ctx, userID, providerID)
			if err != nil {
				// swallow error
				return projectsWithRoles{}, nil
			}
			return projectsWithRoles{projects: groups, roles: roles}, nil
		})
	}

	results, err := wg.WaitAndCollect()
	if err != nil {
		slog.Error("error while listing groups", "err", err)
	}

	projects := make([]models.Project, 0, len(results))
	roles := make([]shared.Role, 0, len(results))
	for _, result := range results {
		projects = append(projects, result.projects...)
		roles = append(roles, result.roles...)
	}
	return projects, roles, nil
}

func (t *thirdPartyIntegrations) ListProjects(ctx context.Context, userID string, providerID string, groupID string) ([]models.Asset, []shared.Role, error) {
	type assetsWithRoles struct {
		assets []models.Asset
		roles  []shared.Role
	}
	wg := utils.ErrGroup[assetsWithRoles](-1)

	for _, i := range t.integrations {
		wg.Go(func() (assetsWithRoles, error) {
			projects, roles, err := i.ListProjects(ctx, userID, providerID, groupID)
			if err != nil {
				// swallow error
				return assetsWithRoles{}, nil
			}
			return assetsWithRoles{assets: projects, roles: roles}, nil
		})
	}
	results, err := wg.WaitAndCollect()
	if err != nil {
		slog.Error("error while listing projects", "err", err)
	}
	assets := make([]models.Asset, 0, len(results))
	roles := make([]shared.Role, 0, len(results))
	for _, result := range results {
		assets = append(assets, result.assets...)
		roles = append(roles, result.roles...)
	}
	return assets, roles, nil
}

func (t *thirdPartyIntegrations) HasAccessToExternalEntityProvider(ctx shared.Context, externalEntityProviderID string) (bool, error) {
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

func (t *thirdPartyIntegrations) ListRepositories(ctx shared.Context) ([]shared.Repository, error) {
	wg := utils.ErrGroup[[]shared.Repository](-1)
	for _, i := range t.integrations {
		wg.Go(func() ([]shared.Repository, error) {
			repos, err := i.ListRepositories(ctx)
			if err != nil {
				slog.Debug("error while listing repositories", "err", err)
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

func (t *thirdPartyIntegrations) ListOrgs(ctx shared.Context) ([]models.Org, error) {
	wg := utils.ErrGroup[[]models.Org](-1)

	for _, i := range t.integrations {
		wg.Go(func() ([]models.Org, error) {
			orgs, err := i.ListOrgs(ctx)
			if err != nil {
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

func (t *thirdPartyIntegrations) WantsToHandleWebhook(ctx shared.Context) bool {
	return utils.Any(t.integrations, func(i shared.ThirdPartyIntegration) bool {
		return i.WantsToHandleWebhook(ctx)
	})
}

func (t *thirdPartyIntegrations) HandleWebhook(ctx shared.Context) error {
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

func (t *thirdPartyIntegrations) GetUsers(org models.Org) []shared.User {

	users, err := t.externalUserRepository.FindByOrgID(nil, org.ID)
	if err != nil {
		slog.Error("could not fetch external users for org", "org", org.Slug, "err", err)
		return nil
	}

	return utils.Map(users, func(user models.ExternalUser) shared.User {
		return shared.User{
			ID:        user.ID,
			Name:      user.Username,
			AvatarURL: &user.AvatarURL,

			Role: string(shared.RoleUnknown), // all users from github are members
		}
	})
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

func (t *thirdPartyIntegrations) UpdateIssue(ctx context.Context, asset models.Asset, assetVersionSlug string, vuln models.Vuln) error {
	wg := utils.ErrGroup[struct{}](-1)
	for _, i := range t.integrations {
		wg.Go(func() (struct{}, error) {
			return struct{}{}, i.UpdateIssue(ctx, asset, assetVersionSlug, vuln)
		})
	}
	_, err := wg.WaitAndCollect()
	return err
}

func (t *thirdPartyIntegrations) CreateIssue(ctx context.Context, asset models.Asset, assetVersionSlug string, vuln models.Vuln, projectSlug string, orgSlug string, justification string, userID string) error {
	wg := utils.ErrGroup[struct{}](-1)
	for _, i := range t.integrations {
		wg.Go(func() (struct{}, error) {
			return struct{}{}, i.CreateIssue(ctx, asset, assetVersionSlug, vuln, projectSlug, orgSlug, justification, userID)
		})
	}

	_, err := wg.WaitAndCollect()
	return err
}

func (t *thirdPartyIntegrations) CreateLabels(ctx context.Context, asset models.Asset) error {
	wg := utils.ErrGroup[struct{}](-1)
	for _, i := range t.integrations {
		wg.Go(func() (struct{}, error) {
			return struct{}{}, i.CreateLabels(ctx, asset)
		})
	}
	_, err := wg.WaitAndCollect()
	return err
}

func NewThirdPartyIntegrations(externalUserRepository shared.ExternalUserRepository, integrations ...shared.ThirdPartyIntegration) *thirdPartyIntegrations {
	return &thirdPartyIntegrations{
		integrations:           integrations,
		externalUserRepository: externalUserRepository,
	}
}
