package integrations

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/obj"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/xanzy/go-gitlab"
)

type gitlabClientFacade interface {
	CreateIssue(ctx context.Context, pid int, opt *gitlab.CreateIssueOptions) (*gitlab.Issue, *gitlab.Response, error)
	EditIssue(ctx context.Context, pid int, issue int, opt *gitlab.UpdateIssueOptions) (*gitlab.Issue, *gitlab.Response, error)
	EditIssueLabel(ctx context.Context, pid int, issue int, labels []*gitlab.CreateLabelOptions) (*gitlab.Response, error)
}

type gitlabIntegrationRepository interface {
	Save(tx core.DB, model *models.GitLabIntegration) error
	Read(id uuid.UUID) (models.GitLabIntegration, error)
	FindByOrganizationId(orgID uuid.UUID) ([]models.GitLabIntegration, error)
	Delete(tx core.DB, id uuid.UUID) error
}

type gitlabRepository struct {
	*gitlab.Project
	gitlabIntegrationId string
}

func (g gitlabRepository) toRepository() core.Repository {
	return core.Repository{
		ID:    fmt.Sprintf("gitlab:%s:%d", g.gitlabIntegrationId, g.ID),
		Label: g.NameWithNamespace,
	}
}

type gitlabIntegration struct {
	gitlabIntegrationRepository gitlabIntegrationRepository
	externalUserRepository      externalUserRepository

	flawRepository      flawRepository
	flawEventRepository flawEventRepository
	frontendUrl         string
	assetRepository     assetRepository
	flawService         flawService

	gitlabClientFactory func(id uuid.UUID) (gitlabClientFacade, error)
}

var _ core.ThirdPartyIntegration = &gitlabIntegration{}

func NewGitLabIntegration(db core.DB) *gitlabIntegration {
	gitlabIntegrationRepository := repositories.NewGitLabIntegrationRepository(db)

	return &gitlabIntegration{
		gitlabIntegrationRepository: gitlabIntegrationRepository,

		flawRepository:         repositories.NewFlawRepository(db),
		flawEventRepository:    repositories.NewFlawEventRepository(db),
		externalUserRepository: repositories.NewExternalUserRepository(db),
		assetRepository:        repositories.NewAssetRepository(db),

		gitlabClientFactory: func(id uuid.UUID) (gitlabClientFacade, error) {
			integration, err := gitlabIntegrationRepository.Read(id)
			if err != nil {
				return nil, err
			}
			client, err := gitlab.NewClient(integration.AccessToken, gitlab.WithBaseURL(integration.GitLabUrl))

			if err != nil {
				return nil, err
			}

			return gitlabClient{Client: client, GitLabIntegration: integration}, nil
		},
	}
}

func (g *gitlabIntegration) IntegrationEnabled(ctx core.Context) bool {
	return len(core.GetTenant(ctx).GitLabIntegrations) > 0
}

func (g *gitlabIntegration) WantsToHandleWebhook(ctx core.Context) bool {
	return true
}

func (g *gitlabIntegration) HandleWebhook(ctx core.Context) error {
	return nil
}

func (g *gitlabIntegration) ListRepositories(ctx core.Context) ([]core.Repository, error) {
	org := core.GetTenant(ctx)
	// create a new gitlab batch client
	gitlabBatchClient, err := newGitLabBatchClient(org.GitLabIntegrations)
	if err != nil {
		slog.Error("failed to create gitlab batch client", "err", err)
		return nil, err
	}

	repos, err := gitlabBatchClient.ListRepositories(ctx.QueryParam("search"))
	if err != nil {
		slog.Error("failed to list repositories", "err", err)
		return nil, err
	}

	return utils.Map(repos, func(r gitlabRepository) core.Repository {
		return r.toRepository()
	}), nil
}

func (g *gitlabIntegration) HandleEvent(event any) error {
	return nil
}

func (g *gitlabIntegration) GetUsers(org models.Org) []core.User {
	return []core.User{}
}

func (g *gitlabIntegration) GetID() core.IntegrationID {
	return core.GitLabIntegrationID
}

func (g *gitlabIntegration) Delete(ctx core.Context) error {
	id := ctx.Param("gitlab_integration_id")

	if id == "" {
		return ctx.JSON(400, map[string]any{
			"message": "GitLab integration ID is required",
		})
	}

	// parse the id
	parsedID, err := uuid.Parse(id)
	if err != nil {
		return ctx.JSON(400, map[string]any{
			"message": "Invalid GitLab integration ID",
		})
	}

	err = g.gitlabIntegrationRepository.Delete(nil, parsedID)
	if err != nil {
		return err
	}

	return ctx.JSON(200, map[string]any{
		"message": "GitLab integration deleted",
	})
}

func (g *gitlabIntegration) TestAndSave(ctx core.Context) error {
	var data struct {
		Url   string `json:"url"`
		Token string `json:"token"`
		Name  string `json:"name"`
	}

	if err := ctx.Bind(&data); err != nil {
		return err
	}
	// check if valid url - maybe the user forgot to add the protocol
	if !strings.HasPrefix(data.Url, "http://") && !strings.HasPrefix(data.Url, "https://") {
		data.Url = "https://" + data.Url
	}

	git, err := gitlab.NewClient(data.Token, gitlab.WithBaseURL(data.Url))
	if err != nil {
		return err
	}

	_, _, err = git.Projects.ListProjects(&gitlab.ListProjectsOptions{
		MinAccessLevel: gitlab.Ptr(gitlab.ReporterPermissions),
	})
	if err != nil {
		return err
	}

	// save the integration
	integration := models.GitLabIntegration{
		GitLabUrl:   data.Url,
		AccessToken: data.Token,
		Name:        data.Name,
		OrgID:       (core.GetTenant(ctx).GetID()),
	}

	if err := g.gitlabIntegrationRepository.Save(nil, &integration); err != nil {
		return err
	}

	// return all projects
	return ctx.JSON(200, obj.GitlabIntegrationDTO{
		ID:              integration.ID.String(),
		Url:             integration.GitLabUrl,
		Name:            integration.Name,
		ObfuscatedToken: integration.AccessToken[:4] + "************" + integration.AccessToken[len(integration.AccessToken)-4:],
	})
}
