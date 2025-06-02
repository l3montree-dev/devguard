package gitlabint

import (
	"context"
	"encoding/json"
	"os"

	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	gitlab "gitlab.com/gitlab-org/api/client-go"

	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"slices"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/accesscontrol"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/asset"
	"github.com/l3montree-dev/devguard/internal/core/integrations/commonint"
	"github.com/l3montree-dev/devguard/internal/core/org"
	"github.com/l3montree-dev/devguard/internal/core/project"
	"github.com/l3montree-dev/devguard/internal/core/risk"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/utils"
)

type gitlabRepository struct {
	*gitlab.Project
	gitlabIntegrationId string
}

func (g gitlabRepository) toRepository() core.Repository {
	// check for group and project access
	if g.Permissions == nil || (g.Permissions.GroupAccess == nil && g.Permissions.ProjectAccess == nil) {
		return core.Repository{
			ID:           fmt.Sprintf("gitlab:%s:%d", g.gitlabIntegrationId, g.ID),
			Label:        g.NameWithNamespace,
			IsDeveloper:  false,
			IsOwner:      false,
			IsMaintainer: false,
			Description:  g.Description,
			Image:        g.AvatarURL,
		}
	}

	// check for project access
	if g.Permissions.ProjectAccess == nil {
		// group access has to be defined
		return core.Repository{
			ID:           fmt.Sprintf("gitlab:%s:%d", g.gitlabIntegrationId, g.ID),
			Label:        g.NameWithNamespace,
			IsDeveloper:  g.Permissions.GroupAccess.AccessLevel >= gitlab.DeveloperPermissions,
			IsOwner:      g.Permissions.GroupAccess.AccessLevel >= gitlab.OwnerPermissions,
			IsMaintainer: g.Permissions.GroupAccess.AccessLevel >= gitlab.MaintainerPermissions,
			Description:  g.Description,
			Image:        g.AvatarURL,
		}
	}

	if g.Permissions.GroupAccess == nil {

		return core.Repository{
			ID:          fmt.Sprintf("gitlab:%s:%d", g.gitlabIntegrationId, g.ID),
			Label:       g.NameWithNamespace,
			Description: g.Description,
			Image:       g.AvatarURL,

			// check for project access
			IsDeveloper:  g.Permissions.ProjectAccess.AccessLevel >= gitlab.DeveloperPermissions,
			IsOwner:      g.Permissions.ProjectAccess.AccessLevel >= gitlab.OwnerPermissions,
			IsMaintainer: g.Permissions.ProjectAccess.AccessLevel >= gitlab.MaintainerPermissions,
		}
	}

	// both is defined - check for the highest access level
	return core.Repository{
		ID:           fmt.Sprintf("gitlab:%s:%d", g.gitlabIntegrationId, g.ID),
		Label:        g.NameWithNamespace,
		IsDeveloper:  g.Permissions.GroupAccess.AccessLevel >= gitlab.DeveloperPermissions || g.Permissions.ProjectAccess.AccessLevel >= gitlab.DeveloperPermissions,
		IsOwner:      g.Permissions.GroupAccess.AccessLevel >= gitlab.OwnerPermissions || g.Permissions.ProjectAccess.AccessLevel >= gitlab.OwnerPermissions,
		IsMaintainer: g.Permissions.GroupAccess.AccessLevel >= gitlab.MaintainerPermissions || g.Permissions.ProjectAccess.AccessLevel >= gitlab.MaintainerPermissions,
		Description:  g.Description,
		Image:        g.AvatarURL,
	}
}

type GitlabIntegration struct {
	oauth2Endpoints             map[string]*GitlabOauth2Config
	gitlabOauth2TokenRepository core.GitLabOauth2TokenRepository

	gitlabIntegrationRepository core.GitlabIntegrationRepository
	externalUserRepository      core.ExternalUserRepository
	firstPartyVulnRepository    core.FirstPartyVulnRepository
	aggregatedVulnRepository    core.VulnRepository
	dependencyVulnRepository    core.DependencyVulnRepository
	vulnEventRepository         core.VulnEventRepository
	frontendUrl                 string
	orgRepository               core.OrganizationRepository
	orgSevice                   core.OrgService
	projectRepository           core.ProjectRepository
	projectService              core.ProjectService
	assetRepository             core.AssetRepository
	assetVersionRepository      core.AssetVersionRepository
	assetService                core.AssetService
	componentRepository         core.ComponentRepository
	gitlabClientFactory         func(id uuid.UUID) (gitlabClientFacade, error)
	gitlabOauth2ClientFactory   func(token models.GitLabOauth2Token, enableClientCache bool) (gitlabClientFacade, error)
	casbinRBACProvider          core.RBACProvider
}

var _ core.ThirdPartyIntegration = &GitlabIntegration{}

func messageWasCreatedByDevguard(message string) bool {
	return strings.Contains(message, "<devguard>")
}

func NewGitLabIntegration(oauth2GitlabIntegration map[string]*GitlabOauth2Config, db core.DB) *GitlabIntegration {

	casbinRBACProvider, err := accesscontrol.NewCasbinRBACProvider(db)
	if err != nil {
		panic(err)
	}

	gitlabIntegrationRepository := repositories.NewGitLabIntegrationRepository(db)

	aggregatedVulnRepository := repositories.NewAggregatedVulnRepository(db)
	dependencyVulnRepository := repositories.NewDependencyVulnRepository(db)
	vulnEventRepository := repositories.NewVulnEventRepository(db)
	externalUserRepository := repositories.NewExternalUserRepository(db)
	assetRepository := repositories.NewAssetRepository(db)
	assetVersionRepository := repositories.NewAssetVersionRepository(db)
	projectRepository := repositories.NewProjectRepository(db)
	componentRepository := repositories.NewComponentRepository(db)
	firstPartyVulnRepository := repositories.NewFirstPartyVulnerabilityRepository(db)
	gitlabOauth2TokenRepository := repositories.NewGitlabOauth2TokenRepository(db)

	orgRepository := repositories.NewOrgRepository(db)

	orgService := org.NewService(orgRepository, casbinRBACProvider)
	projectService := project.NewService(projectRepository, assetRepository)
	assetService := asset.NewService(assetRepository, dependencyVulnRepository, nil)

	frontendUrl := os.Getenv("FRONTEND_URL")
	if frontendUrl == "" {
		panic("FRONTEND_URL is not set")
	}

	return &GitlabIntegration{
		oauth2Endpoints:             oauth2GitlabIntegration,
		gitlabOauth2TokenRepository: gitlabOauth2TokenRepository,
		frontendUrl:                 frontendUrl,
		aggregatedVulnRepository:    aggregatedVulnRepository,
		gitlabIntegrationRepository: gitlabIntegrationRepository,
		dependencyVulnRepository:    dependencyVulnRepository,
		vulnEventRepository:         vulnEventRepository,
		assetRepository:             assetRepository,
		assetVersionRepository:      assetVersionRepository,
		externalUserRepository:      externalUserRepository,
		firstPartyVulnRepository:    firstPartyVulnRepository,
		projectRepository:           projectRepository,
		componentRepository:         componentRepository,
		orgRepository:               orgRepository,
		orgSevice:                   orgService,
		projectService:              projectService,
		assetService:                assetService,
		casbinRBACProvider:          casbinRBACProvider,

		gitlabClientFactory: func(id uuid.UUID) (gitlabClientFacade, error) {
			integration, err := gitlabIntegrationRepository.Read(id)
			if err != nil {
				return nil, err
			}
			client, err := gitlab.NewClient(integration.AccessToken, gitlab.WithBaseURL(integration.GitLabUrl))

			if err != nil {
				return nil, err
			}

			return gitlabClient{Client: client, clientID: integration.ID.String()}, nil
		},

		gitlabOauth2ClientFactory: func(token models.GitLabOauth2Token, enableClientCache bool) (gitlabClientFacade, error) {
			// get the correct gitlab oauth2 integration configuration
			for _, integration := range oauth2GitlabIntegration {
				if integration.ProviderID == token.ProviderID {
					return buildOauth2GitlabClient(token, integration, enableClientCache)
				}
			}
			return nil, errors.New("could not find gitlab oauth2 integration")
		},
	}
}

func (g *GitlabIntegration) WantsToHandleWebhook(ctx core.Context) bool {
	event := ctx.Request().Header.Get("X-Gitlab-Event")
	return strings.TrimSpace(event) != ""
}

func isEventSubscribed(event gitlab.EventType) bool {
	return slices.Contains([]gitlab.EventType{
		gitlab.EventTypeNote,
		gitlab.EventTypeIssue,
	}, event)
}

func parseWebhook(r *http.Request) (any, error) {
	defer func() {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			log.Printf("could discard request body: %v", err)
		}
		if err := r.Body.Close(); err != nil {
			log.Printf("could not close request body: %v", err)
		}
	}()

	if r.Method != http.MethodPost {
		return nil, errors.New("invalid HTTP Method")
	}

	event := r.Header.Get("X-Gitlab-Event")
	if strings.TrimSpace(event) == "" {
		return nil, errors.New("missing X-Gitlab-Event Header")
	}

	eventType := gitlab.EventType(event)
	if !isEventSubscribed(eventType) {
		return nil, errors.New("event not defined to be parsed")
	}

	payload, err := io.ReadAll(r.Body)
	if err != nil || len(payload) == 0 {
		return nil, errors.New("error reading request body")
	}

	return gitlab.ParseWebhook(eventType, payload)
}

func oauth2TokenToOrg(token models.GitLabOauth2Token) models.Org {
	return models.Org{
		Name:                     token.ProviderID,
		Slug:                     fmt.Sprintf("@%s", token.ProviderID),
		ExternalEntityProviderID: &token.ProviderID,
	}
}

func (g *GitlabIntegration) HasAccessToExternalEntityProvider(ctx core.Context, externalEntityProviderID string) bool {
	// get the oauth2 tokens for this user
	token, err := g.gitlabOauth2TokenRepository.FindByUserIdAndProviderId(core.GetSession(ctx).GetUserID(), externalEntityProviderID)
	if err != nil {
		slog.Error("failed to find gitlab oauth2 tokens", "err", err)
		return false
	}

	// check that the token is valid
	if !g.checkIfTokenIsValid(ctx, *token) {
		slog.Error("gitlab oauth2 token is not valid", "providerId", externalEntityProviderID)
		return false
	}

	return err == nil
}

func (g *GitlabIntegration) checkIfTokenIsValid(ctx core.Context, token models.GitLabOauth2Token) bool {
	// create a new gitlab batch client
	gitlabClient, err := g.gitlabOauth2ClientFactory(token, false)
	if err != nil {
		slog.Error("failed to create gitlab batch client", "err", err)
		return false
	}

	// check if the token is valid by fetching the user
	_, _, err = gitlabClient.ListGroups(ctx.Request().Context(), &gitlab.ListGroupsOptions{
		MinAccessLevel: utils.Ptr(gitlab.ReporterPermissions), // only list groups where the user has at least owner permissions
	})
	if err != nil {
		slog.Error("failed to get user", "err", err)
		return false
	}

	return true
}

func (g *GitlabIntegration) getAndSaveOauth2TokenFromAuthServer(ctx core.Context) ([]models.GitLabOauth2Token, error) {
	// check if the user has a gitlab login
	// we can even improve the response by checking if the user has a gitlab login
	// todo this, fetch the kratos user and check if the user has a gitlab login
	adminClient := core.GetAuthAdminClient(ctx)

	identity, err := adminClient.GetIdentityWithCredentials(ctx.Request().Context(), core.GetSession(ctx).GetUserID())
	if err != nil {
		slog.Error("failed to get identity", "err", err)
		return nil, err
	}

	t, err := getGitlabAccessTokenFromOryIdentity(g.oauth2Endpoints, identity)
	if err != nil {
		slog.Error("failed to get gitlab access token from ory identity", "err", err)
		return nil, err
	}

	// check if token is valid
	tokenSlice := make([]models.GitLabOauth2Token, 0, len(t))
	for providerId, token := range t {
		tokenSlice = append(tokenSlice, models.GitLabOauth2Token{
			AccessToken:  token.AccessToken,
			RefreshToken: token.RefreshToken,
			BaseURL:      token.BaseURL,
			GitLabUserID: token.GitLabUserID,
			UserID:       core.GetSession(ctx).GetUserID(),
			ProviderID:   providerId,
			Expiry:       token.Expiry,
		})
	}

	// save the tokens to the database
	if len(tokenSlice) != 0 {
		err = g.gitlabOauth2TokenRepository.Save(nil, utils.SlicePtr(tokenSlice)...)
		if err != nil {
			// if an error happens, just swallow it
			return tokenSlice, nil
		}
	}

	return tokenSlice, nil
}

func (g *GitlabIntegration) ListOrgs(ctx core.Context) ([]models.Org, error) {
	// get the oauth2 tokens for this user
	tokens, err := g.getAndSaveOauth2TokenFromAuthServer(ctx)
	if err != nil {
		slog.Error("failed to find gitlab oauth2 tokens", "err", err)
		return nil, err
	}

	if len(tokens) == 0 {
		slog.Debug("no gitlab oauth2 tokens found for user")
		return nil, nil
	}

	return utils.Map(tokens, oauth2TokenToOrg), nil
}

func (g *GitlabIntegration) ListGroups(ctx core.Context, userID string, providerID string) ([]models.Project, error) {
	// get the oauth2 tokens for this user
	token, err := g.gitlabOauth2TokenRepository.FindByUserIdAndProviderId(userID, providerID)
	if err != nil {
		slog.Error("failed to find gitlab oauth2 tokens", "err", err)
		return nil, err
	}
	// create a new gitlab batch client
	gitlabClient, err := g.gitlabOauth2ClientFactory(*token, true)
	if err != nil {
		slog.Error("failed to create gitlab batch client", "err", err)
		return nil, err
	}
	// get the groups for this user
	groups, _, err := gitlabClient.ListGroups(ctx.Request().Context(), &gitlab.ListGroupsOptions{
		MinAccessLevel: utils.Ptr(gitlab.ReporterPermissions), // only list groups where the user has at least owner permissions
	})

	if err != nil {
		slog.Error("failed to list groups", "err", err)
		return nil, err
	}

	return utils.Map(groups, func(el *gitlab.Group) models.Project {
		return groupToProject(el, providerID)
	}), nil
}

func (g *GitlabIntegration) ListProjects(ctx core.Context, userID string, providerID string, groupID string) ([]models.Asset, error) {
	// get the oauth2 tokens for this user
	token, err := g.gitlabOauth2TokenRepository.FindByUserIdAndProviderId(userID, providerID)
	if err != nil {
		slog.Error("failed to find gitlab oauth2 tokens", "err", err)
		return nil, err
	}
	// create a new gitlab batch client
	gitlabClient, err := g.gitlabOauth2ClientFactory(*token, true)
	if err != nil {
		slog.Error("failed to create gitlab batch client", "err", err)
		return nil, err
	}
	// convert the groupID to an int
	groupIDInt, err := strconv.Atoi(groupID)
	if err != nil {
		slog.Error("failed to convert groupID to int", "err", err)
		return nil, errors.Wrap(err, "failed to convert groupID to int")
	}
	// get the projects in the group
	projects, _, err := gitlabClient.ListProjectsInGroup(ctx.Request().Context(), groupIDInt, nil)
	if err != nil {
		slog.Error("failed to list projects in group", "err", err)
		return nil, err
	}

	// convert the projects to assets
	result := make([]models.Asset, 0, len(projects))
	for _, project := range projects {
		result = append(result, projectToAsset(project, providerID))
	}

	return result, nil
}

func gitlabAccessLevelToRole(accessLevel gitlab.AccessLevelValue) string {
	switch accessLevel {
	case gitlab.OwnerPermissions:
		return "owner"
	case gitlab.MaintainerPermissions:
		return "admin"
	default:
		return "member"
	}
}

func (g *GitlabIntegration) GetGroup(ctx context.Context, userID string, providerID string, groupID string) (models.Project, error) {
	// get the oauth2 tokens for this user
	token, err := g.gitlabOauth2TokenRepository.FindByUserIdAndProviderId(userID, providerID)
	if err != nil {
		slog.Error("failed to find gitlab oauth2 tokens", "err", err)
		return models.Project{}, err
	}

	// create a new gitlab batch client
	gitlabClient, err := g.gitlabOauth2ClientFactory(*token, true)
	if err != nil {
		slog.Error("failed to create gitlab batch client", "err", err)
		return models.Project{}, err
	}

	// convert the groupID to an int
	groupIDInt, err := strconv.Atoi(groupID)
	if err != nil {
		slog.Error("failed to convert groupID to int", "err", err)
		return models.Project{}, errors.Wrap(err, "failed to convert groupID to int")
	}

	group, _, err := gitlabClient.GetGroup(ctx, groupIDInt)
	if err != nil {
		slog.Error("failed to get organization", "err", err)
		return models.Project{}, err
	}
	return groupToProject(group, providerID), nil
}

func (g *GitlabIntegration) GetRoleInGroup(ctx context.Context, userID string, providerID string, groupID string) (string, error) {
	// get the oauth2 tokens for this user
	token, err := g.gitlabOauth2TokenRepository.FindByUserIdAndProviderId(userID, providerID)
	if err != nil {
		slog.Error("failed to find gitlab oauth2 tokens", "err", err)
		return "", err
	}
	// create a new gitlab batch client
	gitlabClient, err := g.gitlabOauth2ClientFactory(*token, true)

	if err != nil {
		slog.Error("failed to create gitlab batch client", "err", err)
		return "", err
	}
	// convert the groupID to an int
	groupIDInt, err := strconv.Atoi(groupID)
	if err != nil {
		slog.Error("failed to convert groupID to int", "err", err)
		return "", errors.Wrap(err, "failed to convert groupID to int")
	}
	// get the group members
	member, _, err := gitlabClient.GetMemberInGroup(ctx, token.GitLabUserID, groupIDInt)
	if err != nil {
		slog.Error("failed to get member in group", "err", err)
		if strings.Contains(err.Error(), "404 Not Found") {
			// user is not a member of the group
			return "", nil
		}
		return "", err
	}

	// return the role of the user in the group
	return gitlabAccessLevelToRole(member.AccessLevel), nil
}

func (g *GitlabIntegration) GetRoleInProject(ctx context.Context, userID string, providerID string, projectID string) (string, error) {
	// get the oauth2 tokens for this user
	token, err := g.gitlabOauth2TokenRepository.FindByUserIdAndProviderId(userID, providerID)
	if err != nil {
		slog.Error("failed to find gitlab oauth2 tokens", "err", err)
		return "", err
	}

	// create a new gitlab batch client
	gitlabClient, err := g.gitlabOauth2ClientFactory(*token, true)
	if err != nil {
		slog.Error("failed to create gitlab batch client", "err", err)
		return "", err
	}

	// convert the projectID to an int
	projectIDInt, err := strconv.Atoi(projectID)
	if err != nil {
		slog.Error("failed to convert projectID to int", "err", err)
		return "", errors.Wrap(err, "failed to convert projectID to int")
	}

	member, _, err := gitlabClient.GetMemberInProject(ctx, token.GitLabUserID, projectIDInt)
	if err != nil {
		slog.Error("failed to get member in project", "err", err)
		if strings.Contains(err.Error(), "404 Not Found") {
			// user is not a member of the project
			return "", nil
		}
		return "", err
	}

	return gitlabAccessLevelToRole(member.AccessLevel), nil
}

func (g *GitlabIntegration) ListRepositories(ctx core.Context) ([]core.Repository, error) {
	var organizationGitlabIntegrations []models.GitLabIntegration
	if core.HasOrganization(ctx) {
		org := core.GetOrg(ctx)
		organizationGitlabIntegrations = org.GitLabIntegrations
	}

	// create a new gitlab batch client
	gitlabBatchClient, err := newGitLabBatchClient(organizationGitlabIntegrations, g.oauth2Endpoints, nil)
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

// Check if the user who comments on a ticket is authorized to use commands like /accept, more checks can be added later
func isGitlabUserAuthorized(event *gitlab.IssueCommentEvent, client gitlabClientFacade) (bool, error) {
	if event == nil || event.User == nil {
		slog.Error("missing event data, could not resolve if user is authorized")
		return false, fmt.Errorf("missing event data, could not resolve if user is authorized")
	}
	return client.IsProjectMember(context.TODO(), event.ProjectID, event.User.ID, nil)
}

func extractIntegrationIdFromRepoId(repoId string) (uuid.UUID, error) {
	// the repo id is formatted like this:
	// gitlab:<integration id>:<project id>
	return uuid.Parse(strings.Split(repoId, ":")[1])
}

func extractProjectIdFromRepoId(repoId string) (int, error) {
	// the repo id is formatted like this:
	// gitlab:<integration id>:<project id>
	return strconv.Atoi(strings.Split(repoId, ":")[2])
}

func (g *GitlabIntegration) gitlabExternalProviderEntity(externalProvider *string) bool {
	if externalProvider == nil {
		return false
	}

	_, ok := g.oauth2Endpoints[*externalProvider]
	return ok
}

func (g *GitlabIntegration) AutoSetup(ctx core.Context) error {
	asset := core.GetAsset(ctx)
	repoId := utils.SafeDereference(asset.RepositoryID)

	var req struct {
		DevguardPrivateKey string `json:"devguardPrivateKey"`
		DevguardAssetName  string `json:"devguardAssetName"`
	}
	err := ctx.Bind(&req)
	if err != nil {
		return errors.Wrap(err, "could not bind request")
	}

	var client gitlabClientFacade
	var projectIdInt int
	enc := json.NewEncoder(ctx.Response())
	var gitlabUrl string
	var accessToken string

	switch {
	case g.gitlabExternalProviderEntity(asset.ExternalEntityProviderID):
		providerId := ctx.QueryParam("providerId")
		if providerId == "" {
			return errors.New("providerId query parameter is required")
		}

		defer func() {
			// delete the token from the database - it is no longer needed after this function finishes
			err = g.gitlabOauth2TokenRepository.DeleteByUserIdAndProviderId(core.GetSession(ctx).GetUserID(), *asset.ExternalEntityProviderID+"autosetup")
			if err != nil {
				slog.Error("could not delete gitlab oauth2 token", "err", err)
			}
		}()

		projectIdInt, err = strconv.Atoi(*asset.ExternalEntityID)
		if err != nil {
			return errors.Wrap(err, "could not convert project id to int")
		}

		// check if the user has a gitlab oauth2 token
		token, err := g.gitlabOauth2TokenRepository.FindByUserIdAndProviderId(core.GetSession(ctx).GetUserID(), providerId)
		if err != nil {
			return errors.Wrap(err, "could not find gitlab oauth2 tokens")
		}

		client, err = g.gitlabOauth2ClientFactory(*token, false)
		if err != nil {
			return errors.Wrap(err, "could not create new gitlab client")
		}
		accessToken = token.AccessToken
		gitlabUrl = token.BaseURL
	case strings.HasPrefix(repoId, "gitlab:"):
		integrationUUID, err := extractIntegrationIdFromRepoId(repoId)
		if err != nil {
			return errors.Wrap(err, "could not extract integration id from repo id")
		}

		client, err = g.gitlabClientFactory(integrationUUID)
		if err != nil {
			return errors.Wrap(err, "could not create new gitlab client")
		}

		integration, err := g.gitlabIntegrationRepository.Read(integrationUUID)
		if err != nil {
			return errors.Wrap(err, "could not read gitlab integration")
		}
		gitlabUrl = integration.GitLabUrl
		accessToken = integration.AccessToken

		ctx.Response().Header().Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		ctx.Response().WriteHeader(http.StatusOK) //nolint:errcheck

		projectIdInt, err = extractProjectIdFromRepoId(repoId)
		if err != nil {
			return errors.Wrap(err, "could not extract project id from repo id")
		}
	}

	err = g.addProjectHook(ctx.Request().Context(), client, asset, projectIdInt)
	if err != nil {
		return errors.Wrap(err, "could not add project hook")
	}

	// notify the user that the project hook was added
	enc.Encode(map[string]string{"step": "projectHook", "status": "success"}) //nolint:errcheck
	ctx.Response().Flush()

	err = g.addProjectVariables(ctx.Request().Context(), client, asset, projectIdInt, req.DevguardPrivateKey, req.DevguardAssetName)
	if err != nil {
		return errors.Wrap(err, "could not add project variables")
	}

	// notify the user that the project variables were added
	enc.Encode(map[string]string{"step": "projectVariables", "status": "success"}) //nolint:errcheck
	ctx.Response().Flush()

	project, _, err := client.GetProject(ctx.Request().Context(), projectIdInt)
	if err != nil {
		return errors.Wrap(err, "could not get project")
	}
	defaultBranch := project.DefaultBranch

	//generate a random branch name
	branchName := fmt.Sprintf("devguard-autosetup-%s", strconv.Itoa(commonint.GenerateFourDigitNumber()))
	if err != nil {
		return errors.Wrap(err, "could not get project name")
	}

	templatePath := getTemplatePath(ctx.QueryParam("scanner"))

	err = commonint.SetupAndPushPipeline(accessToken, gitlabUrl, project.PathWithNamespace, templatePath, branchName)
	if err != nil {
		return errors.Wrap(err, "could not setup and push pipeline")
	}

	// notify the user that the pipeline was created
	enc.Encode(map[string]string{"step": "pipeline", "status": "success"}) //nolint:errcheck
	ctx.Response().Flush()

	//create a merge request
	mr, _, err := client.CreateMergeRequest(ctx.Request().Context(), project.PathWithNamespace, &gitlab.CreateMergeRequestOptions{
		SourceBranch:       gitlab.Ptr(branchName),
		TargetBranch:       gitlab.Ptr(defaultBranch),
		Title:              gitlab.Ptr("Add devguard pipeline template"),
		RemoveSourceBranch: gitlab.Ptr(true),
	})

	if err != nil {
		return errors.Wrap(err, "could not create merge request")
	}

	// notify the user that the merge request was created
	enc.Encode(map[string]string{"step": "mergeRequest", "url": mr.WebURL, "status": "success"}) //nolint:errcheck
	ctx.Response().Flush()

	if g.gitlabExternalProviderEntity(asset.ExternalEntityProviderID) {
		// invite the devguard user to the project
		conf := g.oauth2Endpoints[*asset.ExternalEntityProviderID]
		_, _, err := client.InviteReporter(ctx.Request().Context(), projectIdInt, conf.DevGuardBotUserID)
		if err != nil {
			return errors.Wrap(err, "could not invite devguard bot to project")
		}

		// notify the user that the devguard bot was invited to the project
		enc.Encode(map[string]string{"step": "inviteDevguardBot", "status": "success"}) //nolint:errcheck
		ctx.Response().Flush()
	}

	return nil
}

func (g *GitlabIntegration) addProjectHook(ctx context.Context, client gitlabClientFacade, asset models.Asset, gitlabProjectID int) error {
	// check if the project hook already exists
	hooks, _, err := client.ListProjectHooks(ctx, gitlabProjectID, nil)
	if err != nil {
		return fmt.Errorf("could not list project hooks: %w", err)
	}

	webhookSecret := asset.WebhookSecret
	if webhookSecret == nil {
		token, err := createToken()
		if err != nil {
			return fmt.Errorf("could not create new token: %w", err)
		}

		asset.WebhookSecret = &token
		err = g.assetRepository.Update(nil, &asset)
		if err != nil {
			return fmt.Errorf("could not update asset: %w", err)
		}

		webhookSecret = &token
	}

	projectOptions, err := createProjectHookOptions(webhookSecret, hooks)
	if err != nil { //Swallow error: If an error gets returned it means the hook already exists which means we don't have to do anything further and can return without errors
		return nil
	}

	_, _, err = client.AddProjectHook(ctx, gitlabProjectID, projectOptions)
	if err != nil {
		return fmt.Errorf("could not add project hook: %w", err)
	}

	return nil
}

func createProjectHookOptions(token *uuid.UUID, hooks []*gitlab.ProjectHook) (*gitlab.AddProjectHookOptions, error) {
	projectOptions := &gitlab.AddProjectHookOptions{}

	instanceDomain := os.Getenv("INSTANCE_DOMAIN")

	for _, hook := range hooks {
		if strings.HasPrefix(hook.URL, instanceDomain) {
			return projectOptions, fmt.Errorf("hook already exists")
		}
	}

	projectOptions.IssuesEvents = gitlab.Ptr(true)
	projectOptions.ConfidentialIssuesEvents = gitlab.Ptr(true)
	projectOptions.NoteEvents = gitlab.Ptr(true)
	projectOptions.ConfidentialNoteEvents = gitlab.Ptr(true)
	projectOptions.EnableSSLVerification = gitlab.Ptr(true)
	if instanceDomain == "" { //If no URL is provided in the environment variables default to main URL
		slog.Debug("no URL specified in .env file defaulting to main")
		defaultURL := "https://api.main.devguard.org/api/v1/webhook/"
		projectOptions.URL = &defaultURL
	} else {
		instanceDomain = strings.TrimSuffix(instanceDomain, "/") //Remove trailing slash if it exists
		constructedURL := instanceDomain + "/api/v1/webhook/"
		projectOptions.URL = &constructedURL
	}
	if token != nil {
		projectOptions.Token = gitlab.Ptr(token.String())
	}

	return projectOptions, nil
}

func createToken() (uuid.UUID, error) {
	// create a new token
	token, err := uuid.NewUUID()
	if err != nil {
		slog.Error("could not create new token", "err", err)
		return uuid.Nil, fmt.Errorf("could not create new token: %w", err)
	}
	return token, nil
}

func (g *GitlabIntegration) addProjectVariables(ctx context.Context, client gitlabClientFacade, asset models.Asset, gitlabProjectID int, devguardPrivateKey string, devguardAssetName string) error {
	toCreate := []string{"DEVGUARD_TOKEN", "DEVGUARD_ASSET_NAME"}

	// check if the project variable already exists
	variables, _, err := client.ListVariables(ctx, gitlabProjectID, nil)
	if err != nil {
		return fmt.Errorf("could not list project variables: %w", err)
	}

	for _, variable := range variables {
		if slices.Contains(toCreate, variable.Key) {
			// the variable already exists
			// remove it - we cannot update, since some are protected
			_, err = client.RemoveVariable(ctx, gitlabProjectID, variable.Key)
			if err != nil {
				return errors.Wrap(err, "could not remove project variable")
			}
		}
	}

	devguardTokenVariable := &gitlab.CreateProjectVariableOptions{
		Key:    gitlab.Ptr("DEVGUARD_TOKEN"),
		Value:  gitlab.Ptr(devguardPrivateKey),
		Masked: gitlab.Ptr(true),
	}

	_, _, err = client.CreateVariable(ctx, gitlabProjectID, devguardTokenVariable)
	if err != nil {
		return fmt.Errorf("could not create project variable: %w", err)
	}

	assetNameVariable := &gitlab.CreateProjectVariableOptions{
		Key:    gitlab.Ptr("DEVGUARD_ASSET_NAME"),
		Value:  gitlab.Ptr(devguardAssetName),
		Masked: gitlab.Ptr(false),
	}

	_, _, err = client.CreateVariable(ctx, gitlabProjectID, assetNameVariable)

	return err
}

func getTemplatePath(scannerID string) string {
	switch scannerID {
	case "full":
		return "./templates/full_template.yml"
	case "sca":
		return "./templates/sca_template.yml"
	case "container-scanning":
		return "./templates/container_scanning_template.yml"
	default:
		return "./templates/full_template.yml"
	}
}

func (g *GitlabIntegration) GetUsers(org models.Org) []core.User {
	return []core.User{}
}

func (g *GitlabIntegration) GetID() core.IntegrationID {
	return core.GitLabIntegrationID
}

func (g *GitlabIntegration) Delete(ctx core.Context) error {
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

func (g *GitlabIntegration) TestAndSave(ctx core.Context) error {
	var data struct {
		Url   string `json:"url"`
		Token string `json:"token"`
		Name  string `json:"name"`
	}

	if err := ctx.Bind(&data); err != nil {
		return err
	}

	if data.Token == "" {
		slog.Error("token must not be empty")
		return ctx.JSON(400, "token must not be empty")
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
		return ctx.JSON(400, map[string]any{
			"message": "Invalid GitLab token",
		})
	}

	// save the integration
	integration := models.GitLabIntegration{
		GitLabUrl:   data.Url,
		AccessToken: data.Token,
		Name:        data.Name,
		OrgID:       (core.GetOrg(ctx).GetID()),
	}

	if err := g.gitlabIntegrationRepository.Save(nil, &integration); err != nil {
		return err
	}

	// return all projects
	return ctx.JSON(200, common.GitlabIntegrationDTO{
		ID:              integration.ID.String(),
		Url:             integration.GitLabUrl,
		Name:            integration.Name,
		ObfuscatedToken: integration.AccessToken[:4] + "************" + integration.AccessToken[len(integration.AccessToken)-4:],
	})
}

func (g *GitlabIntegration) ReopenIssue(ctx context.Context, repoId string, vuln models.Vuln) error {
	if !strings.HasPrefix(repoId, "gitlab:") {
		// this integration only handles gitlab repositories
		return nil
	}

	integrationUUID, err := extractIntegrationIdFromRepoId(repoId)
	if err != nil {
		slog.Error("failed to extract integration id from repo id", "err", err, "repoId", repoId)
		return err
	}

	projectId, err := extractProjectIdFromRepoId(repoId)
	if err != nil {
		slog.Error("failed to extract project id from repo id", "err", err, "repoId", repoId)
		return err
	}

	client, err := g.gitlabClientFactory(integrationUUID)
	if err != nil {
		return err
	}

	gitlabTicketID := strings.TrimPrefix(*vuln.GetTicketID(), "gitlab:")
	gitlabTicketIDInt, err := strconv.Atoi(strings.Split(gitlabTicketID, "/")[1])
	if err != nil {
		return err
	}
	labels := commonint.GetLabels(vuln)

	_, _, err = client.EditIssue(ctx, projectId, gitlabTicketIDInt, &gitlab.UpdateIssueOptions{
		StateEvent: gitlab.Ptr("reopen"),
		Labels:     gitlab.Ptr(gitlab.LabelOptions(labels)),
	})
	if err != nil {
		return err
	}

	return nil
}

func (g *GitlabIntegration) UpdateIssue(ctx context.Context, asset models.Asset, repoId string, vuln models.Vuln) error {
	if !strings.HasPrefix(repoId, "gitlab:") {
		// this integration only handles gitlab repositories
		return nil
	}

	integrationUUID, err := extractIntegrationIdFromRepoId(repoId)
	if err != nil {
		slog.Error("failed to extract integration id from repo id", "err", err, "repoId", repoId)
		return err
	}

	projectId, err := extractProjectIdFromRepoId(repoId)
	if err != nil {
		slog.Error("failed to extract project id from repo id", "err", err, "repoId", repoId)
		return err
	}

	client, err := g.gitlabClientFactory(integrationUUID)
	if err != nil {
		return err
	}

	project, err := g.projectRepository.GetProjectByAssetID(asset.ID)
	if err != nil {
		slog.Error("could not get project by asset id", "err", err)
		return err
	}

	org, err := g.orgRepository.GetOrgByID(project.OrganizationID)
	if err != nil {
		slog.Error("could not get org by id", "err", err)
		return err
	}

	switch v := vuln.(type) {
	case *models.DependencyVuln:
		err = g.updateDependencyVulnIssue(ctx, v, asset, client, vuln.GetAssetVersionName(), "", org.Slug, project.Slug, projectId)

	case *models.FirstPartyVuln:
		err = g.updateFirstPartyIssue(ctx, v, asset, client, vuln.GetAssetVersionName(), "", org.Slug, project.Slug, projectId)
	}

	if err != nil {
		//check if err is 404 - if so, we can not reopen the issue
		if err.Error() == "404 Not Found" {

			// we can not reopen the issue - it is deleted
			vulnEvent := models.NewFalsePositiveEvent(vuln.GetID(), vuln.GetType(), "user", "This Vulnerability is marked as a false positive due to deletion", models.VulnerableCodeNotInExecutePath, vuln.GetScannerIDs())
			// save the event
			err := g.aggregatedVulnRepository.ApplyAndSave(nil, vuln, &vulnEvent)
			if err != nil {
				slog.Error("could not save dependencyVuln and event", "err", err)
			}
			return nil
		}
		return err
	}

	return nil
}

func (g *GitlabIntegration) updateFirstPartyIssue(ctx context.Context, dependencyVuln *models.FirstPartyVuln, asset models.Asset, client gitlabClientFacade, assetVersionName, justification, orgSlug, projectSlug string, projectId int) error {
	stateEvent := "close"
	gitlabTicketID := strings.TrimPrefix(*dependencyVuln.TicketID, "gitlab:")
	gitlabTicketIDInt, err := strconv.Atoi(strings.Split(gitlabTicketID, "/")[1])

	labels := commonint.GetLabels(dependencyVuln)

	if err != nil {
		return err
	}

	if dependencyVuln.State == models.VulnStateOpen {
		stateEvent = "reopen"
	}

	_, _, err = client.EditIssue(ctx, projectId, gitlabTicketIDInt, &gitlab.UpdateIssueOptions{
		StateEvent:  gitlab.Ptr(stateEvent),
		Title:       gitlab.Ptr(dependencyVuln.Title()),
		Description: gitlab.Ptr(dependencyVuln.RenderMarkdown()),
		Labels:      gitlab.Ptr(gitlab.LabelOptions(labels)),
	})
	return err
}

func (g *GitlabIntegration) updateDependencyVulnIssue(ctx context.Context, dependencyVuln *models.DependencyVuln, asset models.Asset, client gitlabClientFacade, assetVersionName, justification, orgSlug, projectSlug string, projectId int) error {

	riskMetrics, vector := risk.RiskCalculation(*dependencyVuln.CVE, core.GetEnvironmentalFromAsset(asset))

	exp := risk.Explain(*dependencyVuln, asset, vector, riskMetrics)

	componentTree, err := commonint.RenderPathToComponent(g.componentRepository, asset.ID, dependencyVuln.AssetVersionName, dependencyVuln.ScannerIDs, exp.ComponentPurl)
	if err != nil {
		return err
	}

	gitlabTicketID := strings.TrimPrefix(*dependencyVuln.TicketID, "gitlab:")
	gitlabTicketIDInt, err := strconv.Atoi(strings.Split(gitlabTicketID, "/")[1])
	if err != nil {
		return err
	}
	labels := commonint.GetLabels(dependencyVuln)

	stateEvent := "close"
	if dependencyVuln.State == models.VulnStateOpen {
		stateEvent = "reopen"
	}

	_, _, err = client.EditIssue(ctx, projectId, gitlabTicketIDInt, &gitlab.UpdateIssueOptions{
		StateEvent:  gitlab.Ptr(stateEvent),
		Title:       gitlab.Ptr(fmt.Sprintf("%s found in %s", utils.SafeDereference(dependencyVuln.CVEID), utils.RemovePrefixInsensitive(utils.SafeDereference(dependencyVuln.ComponentPurl), "pkg:"))),
		Description: gitlab.Ptr(exp.Markdown(g.frontendUrl, orgSlug, projectSlug, asset.Slug, dependencyVuln.AssetVersionName, componentTree)),
		Labels:      gitlab.Ptr(gitlab.LabelOptions(labels)),
	})
	return err
}

func (g *GitlabIntegration) CloseIssue(ctx context.Context, state string, repoId string, vuln models.Vuln) error {
	if !strings.HasPrefix(repoId, "gitlab:") {
		// this integration only handles gitlab repositories
		return nil
	}

	integrationUUID, err := extractIntegrationIdFromRepoId(repoId)
	if err != nil {
		slog.Error("failed to extract integration id from repo id", "err", err, "repoId", repoId)
		return err
	}

	projectId, err := extractProjectIdFromRepoId(repoId)
	if err != nil {
		slog.Error("failed to extract project id from repo id", "err", err, "repoId", repoId)
		return err
	}

	client, err := g.gitlabClientFactory(integrationUUID)
	if err != nil {
		return err
	}

	assetID := vuln.GetAssetID()
	asset, err := g.assetRepository.Read(assetID)
	if err != nil {
		slog.Error("could not read asset", "err", err)
	}

	project, err := g.projectRepository.GetProjectByAssetID(asset.ID)
	if err != nil {
		slog.Error("could not get project by asset id", "err", err)
		return err
	}

	org, err := g.orgRepository.Read(project.OrganizationID)
	if err != nil {
		slog.Error("could not get org by id", "err", err)
		return err
	}

	switch v := vuln.(type) {
	case *models.DependencyVuln:
		err = g.closeDependencyVulnIssue(ctx, v, asset, client, vuln.GetAssetVersionName(), "", org.Slug, project.Slug, projectId)
	case *models.FirstPartyVuln:
		err = g.closeFirstPartyIssue(ctx, v, asset, client, vuln.GetAssetVersionName(), "", org.Slug, project.Slug, projectId)
	}

	if err != nil {
		return err
	}

	return nil
}

func (g *GitlabIntegration) closeFirstPartyIssue(ctx context.Context, vuln *models.FirstPartyVuln, asset models.Asset, client gitlabClientFacade, assetVersionName, justification, orgSlug, projectSlug string, projectId int) error {
	gitlabTicketID := strings.TrimPrefix(*vuln.TicketID, "gitlab:")
	gitlabTicketIDInt, err := strconv.Atoi(strings.Split(gitlabTicketID, "/")[1])
	if err != nil {
		return err
	}
	labels := commonint.GetLabels(vuln)

	_, _, err = client.EditIssue(ctx, projectId, gitlabTicketIDInt, &gitlab.UpdateIssueOptions{
		StateEvent: gitlab.Ptr("close"),
		Labels:     gitlab.Ptr(gitlab.LabelOptions(labels)),
	})
	return err
}

func (g *GitlabIntegration) closeDependencyVulnIssue(ctx context.Context, vuln *models.DependencyVuln, asset models.Asset, client gitlabClientFacade, assetVersionName, justification, orgSlug, projectSlug string, projectId int) error {
	riskMetrics, vector := risk.RiskCalculation(*vuln.CVE, core.GetEnvironmentalFromAsset(asset))

	exp := risk.Explain(*vuln, asset, vector, riskMetrics)

	componentTree, err := commonint.RenderPathToComponent(g.componentRepository, asset.ID, vuln.AssetVersionName, vuln.ScannerIDs, exp.ComponentPurl)
	if err != nil {
		return err
	}

	gitlabTicketID := strings.TrimPrefix(*vuln.TicketID, "gitlab:")
	gitlabTicketIDInt, err := strconv.Atoi(strings.Split(gitlabTicketID, "/")[1])
	if err != nil {
		return err
	}
	labels := commonint.GetLabels(vuln)

	_, _, err = client.EditIssue(ctx, projectId, gitlabTicketIDInt, &gitlab.UpdateIssueOptions{
		StateEvent: gitlab.Ptr("close"),
		Labels:     gitlab.Ptr(gitlab.LabelOptions(labels)),

		Title:       gitlab.Ptr(fmt.Sprintf("%s found in %s", utils.SafeDereference(vuln.CVEID), utils.RemovePrefixInsensitive(utils.SafeDereference(vuln.ComponentPurl), "pkg:"))),
		Description: gitlab.Ptr(exp.Markdown(g.frontendUrl, orgSlug, projectSlug, asset.Slug, vuln.AssetVersionName, componentTree)),
	})
	return err
}

func (g *GitlabIntegration) CreateIssue(ctx context.Context, asset models.Asset, assetVersionName string, repoId string, vuln models.Vuln, projectSlug string, orgSlug string, justification string, userID string) error {

	if !strings.HasPrefix(repoId, "gitlab:") {
		// this integration only handles gitlab repositories
		return nil
	}

	integrationUUID, err := extractIntegrationIdFromRepoId(repoId)
	if err != nil {
		slog.Error("failed to extract integration id from repo id", "err", err, "repoId", repoId)
		return err
	}

	projectId, err := extractProjectIdFromRepoId(repoId)
	if err != nil {
		slog.Error("failed to extract project id from repo id", "err", err, "repoId", repoId)
		return err
	}

	client, err := g.gitlabClientFactory(integrationUUID)
	if err != nil {
		return err
	}

	var createdIssue *gitlab.Issue

	switch v := vuln.(type) {
	case *models.DependencyVuln:
		createdIssue, err = g.createDependencyVulnIssue(ctx, v, asset, client, assetVersionName, justification, orgSlug, projectSlug, projectId)
		if err != nil {
			return err
		}
	case *models.FirstPartyVuln:
		createdIssue, err = g.createFirstPartyVulnIssue(ctx, v, asset, client, assetVersionName, justification, orgSlug, projectSlug, projectId)
		if err != nil {
			return err
		}
	}

	vuln.SetTicketID(fmt.Sprintf("gitlab:%d/%d", createdIssue.ProjectID, createdIssue.IID))
	vuln.SetTicketURL(createdIssue.WebURL)
	vuln.SetManualTicketCreation(userID != "system")

	vulnEvent := models.NewMitigateEvent(
		vuln.GetID(),
		vuln.GetType(),
		userID,
		justification,
		map[string]any{
			"ticketId":  vuln.GetTicketID(),
			"ticketUrl": createdIssue.WebURL,
		})

	return g.aggregatedVulnRepository.ApplyAndSave(nil, vuln, &vulnEvent)
}

func (g *GitlabIntegration) createFirstPartyVulnIssue(ctx context.Context, vuln *models.FirstPartyVuln, asset models.Asset, client gitlabClientFacade, assetVersionName, justification, orgSlug, projectSlug string, projectId int) (*gitlab.Issue, error) {

	labels := commonint.GetLabels(vuln)

	issue := &gitlab.CreateIssueOptions{
		Title:       gitlab.Ptr(vuln.Title()),
		Description: gitlab.Ptr(vuln.RenderMarkdown()),
		Labels:      gitlab.Ptr(gitlab.LabelOptions(labels)),
	}

	createdIssue, _, err := client.CreateIssue(ctx, projectId, issue)
	if err != nil {
		return nil, err
	}

	// create a comment with the justification
	_, _, err = client.CreateIssueComment(ctx, projectId, createdIssue.IID, &gitlab.CreateIssueNoteOptions{
		Body: gitlab.Ptr(fmt.Sprintf("<devguard> %s\n", justification)),
	})
	if err != nil {
		slog.Error("could not create issue comment", "err", err)
		return nil, err
	}

	return createdIssue, nil
}

func (g *GitlabIntegration) createDependencyVulnIssue(ctx context.Context, dependencyVuln *models.DependencyVuln, asset models.Asset, client gitlabClientFacade, assetVersionName, justification, orgSlug, projectSlug string, projectId int) (*gitlab.Issue, error) {
	riskMetrics, vector := risk.RiskCalculation(*dependencyVuln.CVE, core.GetEnvironmentalFromAsset(asset))

	exp := risk.Explain(*dependencyVuln, asset, vector, riskMetrics)

	assetSlug := asset.Slug
	labels := commonint.GetLabels(dependencyVuln)
	componentTree, err := commonint.RenderPathToComponent(g.componentRepository, asset.ID, assetVersionName, dependencyVuln.ScannerIDs, exp.ComponentPurl)
	if err != nil {
		return nil, err
	}

	issue := &gitlab.CreateIssueOptions{
		Title:       gitlab.Ptr(fmt.Sprintf("%s found in %s", utils.SafeDereference(dependencyVuln.CVEID), utils.RemovePrefixInsensitive(utils.SafeDereference(dependencyVuln.ComponentPurl), "pkg:"))),
		Description: gitlab.Ptr(exp.Markdown(g.frontendUrl, orgSlug, projectSlug, assetSlug, assetVersionName, componentTree)),
		Labels:      gitlab.Ptr(gitlab.LabelOptions(labels)),
	}

	createdIssue, _, err := client.CreateIssue(ctx, projectId, issue)
	if err != nil {
		return nil, err
	}

	// create a comment with the justification
	_, _, err = client.CreateIssueComment(ctx, projectId, createdIssue.IID, &gitlab.CreateIssueNoteOptions{
		Body: gitlab.Ptr(fmt.Sprintf("<devguard> %s\n", justification)),
	})
	return createdIssue, err
}
