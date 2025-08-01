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
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/asset"
	"github.com/l3montree-dev/devguard/internal/core/integrations/commonint"
	"github.com/l3montree-dev/devguard/internal/core/org"
	"github.com/l3montree-dev/devguard/internal/core/project"
	"github.com/l3montree-dev/devguard/internal/core/risk"
	"github.com/l3montree-dev/devguard/internal/core/vuln"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/utils"
)

type gitlabRepository struct {
	*gitlab.Project
	gitlabIntegrationID string
}

func (g gitlabRepository) toRepository() core.Repository {
	// check for group and project access
	if g.Permissions == nil || (g.Permissions.GroupAccess == nil && g.Permissions.ProjectAccess == nil) {
		return core.Repository{
			ID:           fmt.Sprintf("gitlab:%s:%d", g.gitlabIntegrationID, g.ID),
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
			ID:           fmt.Sprintf("gitlab:%s:%d", g.gitlabIntegrationID, g.ID),
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
			ID:          fmt.Sprintf("gitlab:%s:%d", g.gitlabIntegrationID, g.ID),
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
		ID:           fmt.Sprintf("gitlab:%s:%d", g.gitlabIntegrationID, g.ID),
		Label:        g.NameWithNamespace,
		IsDeveloper:  g.Permissions.GroupAccess.AccessLevel >= gitlab.DeveloperPermissions || g.Permissions.ProjectAccess.AccessLevel >= gitlab.DeveloperPermissions,
		IsOwner:      g.Permissions.GroupAccess.AccessLevel >= gitlab.OwnerPermissions || g.Permissions.ProjectAccess.AccessLevel >= gitlab.OwnerPermissions,
		IsMaintainer: g.Permissions.GroupAccess.AccessLevel >= gitlab.MaintainerPermissions || g.Permissions.ProjectAccess.AccessLevel >= gitlab.MaintainerPermissions,
		Description:  g.Description,
		Image:        g.AvatarURL,
	}
}

type GitlabIntegration struct {
	clientFactory               core.GitlabClientFactory
	oauth2Endpoints             map[string]*GitlabOauth2Config
	gitlabOauth2TokenRepository core.GitLabOauth2TokenRepository
	gitlabIntegrationRepository core.GitlabIntegrationRepository
	externalUserRepository      core.ExternalUserRepository
	firstPartyVulnRepository    core.FirstPartyVulnRepository
	aggregatedVulnRepository    core.VulnRepository
	dependencyVulnRepository    core.DependencyVulnRepository
	vulnEventRepository         core.VulnEventRepository
	frontendURL                 string
	orgRepository               core.OrganizationRepository
	orgSevice                   core.OrgService
	projectRepository           core.ProjectRepository
	projectService              core.ProjectService
	assetRepository             core.AssetRepository
	assetVersionRepository      core.AssetVersionRepository
	assetService                core.AssetService
	componentRepository         core.ComponentRepository
	casbinRBACProvider          core.RBACProvider
	licenseRiskRepository       core.LicenseRiskRepository
	licenseRiskService          core.LicenseRiskService
}

var _ core.ThirdPartyIntegration = &GitlabIntegration{}

func messageWasCreatedByDevguard(message string) bool {
	return strings.Contains(message, "<devguard>")
}

func NewGitlabIntegration(db core.DB, oauth2GitlabIntegration map[string]*GitlabOauth2Config, casbinRBACProvider core.RBACProvider, clientFactory core.GitlabClientFactory) *GitlabIntegration {
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
	licenseRiskRepository := repositories.NewLicenseRiskRepository(db)

	orgRepository := repositories.NewOrgRepository(db)

	orgService := org.NewService(orgRepository, casbinRBACProvider)
	projectService := project.NewService(projectRepository, assetRepository)
	assetService := asset.NewService(assetRepository, dependencyVulnRepository, nil)
	licenseRiskService := vuln.NewLicenseRiskService(licenseRiskRepository, vulnEventRepository)

	frontendURL := os.Getenv("FRONTEND_URL")
	if frontendURL == "" {
		panic("FRONTEND_URL is not set")
	}

	return &GitlabIntegration{
		oauth2Endpoints:             oauth2GitlabIntegration,
		gitlabOauth2TokenRepository: gitlabOauth2TokenRepository,
		frontendURL:                 frontendURL,
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
		clientFactory:               clientFactory,
		licenseRiskRepository:       licenseRiskRepository,
		licenseRiskService:          licenseRiskService,
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

func (g *GitlabIntegration) HasAccessToExternalEntityProvider(ctx core.Context, externalEntityProviderID string) (bool, error) {
	// get the oauth2 tokens for this user
	token, err := g.gitlabOauth2TokenRepository.FindByUserIDAndProviderID(core.GetSession(ctx).GetUserID(), externalEntityProviderID)
	if err != nil {
		slog.Error("failed to find gitlab oauth2 tokens", "err", err)
		return false, fmt.Errorf("failed to find gitlab oauth2 tokens: %w", err)
	}

	// check that the token is valid
	if !g.checkIfTokenIsValid(ctx, *token) {
		slog.Error("gitlab oauth2 token is not valid", "providerID", externalEntityProviderID)
		return false, fmt.Errorf("gitlab oauth2 token is not valid for provider %s", externalEntityProviderID)
	}

	return true, nil
}

func (g *GitlabIntegration) checkIfTokenIsValid(ctx core.Context, token models.GitLabOauth2Token) bool {
	// create a new gitlab batch client
	gitlabClient, err := g.clientFactory.FromOauth2Token(token, true)
	if err != nil {
		slog.Error("failed to create gitlab batch client", "err", err)
		return false
	}

	// check if the token is valid by fetching the user
	user, _, err := gitlabClient.ListGroups(ctx.Request().Context(), &gitlab.ListGroupsOptions{
		MinAccessLevel: utils.Ptr(gitlab.ReporterPermissions), // only list groups where the user has at least reporter permissions
		ListOptions:    gitlab.ListOptions{PerPage: 1},        // we only need to check if the request is successful, so we can limit the number of results
	})

	_ = user
	if err != nil {
		slog.Error("failed to get user", "err", err, "tokenHash", utils.HashString(token.AccessToken))
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
	for providerID, token := range t {
		tokenSlice = append(tokenSlice, models.GitLabOauth2Token{
			AccessToken:  token.AccessToken,
			RefreshToken: token.RefreshToken,
			BaseURL:      token.BaseURL,
			GitLabUserID: token.GitLabUserID,
			UserID:       core.GetSession(ctx).GetUserID(),
			ProviderID:   providerID,
			Expiry:       token.Expiry,
		})
	}

	// save the oauth2 tokens if the user doesnt have any tokens yet
	if len(tokenSlice) > 0 {
		err := g.gitlabOauth2TokenRepository.CreateIfNotExists(utils.SlicePtr(tokenSlice))
		if err != nil {
			return nil, err
		}
	}

	return tokenSlice, nil
}

func (g *GitlabIntegration) ListOrgs(ctx core.Context) ([]models.Org, error) {
	// get the oauth2 tokens for this user only from the auth server
	// if the user revoked is sign in, we do not want to show him the org anymore.
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

func (g *GitlabIntegration) ListGroups(ctx context.Context, userID string, providerID string) ([]models.Project, []core.Role, error) {
	// get the oauth2 tokens for this user
	token, err := g.gitlabOauth2TokenRepository.FindByUserIDAndProviderID(userID, providerID)
	if err != nil {
		slog.Error("failed to find gitlab oauth2 tokens", "err", err)
		return nil, nil, err
	}
	// create a new gitlab batch client
	gitlabClient, err := g.clientFactory.FromOauth2Token(*token, true)
	if err != nil {
		slog.Error("failed to create gitlab batch client", "err", err)
		return nil, nil, err
	}
	// get the groups for this user
	groups, _, err := gitlabClient.ListGroups(ctx, &gitlab.ListGroupsOptions{
		ListOptions: gitlab.ListOptions{PerPage: 100},
		//MinAccessLevel: utils.Ptr(gitlab.ReporterPermissions),
		// only list groups where the user has at least reporter permissions
	})

	if err != nil {
		slog.Error("failed to list groups", "err", err)
		return nil, nil, err
	}

	type groupWithAccessLevel struct {
		group       *gitlab.Group
		accessLevel gitlab.AccessLevelValue
	}

	errgroup := utils.ErrGroup[*groupWithAccessLevel](10)
	for _, group := range groups {
		errgroup.Go(func() (*groupWithAccessLevel, error) {
			member, _, err := gitlabClient.GetMemberInGroup(ctx, token.GitLabUserID, (*group).ID)
			if err != nil {
				if strings.Contains(err.Error(), "403 Forbidden") || strings.Contains(err.Error(), "404 Not Found") {
					return nil, nil
				} else {
					return nil, err
				}
			}
			if member.AccessLevel >= gitlab.ReporterPermissions {
				return &groupWithAccessLevel{
					group:       group,
					accessLevel: member.AccessLevel,
				}, nil
			}
			return nil, nil
		})
	}

	cleanedGroups, err := errgroup.WaitAndCollect()
	if err != nil {
		return nil, nil, err
	}
	cleanedGroups = utils.Filter(cleanedGroups, func(g *groupWithAccessLevel) bool {
		return g != nil && g.group != nil
	})

	return utils.Map(cleanedGroups, func(el *groupWithAccessLevel) models.Project {
			return groupToProject(el.group, providerID)
		}), utils.Map(
			cleanedGroups, func(el *groupWithAccessLevel) core.Role {
				return gitlabAccessLevelToRole(el.accessLevel)
			},
		), nil
}

func gitlabAccessLevelToRole(accessLevel gitlab.AccessLevelValue) core.Role {

	if accessLevel >= gitlab.OwnerPermissions {
		return core.RoleAdmin // there is nothing like an owner on project level, so we map it to admin
	} else if accessLevel >= gitlab.MaintainerPermissions {
		return core.RoleAdmin
	} else if accessLevel >= gitlab.DeveloperPermissions {
		return core.RoleMember
	}
	return core.RoleMember // default to member if no higher access level is found
}

func (g *GitlabIntegration) ListProjects(ctx context.Context, userID string, providerID string, groupID string) ([]models.Asset, []core.Role, error) {
	// get the oauth2 tokens for this user
	token, err := g.gitlabOauth2TokenRepository.FindByUserIDAndProviderID(userID, providerID)
	if err != nil {
		slog.Error("failed to find gitlab oauth2 tokens", "err", err)
		return nil, nil, err
	}
	// create a new gitlab batch client
	gitlabClient, err := g.clientFactory.FromOauth2Token(*token, true)
	if err != nil {
		slog.Error("failed to create gitlab batch client", "err", err)
		return nil, nil, err
	}
	// convert the groupID to an int
	groupIDInt, err := strconv.Atoi(groupID)
	if err != nil {
		slog.Error("failed to convert groupID to int", "err", err)
		return nil, nil, errors.Wrap(err, "failed to convert groupID to int")
	}
	// get the projects in the group
	projects, _, err := gitlabClient.ListProjectsInGroup(ctx, groupIDInt, &gitlab.ListGroupProjectsOptions{
		WithShared: gitlab.Ptr(false),
	})
	if err != nil {
		slog.Error("failed to list projects in group", "err", err)
		return nil, nil, err
	}

	// convert the projects to assets
	result := make([]models.Asset, 0, len(projects))
	accessLevels := make([]core.Role, 0, len(projects))
	for _, project := range projects {
		// check if the project has a permissions set - otherwise it is an public project
		if project.Permissions != nil && project.Permissions.ProjectAccess != nil {
			result = append(result, projectToAsset(project, providerID))
			accessLevels = append(accessLevels, gitlabAccessLevelToRole(project.Permissions.ProjectAccess.AccessLevel))
		}
	}

	return result, accessLevels, nil
}

func (g *GitlabIntegration) GetGroup(ctx context.Context, userID string, providerID string, groupID string) (models.Project, error) {
	// get the oauth2 tokens for this user
	token, err := g.gitlabOauth2TokenRepository.FindByUserIDAndProviderID(userID, providerID)
	if err != nil {
		slog.Error("failed to find gitlab oauth2 tokens", "err", err)
		return models.Project{}, err
	}

	// create a new gitlab batch client
	gitlabClient, err := g.clientFactory.FromOauth2Token(*token, true)
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

func (g *GitlabIntegration) GetRoleInGroup(ctx context.Context, userID string, providerID string, groupID string) (core.Role, error) {
	// get the oauth2 tokens for this user
	token, err := g.gitlabOauth2TokenRepository.FindByUserIDAndProviderID(userID, providerID)
	if err != nil {
		slog.Error("failed to find gitlab oauth2 tokens", "err", err)
		return "", err
	}
	// create a new gitlab batch client
	gitlabClient, err := g.clientFactory.FromOauth2Token(*token, true)

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

func (g *GitlabIntegration) GetRoleInProject(ctx context.Context, userID string, providerID string, projectID string) (core.Role, error) {
	// get the oauth2 tokens for this user
	token, err := g.gitlabOauth2TokenRepository.FindByUserIDAndProviderID(userID, providerID)
	if err != nil {
		slog.Error("failed to find gitlab oauth2 tokens", "err", err)
		return "", err
	}

	// create a new gitlab batch client
	gitlabClient, err := g.clientFactory.FromOauth2Token(*token, true)
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

	// build all clients
	var clients []core.GitlabClientFacade
	for _, integration := range organizationGitlabIntegrations {
		client, err := g.clientFactory.FromIntegrationUUID(integration.ID)
		if err != nil {
			slog.Error("failed to create gitlab client from integration", "err", err, "integrationId", integration.ID)
			return nil, err
		}
		clients = append(clients, client)
	}

	// create a new gitlab batch client
	gitlabBatchClient := NewGitlabBatchClient(clients)

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
func isGitlabUserAuthorized(event *gitlab.IssueCommentEvent, client core.GitlabClientFacade) (bool, error) {
	if event == nil || event.User == nil {
		slog.Error("missing event data, could not resolve if user is authorized")
		return false, fmt.Errorf("missing event data, could not resolve if user is authorized")
	}
	return client.IsProjectMember(context.TODO(), event.ProjectID, event.User.ID, nil)
}

func extractIntegrationIDFromRepoID(repoID string) (uuid.UUID, error) {
	// the repo id is formatted like this:
	// gitlab:<integration id>:<project id>
	return uuid.Parse(strings.Split(repoID, ":")[1])
}

func extractProjectIDFromRepoID(repoID string) (int, error) {
	// the repo id is formatted like this:
	// gitlab:<integration id>:<project id>
	return strconv.Atoi(strings.Split(repoID, ":")[2])
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
	repoID := utils.SafeDereference(asset.RepositoryID)

	var req struct {
		DevguardPrivateKey string `json:"devguardPrivateKey"`
		DevguardAssetName  string `json:"devguardAssetName"`
	}
	err := ctx.Bind(&req)
	if err != nil {
		return errors.Wrap(err, "could not bind request")
	}

	var client core.GitlabClientFacade
	var projectIDInt int
	enc := json.NewEncoder(ctx.Response())
	var gitlabURL string
	var accessToken string

	switch {
	case g.gitlabExternalProviderEntity(asset.ExternalEntityProviderID):
		providerID := ctx.QueryParam("providerId")
		if providerID == "" {
			return errors.New("providerID query parameter is required")
		}

		defer func() {
			// delete the token from the database - it is no longer needed after this function finishes
			err = g.gitlabOauth2TokenRepository.DeleteByUserIDAndProviderID(core.GetSession(ctx).GetUserID(), *asset.ExternalEntityProviderID+"autosetup")
			if err != nil {
				slog.Error("could not delete gitlab oauth2 token", "err", err)
			}
		}()

		projectIDInt, err = strconv.Atoi(*asset.ExternalEntityID)
		if err != nil {
			return errors.Wrap(err, "could not convert project id to int")
		}

		// check if the user has a gitlab oauth2 token
		token, err := g.gitlabOauth2TokenRepository.FindByUserIDAndProviderID(core.GetSession(ctx).GetUserID(), providerID)
		if err != nil {
			return errors.Wrap(err, "could not find gitlab oauth2 tokens")
		}

		client, err = g.clientFactory.FromOauth2Token(*token, false)
		if err != nil {
			return errors.Wrap(err, "could not create new gitlab client")
		}
		accessToken = token.AccessToken
		gitlabURL = token.BaseURL
	case strings.HasPrefix(repoID, "gitlab:"):
		integrationUUID, err := extractIntegrationIDFromRepoID(repoID)
		if err != nil {
			return errors.Wrap(err, "could not extract integration id from repo id")
		}

		integration, err := g.gitlabIntegrationRepository.Read(integrationUUID)
		if err != nil {
			return errors.Wrap(err, "could not read gitlab integration")
		}
		client, err = g.clientFactory.FromIntegration(integration)
		if err != nil {
			return errors.Wrap(err, "could not create new gitlab client")
		}

		gitlabURL = integration.GitLabURL
		accessToken = integration.AccessToken

		ctx.Response().Header().Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		ctx.Response().WriteHeader(http.StatusOK) //nolint:errcheck

		projectIDInt, err = extractProjectIDFromRepoID(repoID)
		if err != nil {
			return errors.Wrap(err, "could not extract project id from repo id")
		}
	}

	err = g.addProjectHook(ctx.Request().Context(), client, asset, projectIDInt)
	if err != nil {
		return errors.Wrap(err, "could not add project hook")
	}

	// notify the user that the project hook was added
	enc.Encode(map[string]string{"step": "projectHook", "status": "success"}) //nolint:errcheck
	ctx.Response().Flush()

	err = g.addProjectVariables(ctx.Request().Context(), client, asset, projectIDInt, req.DevguardPrivateKey, req.DevguardAssetName)
	if err != nil {
		return errors.Wrap(err, "could not add project variables")
	}

	// notify the user that the project variables were added
	enc.Encode(map[string]string{"step": "projectVariables", "status": "success"}) //nolint:errcheck
	ctx.Response().Flush()

	project, _, err := client.GetProject(ctx.Request().Context(), projectIDInt)
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

	err = commonint.SetupAndPushPipeline(accessToken, gitlabURL, project.PathWithNamespace, templatePath, branchName)
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
		_, _, err := client.InviteReporter(ctx.Request().Context(), projectIDInt, conf.DevGuardBotUserID)
		if err != nil {
			return errors.Wrap(err, "could not invite devguard bot to project")
		}

		// notify the user that the devguard bot was invited to the project
		enc.Encode(map[string]string{"step": "inviteDevguardBot", "status": "success"}) //nolint:errcheck
		ctx.Response().Flush()
	}

	return nil
}

func (g *GitlabIntegration) addProjectHook(ctx context.Context, client core.GitlabClientFacade, asset models.Asset, gitlabProjectID int) error {
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
		if instanceDomain != "" && strings.HasPrefix(hook.URL, instanceDomain) {
			return projectOptions, fmt.Errorf("hook already exists")
		}
	}

	projectOptions.IssuesEvents = gitlab.Ptr(true)
	projectOptions.ConfidentialIssuesEvents = gitlab.Ptr(true)
	projectOptions.NoteEvents = gitlab.Ptr(true)
	projectOptions.ConfidentialNoteEvents = gitlab.Ptr(true)
	projectOptions.EnableSSLVerification = gitlab.Ptr(true)
	projectOptions.PushEvents = gitlab.Ptr(false)
	if instanceDomain == "" { //If no URL is provided in the environment variables default to main URL
		slog.Debug("no URL specified in .env file defaulting to main")
		defaultURL := "https://api.devguard.org/api/v1/webhook/"
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

func (g *GitlabIntegration) addProjectVariables(ctx context.Context, client core.GitlabClientFacade, asset models.Asset, gitlabProjectID int, devguardPrivateKey string, devguardAssetName string) error {
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
		URL   string `json:"url"`
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
	if !strings.HasPrefix(data.URL, "http://") && !strings.HasPrefix(data.URL, "https://") {
		data.URL = "https://" + data.URL
	}

	git, err := gitlab.NewClient(data.Token, gitlab.WithBaseURL(data.URL))
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
		GitLabURL:   data.URL,
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
		URL:             integration.GitLabURL,
		Name:            integration.Name,
		ObfuscatedToken: integration.AccessToken[:4] + "************" + integration.AccessToken[len(integration.AccessToken)-4:],
	})
}

func (g *GitlabIntegration) UpdateIssue(ctx context.Context, asset models.Asset, vuln models.Vuln) error {
	client, projectID, err := g.getClientBasedOnAsset(asset)
	if err != nil {
		slog.Error("could not get gitlab client based on asset", "err", err)
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
		err = g.updateDependencyVulnIssue(ctx, v, asset, client, vuln.GetAssetVersionName(), org.Slug, project.Slug, projectID)

	case *models.FirstPartyVuln:
		err = g.updateFirstPartyIssue(ctx, v, asset, client, vuln.GetAssetVersionName(), org.Slug, project.Slug, projectID)
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

func (g *GitlabIntegration) updateFirstPartyIssue(ctx context.Context, dependencyVuln *models.FirstPartyVuln, asset models.Asset, client core.GitlabClientFacade, assetVersionName, orgSlug, projectSlug string, projectID int) error {
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

	_, _, err = client.EditIssue(ctx, projectID, gitlabTicketIDInt, &gitlab.UpdateIssueOptions{
		StateEvent:  gitlab.Ptr(stateEvent),
		Title:       gitlab.Ptr(dependencyVuln.Title()),
		Description: gitlab.Ptr(dependencyVuln.RenderMarkdown()),
		Labels:      gitlab.Ptr(gitlab.LabelOptions(labels)),
	})
	return err
}

func (g *GitlabIntegration) updateDependencyVulnIssue(ctx context.Context, dependencyVuln *models.DependencyVuln, asset models.Asset, client core.GitlabClientFacade, assetVersionName, orgSlug, projectSlug string, projectID int) error {

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

	expectedState := vuln.GetExpectedIssueState(asset, dependencyVuln)

	_, _, err = client.EditIssue(ctx, projectID, gitlabTicketIDInt, &gitlab.UpdateIssueOptions{
		StateEvent:  gitlab.Ptr(expectedState.ToGitlab()),
		Title:       gitlab.Ptr(fmt.Sprintf("%s found in %s", utils.SafeDereference(dependencyVuln.CVEID), utils.RemovePrefixInsensitive(utils.SafeDereference(dependencyVuln.ComponentPurl), "pkg:"))),
		Description: gitlab.Ptr(exp.Markdown(g.frontendURL, orgSlug, projectSlug, asset.Slug, dependencyVuln.AssetVersionName, componentTree)),
		Labels:      gitlab.Ptr(gitlab.LabelOptions(labels)),
	})
	return err
}

var notConnectedError = errors.New("not connected to gitlab")

func (g *GitlabIntegration) getClientBasedOnAsset(asset models.Asset) (core.GitlabClientFacade, int, error) {
	if asset.RepositoryID != nil && strings.HasPrefix(*asset.RepositoryID, "gitlab:") {
		integrationUUID, err := extractIntegrationIDFromRepoID(*asset.RepositoryID)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to extract integration id from repo id: %w", err)
		}

		client, err := g.clientFactory.FromIntegrationUUID(integrationUUID)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to create gitlab client: %w", err)
		}
		projectID, err := extractProjectIDFromRepoID(*asset.RepositoryID)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to extract project id from repo id: %w", err)
		}
		// return the client and project id
		return client, projectID, nil
	} else if asset.ExternalEntityProviderID != nil && g.gitlabExternalProviderEntity(asset.ExternalEntityProviderID) {
		conf := g.oauth2Endpoints[*asset.ExternalEntityProviderID]

		client, err := g.clientFactory.FromAccessToken(conf.DevGuardBotUserAccessToken, conf.GitlabBaseURL)
		if err != nil {
			slog.Error("failed to create gitlab client from access token", "err", err, "providerID", *asset.ExternalEntityProviderID)
			return nil, 0, fmt.Errorf("failed to create gitlab client from access token: %w", err)
		}
		projectID, err := strconv.Atoi(*asset.ExternalEntityID)
		if err != nil {
			slog.Error("failed to convert project id to int", "err", err, "externalEntityID", *asset.ExternalEntityID)
			return nil, 0, fmt.Errorf("failed to convert project id to int: %w", err)
		}
		// return the client and project id
		return client, projectID, nil
	}

	return nil, 0, notConnectedError
}

func (g *GitlabIntegration) CreateIssue(ctx context.Context, asset models.Asset, assetVersionName string, vuln models.Vuln, projectSlug string, orgSlug string, justification string, userID string) error {
	client, projectID, err := g.getClientBasedOnAsset(asset)
	if err != nil {
		if errors.Is(err, notConnectedError) {
			return nil
		}
		slog.Error("failed to get gitlab client based on asset", "err", err, "asset", asset)
		return err
	}

	var createdIssue *gitlab.Issue

	switch v := vuln.(type) {
	case *models.DependencyVuln:
		createdIssue, err = g.createDependencyVulnIssue(ctx, v, asset, client, assetVersionName, justification, orgSlug, projectSlug, projectID)
		if err != nil {
			return err
		}
	case *models.FirstPartyVuln:
		createdIssue, err = g.createFirstPartyVulnIssue(ctx, v, asset, client, assetVersionName, justification, orgSlug, projectSlug, projectID)
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

func (g *GitlabIntegration) createFirstPartyVulnIssue(ctx context.Context, vuln *models.FirstPartyVuln, asset models.Asset, client core.GitlabClientFacade, assetVersionName, justification, orgSlug, projectSlug string, projectID int) (*gitlab.Issue, error) {

	labels := commonint.GetLabels(vuln)

	issue := &gitlab.CreateIssueOptions{
		Title:       gitlab.Ptr(vuln.Title()),
		Description: gitlab.Ptr(vuln.RenderMarkdown()),
		Labels:      gitlab.Ptr(gitlab.LabelOptions(labels)),
	}

	createdIssue, _, err := client.CreateIssue(ctx, projectID, issue)
	if err != nil {
		return nil, err
	}

	// create a comment with the justification
	_, _, err = client.CreateIssueComment(ctx, projectID, createdIssue.IID, &gitlab.CreateIssueNoteOptions{
		Body: gitlab.Ptr(fmt.Sprintf("<devguard> %s\n", justification)),
	})
	if err != nil {
		slog.Error("could not create issue comment", "err", err)
		return nil, err
	}

	return createdIssue, nil
}

func (g *GitlabIntegration) createDependencyVulnIssue(ctx context.Context, dependencyVuln *models.DependencyVuln, asset models.Asset, client core.GitlabClientFacade, assetVersionName, justification, orgSlug, projectSlug string, projectID int) (*gitlab.Issue, error) {
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
		Description: gitlab.Ptr(exp.Markdown(g.frontendURL, orgSlug, projectSlug, assetSlug, assetVersionName, componentTree)),
		Labels:      gitlab.Ptr(gitlab.LabelOptions(labels)),
	}

	createdIssue, _, err := client.CreateIssue(ctx, projectID, issue)
	if err != nil {
		return nil, err
	}

	// create a comment with the justification
	_, _, err = client.CreateIssueComment(ctx, projectID, createdIssue.IID, &gitlab.CreateIssueNoteOptions{
		Body: gitlab.Ptr(fmt.Sprintf("<devguard> %s\n", justification)),
	})
	return createdIssue, err
}
