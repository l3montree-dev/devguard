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
	gitlabOauth2ClientFactory   func(token models.GitLabOauth2Token) (gitlabClientFacade, error)
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

		gitlabOauth2ClientFactory: func(token models.GitLabOauth2Token) (gitlabClientFacade, error) {
			// get the correct gitlab oauth2 integration configuration
			for _, integration := range oauth2GitlabIntegration {
				if integration.ProviderID == token.ProviderID {
					return buildOauth2GitlabClient(token, integration)
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
	gitlabClient, err := g.gitlabOauth2ClientFactory(token)
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

func (g *GitlabIntegration) getOauth2TokenFromAuthServer(ctx core.Context) ([]models.GitLabOauth2Token, error) {
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

	return tokenSlice, nil
}

func (g *GitlabIntegration) checkTokens(ctx core.Context, tokens []models.GitLabOauth2Token) ([]models.GitLabOauth2Token, []models.GitLabOauth2Token) {
	// remove all invalid tokens
	wg := utils.ErrGroup[bool](10)
	for i := range tokens {
		wg.Go(func() (bool, error) {
			return g.checkIfTokenIsValid(ctx, tokens[i]), nil
		})
	}

	result, _ := wg.WaitAndCollect()
	validTokens := make([]models.GitLabOauth2Token, 0)
	toRemove := make([]models.GitLabOauth2Token, 0)
	for i, valid := range result {
		if valid {
			validTokens = append(validTokens, tokens[i])
		} else {
			toRemove = append(toRemove, tokens[i])
		}
	}

	return validTokens, toRemove
}

func (g *GitlabIntegration) GetOauth2Tokens(ctx core.Context) ([]models.GitLabOauth2Token, error) {
	// get the oauth2 tokens for this user
	tokens, err := g.gitlabOauth2TokenRepository.FindByUserId(core.GetSession(ctx).GetUserID())
	if err != nil {
		tokens = make([]models.GitLabOauth2Token, 0)
	}

	validTokens, toRemove := g.checkTokens(ctx, tokens)

	// delete the invalid tokens from the database
	if len(toRemove) > 0 {
		err = g.gitlabOauth2TokenRepository.Delete(nil, toRemove)
		if err != nil {
			slog.Error("failed to delete invalid gitlab oauth2 tokens", "err", err)
			return nil, err
		}
	}

	if len(validTokens) == 0 {
		// if no valid tokens are found, try to get the tokens from the auth server
		slog.Debug("no valid gitlab oauth2 tokens found, trying to get them from the auth server")
		tokens, err = g.getOauth2TokenFromAuthServer(ctx)
		if err != nil {
			slog.Error("failed to get gitlab oauth2 tokens from auth server", "err", err)
			return nil, err
		}

		// filter the tokens - remove all tokens we already removed
		tokens = utils.Filter(tokens, func(token models.GitLabOauth2Token) bool {
			for _, t := range toRemove {
				if t.AccessToken == token.AccessToken {
					return false
				}
			}
			return true
		})

		validTokens, _ = g.checkTokens(ctx, tokens)

		if len(validTokens) != 0 {
			// save the tokens in the database
			err = g.gitlabOauth2TokenRepository.Save(nil, utils.SlicePtr(validTokens)...)
			if err != nil {
				slog.Error("failed to save gitlab oauth2 tokens", "err", err)
				return nil, err
			}
		}
	}

	return validTokens, nil
}

func (g *GitlabIntegration) ListOrgs(ctx core.Context) ([]models.Org, error) {
	// get the oauth2 tokens for this user
	tokens, err := g.getOauth2TokenFromAuthServer(ctx)
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
	gitlabClient, err := g.gitlabOauth2ClientFactory(*token)
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
	gitlabClient, err := g.gitlabOauth2ClientFactory(*token)
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
	gitlabClient, err := g.gitlabOauth2ClientFactory(*token)
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
	gitlabClient, err := g.gitlabOauth2ClientFactory(*token)

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
	gitlabClient, err := g.gitlabOauth2ClientFactory(*token)
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

	tokens, err := g.GetOauth2Tokens(ctx)
	if err != nil {
		slog.Error("failed to get gitlab oauth2 tokens", "err", err)
		return nil, err
	}

	// create a new gitlab batch client
	gitlabBatchClient, err := newGitLabBatchClient(organizationGitlabIntegrations, g.oauth2Endpoints, tokens)
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

func (g *GitlabIntegration) AutoSetup(ctx core.Context) error {
	asset := core.GetAsset(ctx)
	repoId := utils.SafeDereference(asset.RepositoryID)
	if !strings.HasPrefix(repoId, "gitlab:") {
		// this integration only handles gitlab repositories
		return nil
	}

	integrationUUID, err := extractIntegrationIdFromRepoId(repoId)
	if err != nil {
		return errors.Wrap(err, "could not extract integration id from repo id")
	}

	client, err := g.gitlabClientFactory(integrationUUID)
	if err != nil {
		return errors.Wrap(err, "could not create new gitlab client")
	}

	integration, err := g.gitlabIntegrationRepository.Read(integrationUUID)
	if err != nil {
		return errors.Wrap(err, "could not read gitlab integration")
	}
	accessToken := integration.AccessToken
	gitlabUrl := integration.GitLabUrl

	var req struct {
		DevguardAssetName  string `json:"devguardAssetName"`
		DevguardPrivateKey string `json:"devguardPrivateKey"`
	}
	err = ctx.Bind(&req)
	if err != nil {
		return errors.Wrap(err, "could not bind request")
	}

	ctx.Response().Header().Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	ctx.Response().WriteHeader(http.StatusOK) //nolint:errcheck

	enc := json.NewEncoder(ctx.Response())

	err = g.addProjectHook(ctx)
	if err != nil {
		return errors.Wrap(err, "could not add project hook")
	}

	// notify the user that the project hook was added
	enc.Encode(map[string]string{"step": "projectHook", "status": "success"}) //nolint:errcheck
	ctx.Response().Flush()

	err = g.addProjectVariables(ctx, req.DevguardPrivateKey, req.DevguardAssetName)
	if err != nil {
		return errors.Wrap(err, "could not add project variables")
	}

	// notify the user that the project variables were added
	enc.Encode(map[string]string{"step": "projectVariables", "status": "success"}) //nolint:errcheck
	ctx.Response().Flush()

	// get the project name
	projectId, err := extractProjectIdFromRepoId(repoId)
	if err != nil {
		return errors.Wrap(err, "could not extract project id from repo id")
	}

	project, _, err := client.GetProject(ctx.Request().Context(), projectId)
	if err != nil {
		return errors.Wrap(err, "could not get project")
	}
	defaultBranch := project.DefaultBranch

	//generate a random branch name
	branchName := fmt.Sprintf("devguard-autosetup-%s", strconv.Itoa(commonint.GenerateFourDigitNumber()))

	projectName, err := g.getRepoNameFromProjectId(ctx, projectId)
	if err != nil {
		return errors.Wrap(err, "could not get project name")
	}

	templatePath := getTemplatePath(ctx.QueryParam("scanner"))
	err = commonint.SetupAndPushPipeline(accessToken, gitlabUrl, projectName, templatePath, branchName)
	if err != nil {
		return errors.Wrap(err, "could not setup and push pipeline")
	}

	// notify the user that the pipeline was created
	enc.Encode(map[string]string{"step": "pipeline", "status": "success"}) //nolint:errcheck
	ctx.Response().Flush()

	//create a merge request
	mr, _, err := client.CreateMergeRequest(ctx.Request().Context(), projectName, &gitlab.CreateMergeRequestOptions{
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

	return nil
}

func (g *GitlabIntegration) addProjectHook(ctx core.Context) error {
	asset := core.GetAsset(ctx)
	repoId := utils.SafeDereference(asset.RepositoryID)
	if !strings.HasPrefix(repoId, "gitlab:") {
		// this integration only handles gitlab repositories
		return nil
	}

	integrationUUID, err := extractIntegrationIdFromRepoId(repoId)
	if err != nil {
		return fmt.Errorf("could not extract integration id from repo id: %w", err)
	}

	projectId, err := extractProjectIdFromRepoId(repoId)
	if err != nil {
		return fmt.Errorf("could not extract project id from repo id: %w", err)
	}

	client, err := g.gitlabClientFactory(integrationUUID)
	if err != nil {
		return fmt.Errorf("could not create new gitlab client: %w", err)
	}
	// check if the project hook already exists
	hooks, _, err := client.ListProjectHooks(ctx.Request().Context(), projectId, nil)
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

	_, _, err = client.AddProjectHook(ctx.Request().Context(), projectId, projectOptions)
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

func (g *GitlabIntegration) addProjectVariables(ctx core.Context, devguardPrivateKey, assetName string) error {

	asset := core.GetAsset(ctx)
	repoId := utils.SafeDereference(asset.RepositoryID)
	if !strings.HasPrefix(repoId, "gitlab:") {
		// this integration only handles gitlab repositories
		return nil
	}

	integrationUUID, err := extractIntegrationIdFromRepoId(repoId)
	if err != nil {
		return fmt.Errorf("could not extract integration id from repo id: %w", err)
	}

	projectId, err := extractProjectIdFromRepoId(repoId)
	if err != nil {
		return fmt.Errorf("could not extract project id from repo id: %w", err)
	}

	client, err := g.gitlabClientFactory(integrationUUID)
	if err != nil {
		return fmt.Errorf("could not create new gitlab client: %w", err)
	}

	err = g.addProjectVariable(ctx, "DEVGUARD_TOKEN", devguardPrivateKey, true, projectId, client)

	if err != nil {
		return err
	}

	err = g.addProjectVariable(ctx, "DEVGUARD_ASSET_NAME", assetName, false, projectId, client)
	if err != nil {
		return err
	}

	return nil
}
func (g *GitlabIntegration) addProjectVariable(ctx core.Context, key string, value string, Masked bool, projectId int, client gitlabClientFacade) error {

	projectVariable := &gitlab.CreateProjectVariableOptions{
		Key:    gitlab.Ptr(key),
		Value:  gitlab.Ptr(value),
		Masked: gitlab.Ptr(Masked),
	}

	// check if the project variable already exists
	variables, _, err := client.ListVariables(ctx.Request().Context(), projectId, nil)
	if err != nil {
		return fmt.Errorf("could not list project variables: %w", err)
	}

	for _, variable := range variables {
		if variable.Key == key {
			// the variable already exists
			// remove it - we cannot update, since some are protected
			_, err = client.RemoveVariable(ctx.Request().Context(), projectId, key)
			if err != nil {
				return errors.Wrap(err, "could not remove project variable")
			}
		}
	}

	_, _, err = client.CreateVariable(ctx.Request().Context(), projectId, projectVariable)
	if err != nil {
		return fmt.Errorf("could not create project variable: %w", err)
	}

	return nil
}

func (g *GitlabIntegration) getRepoNameFromProjectId(ctx core.Context, projectId int) (string, error) {
	asset := core.GetAsset(ctx)
	repoId := utils.SafeDereference(asset.RepositoryID)
	if !strings.HasPrefix(repoId, "gitlab:") {
		// this integration only handles gitlab repositories
		return "", nil
	}

	integrationUUID, err := extractIntegrationIdFromRepoId(repoId)
	if err != nil {
		return "", fmt.Errorf("could not extract integration id from repo id: %v", err)
	}

	client, err := g.gitlabClientFactory(integrationUUID)
	if err != nil {
		return "", fmt.Errorf("could not create new gitlab client: %v", err)
	}

	project, _, err := client.GetProject(ctx.Request().Context(), projectId)
	if err != nil {
		return "", fmt.Errorf("could not get project: %v", err)
	}
	projectName := project.PathWithNamespace
	return strings.ReplaceAll(projectName, " ", ""), nil
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

/*
{"providers":[{"subject":"2028","provider":"opencode","initial_id_token":"65794a30655841694f694a4b563151694c434a72615751694f69497852313953536c563064564a5461554e32566b744365554e50533246775a6c46725a564268526e46315446513453456c6962307048626a644a496977695957786e496a6f69556c4d794e54596966512e65794a7063334d694f694a6f64485277637a6f764c3264706447786859693576634756755932396b5a53356b5a534973496e4e3159694936496a49774d6a67694c434a68645751694f6949795932466b4d6a49344f544133596a51784d3249794f444d324e44426d59544e6b5a6a4d334d44526d4d4441354e475a69593259794d44417a4e7a526b5a44686b59544a6b5a5459784d325a6a4d7a4e6d4d325978496977695a586877496a6f784e7a51344f44557a4d4445794c434a70595851694f6a45334e4467344e5449344f544973496d46316447686664476c745a5349364d5463304f4467304e7a51334e697769633356695832786c5a32466a65534936496a5179597a41775a475577596a637a5a44566c4d4751304d57526a5a4749794d7a526d4f44426d4d7a6b354d4755794e7a466c5a47597a5a4464694d475a694e6d4a694d475935596d4a6d4d444a6c4e546c6c596a55694c434a755957316c496a6f6956476c7449454a686333527062694973496d3570593274755957316c496a6f6964476c74596d467a64476c754969776963484a6c5a6d5679636d566b5833567a5a584a755957316c496a6f6964476c74596d467a64476c75496977695a573168615777694f694a3061573075596d467a64476c755147777a6257397564484a6c5a53356a623230694c434a6c62574670624639325a584a705a6d6c6c5a43493664484a315a53776963484a765a6d6c735a534936496d68306448427a4f6938765a326c30624746694c6d39775a57356a6232526c4c6d526c4c33527062574a686333527062694973496e427059335231636d55694f694a6f64485277637a6f764c3264706447786859693576634756755932396b5a53356b5a533931634778765957527a4c79307663336c7a644756744c33567a5a58497659585a68644746794c7a49774d6a677659585a68644746794c6e42755a794973496d6479623356776331396b61584a6c593351694f6c736959584a6a61484a734c576c304c574a31626d51694c434a76634756755932396b5a533168626d46736558706c63694973496d4e35596d56796332566a64584a7064486b746147466a6132463061473975496977696233426c6269316a6232526c4c324a685a47646c596d466a613256755a434973496d777a6257397564484a6c5a534973496e4e6c636e5a705932567a644746755a4746795a434973496d39775a5734745932396b5a533970626e526c636d3568624339775a584a7461584e7a615739756379396a62323177595735354c32777a6257397564484a6c5a534a6466512e75565474752d76344b737074467052466951704b46394e4838586262646732707a7a35744935766e784759614258356a4f50706c5a385439386a4e69564332316d6549782d5a746c5937694f4a6d42383737716e50363864716c74584a48697262417730445870627036505638624a576c68386243335f73494e6b5644456e6e776166585a386963397347576e71552d5174566d3355644b31665242395a39614e3043632d45776257462d6f685a703133517655794e56366e316b61597043305a576863696e43396c4c534f77462d424b5955306a4e676e4e6577446658492d642d50767866524430725a693136684354514637484f7337437a7577444f4458595a47494b372d377134526a4236756c535868735a4b375f5f7a646371597661664b447777446b344e424246766f726f386c774c58317a31744d426431655434316648416e615448584f70436a4c4e36697a30465451","initial_access_token":"34353263636132343662623266626133383366356238346136373630623838343334666666343864373530313633623666383833613236663866323662663962","initial_refresh_token":"30353065306439613364346332323231653136333766333634373064353565623762386232396435316539346533303961353566363332343462636365656364"}]}*/
