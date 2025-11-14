package gitlabint

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/integrations/commonint"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/l3montree-dev/devguard/vulndb"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

type gitlabRepository struct {
	*gitlab.Project
	gitlabIntegrationID string
}

func (g gitlabRepository) toRepository() dtos.GitRepository {
	// check for group and project access
	if g.Permissions == nil || (g.Permissions.GroupAccess == nil && g.Permissions.ProjectAccess == nil) {
		return dtos.GitRepository{
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
		return dtos.GitRepository{
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

		return dtos.GitRepository{
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
	return dtos.GitRepository{
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
	clientFactory               GitlabClientFactory
	oauth2Endpoints             map[string]*GitlabOauth2Config
	gitlabOauth2TokenRepository shared.GitLabOauth2TokenRepository
	gitlabIntegrationRepository shared.GitlabIntegrationRepository
	externalUserRepository      shared.ExternalUserRepository
	firstPartyVulnRepository    shared.FirstPartyVulnRepository
	aggregatedVulnRepository    shared.VulnRepository
	dependencyVulnRepository    shared.DependencyVulnRepository
	vulnEventRepository         shared.VulnEventRepository
	frontendURL                 string
	orgRepository               shared.OrganizationRepository
	orgSevice                   shared.OrgService
	projectRepository           shared.ProjectRepository
	projectService              shared.ProjectService
	assetRepository             shared.AssetRepository
	assetVersionRepository      shared.AssetVersionRepository
	assetService                shared.AssetService
	componentRepository         shared.ComponentRepository
	casbinRBACProvider          shared.RBACProvider
	licenseRiskRepository       shared.LicenseRiskRepository
	licenseRiskService          shared.LicenseRiskService
	statisticsService           shared.StatisticsService
}

var _ shared.ThirdPartyIntegration = &GitlabIntegration{}

func messageWasCreatedByDevguard(message string) bool {
	return strings.Contains(message, "<devguard>")
}

func NewGitlabIntegration(db shared.DB, oauth2GitlabIntegration map[string]*GitlabOauth2Config, casbinRBACProvider shared.RBACProvider, clientFactory GitlabClientFactory) *GitlabIntegration {
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
	statisticsRepository := repositories.NewStatisticsRepository(db)
	assetRiskAggregationRepository := repositories.NewArtifactRiskHistoryRepository(db)
	releaseRepository := repositories.NewReleaseRepository(db)

	orgRepository := repositories.NewOrgRepository(db)

	statisticsService := services.NewStatisticsService(statisticsRepository, componentRepository, assetRiskAggregationRepository, dependencyVulnRepository, assetVersionRepository, projectRepository, releaseRepository)
	orgService := services.NewOrgService(orgRepository, casbinRBACProvider)
	projectService := services.NewProjectService(projectRepository, assetRepository)
	assetService := services.NewAssetService(assetRepository, dependencyVulnRepository, nil)
	licenseRiskService := services.NewLicenseRiskService(licenseRiskRepository, vulnEventRepository)

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
		statisticsService:           statisticsService,
	}
}

func (g *GitlabIntegration) WantsToHandleWebhook(ctx shared.Context) bool {
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

func (g *GitlabIntegration) HasAccessToExternalEntityProvider(ctx shared.Context, externalEntityProviderID string) (bool, error) {
	// get the oauth2 tokens for this user
	token, err := g.gitlabOauth2TokenRepository.FindByUserIDAndProviderID(shared.GetSession(ctx).GetUserID(), externalEntityProviderID)
	if err != nil {
		slog.Error("failed to find gitlab oauth2 tokens", "err", err)
		return false, fmt.Errorf("failed to find gitlab oauth2 tokens: %w", err)
	}

	// check that the token is valid
	if !g.checkIfTokenIsValid(ctx, *token, 0) {
		slog.Error("gitlab oauth2 token is not valid", "providerID", externalEntityProviderID)
		return false, fmt.Errorf("gitlab oauth2 token is not valid for provider %s", externalEntityProviderID)
	}

	return true, nil
}

func (g *GitlabIntegration) checkIfTokenIsValid(ctx shared.Context, token models.GitLabOauth2Token, iteration int) bool {
	// create a new gitlab batch client
	gitlabClient, err := g.clientFactory.FromOauth2Token(token, true)
	if err != nil {
		slog.Error("failed to create gitlab batch client", "err", err)
		return false
	}

	// check if the token is valid by fetching the user
	_, _, err = gitlabClient.GetVersion(ctx.Request().Context())
	if err != nil {
		if iteration >= 3 {
			// we tried 3 times to check if the token is valid, but it is still not valid
			slog.Error("gitlab oauth2 token is not valid", "err", err, "tokenHash", utils.HashString(token.AccessToken), "iteration", iteration)
			return false
		}
		slog.Error("gitlab oauth2 token is not valid", "err", err, "tokenHash", utils.HashString(token.AccessToken), "iteration", iteration)
		// wait 1 second before trying again
		time.Sleep(1 * time.Second)
		return g.checkIfTokenIsValid(ctx, token, iteration+1)
	}

	return true
}

func (g *GitlabIntegration) getAndSaveOauth2TokenFromAuthServer(ctx shared.Context) ([]models.GitLabOauth2Token, error) {
	// check if the user has a gitlab login
	// we can even improve the response by checking if the user has a gitlab login
	// todo this, fetch the kratos user and check if the user has a gitlab login
	adminClient := shared.GetAuthAdminClient(ctx)

	ctxWithTimeout, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	identity, err := adminClient.GetIdentityWithCredentials(ctxWithTimeout, shared.GetSession(ctx).GetUserID())
	if err != nil {
		slog.Error("failed to get identity", "err", err)
		return nil, err
	}

	t, err := getGitlabAccessTokenFromOryIdentity(g.oauth2Endpoints, identity)
	if err != nil {
		slog.Warn("failed to get gitlab access token from ory identity")
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
			UserID:       shared.GetSession(ctx).GetUserID(),
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

func (g *GitlabIntegration) ListOrgs(ctx shared.Context) ([]models.Org, error) {
	// get the oauth2 tokens for this user only from the auth server
	// if the user revoked is sign in, we do not want to show him the org anymore.
	tokens, err := g.getAndSaveOauth2TokenFromAuthServer(ctx)
	if err != nil {
		slog.Debug("failed to find gitlab oauth2 tokens")
		return nil, err
	}

	if len(tokens) == 0 {
		slog.Debug("no gitlab oauth2 tokens found for user")
		return nil, nil
	}

	return utils.Map(tokens, oauth2TokenToOrg), nil
}

type groupWithAccessLevel struct {
	group        *gitlab.Group
	avatarBase64 *string
	accessLevel  gitlab.AccessLevelValue
}

func getAllParentGroups(idMap map[int]*gitlab.Group, group *gitlab.Group) []*gitlab.Group {
	var parentGroups []*gitlab.Group
	for group.ParentID != 0 {
		parentGroup, ok := idMap[group.ParentID]
		if !ok {
			break
		}
		parentGroups = append(parentGroups, parentGroup)
		group = parentGroup
	}
	return parentGroups
}

func (g *GitlabIntegration) ListGroups(ctx context.Context, userID string, providerID string) ([]models.Project, []shared.Role, error) {
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

	groups, err := FetchPaginatedData(func(page int) ([]*gitlab.Group, *gitlab.Response, error) {
		// get the groups for this user
		// this WONT list public groups - user is really a member - or at least member of a subproject
		return gitlabClient.ListGroups(ctx, &gitlab.ListGroupsOptions{
			ListOptions: gitlab.ListOptions{Page: page, PerPage: 100},
		})
	})

	if err != nil {
		slog.Error("failed to list groups", "err", err)
		return nil, nil, err
	}

	errgroup := utils.ErrGroup[[]*groupWithAccessLevel](10)

	// !!!we need to mark the user as member in ALL PARENT-GROUPS he has access to!!!
	idMap := make(map[int]*gitlab.Group)
	for _, group := range groups {
		idMap[group.ID] = group
	}

	for _, group := range groups {
		errgroup.Go(func() ([]*groupWithAccessLevel, error) {

			var accessLevel gitlab.AccessLevelValue
			member, _, err := gitlabClient.GetMemberInGroup(ctx, token.GitLabUserID, (*group).ID)
			if err != nil {
				// the user is not really part of the group but part of a subproject
				accessLevel = gitlab.GuestPermissions
			} else {
				accessLevel = member.AccessLevel
			}

			// check if we can fetch the avatar
			var avatarBase64 *string
			if group.AvatarURL != "" {
				avatar, err := gitlabClient.FetchGroupAvatarBase64(group.ID)
				if err != nil {
					slog.Error("failed to fetch avatar", "err", err, "groupID", group.ID)
					return nil, err
				}
				avatarBase64 = &avatar
			}

			// get all parent groups
			parentGroups := getAllParentGroups(idMap, group)
			res := make([]*groupWithAccessLevel, 0, len(parentGroups)+1)
			// add the current group
			res = append(res, &groupWithAccessLevel{
				group:        group,
				avatarBase64: avatarBase64,
				accessLevel:  accessLevel,
			})

			// add all parent groups
			for _, parentGroup := range parentGroups {
				res = append(res, &groupWithAccessLevel{
					group:        parentGroup,
					avatarBase64: nil,
					accessLevel:  accessLevel,
				})
			}
			return res, nil
		})
	}

	cleanedGroups, err := errgroup.WaitAndCollect()
	if err != nil {
		return nil, nil, err
	}
	cleanedGroupsFlat := utils.Filter(utils.Flat(cleanedGroups), func(g *groupWithAccessLevel) bool {
		return g != nil && g.group != nil
	})

	// there might be duplicates now in the cleanedGroupsFlat - unique them by group ID. If a group has an avatar, we use that one, otherwise we use the first one we find.
	uniqueIDMap := make(map[int]*groupWithAccessLevel)
	for _, group := range cleanedGroupsFlat {
		if existing, ok := uniqueIDMap[group.group.ID]; ok {
			// if the existing group has an avatar, we keep it, otherwise we use the new one
			if existing.avatarBase64 == nil && group.avatarBase64 != nil {
				uniqueIDMap[group.group.ID] = group
			}
		} else {
			// if the group is not in the map, we add it
			uniqueIDMap[group.group.ID] = group
		}
	}

	// convert the uniqueIdMap to a slice
	cleanedGroupsFlat = make([]*groupWithAccessLevel, 0, len(uniqueIDMap))
	for _, group := range uniqueIDMap {
		cleanedGroupsFlat = append(cleanedGroupsFlat, group)
	}

	return utils.Map(cleanedGroupsFlat, func(el *groupWithAccessLevel) models.Project {
			return groupToProject(el.avatarBase64, el.group, providerID)
		}), utils.Map(
			cleanedGroupsFlat, func(el *groupWithAccessLevel) shared.Role {
				return gitlabAccessLevelToRole(el.accessLevel)
			},
		), nil
}

// Generic function to fetch paginated data with rate limiting and concurrency
func FetchPaginatedData[T any](
	fetchPage func(page int) ([]T, *gitlab.Response, error),
) ([]T, error) {

	// Channel to collect fetched data
	dataChan := make(chan []T)
	var wg sync.WaitGroup

	// Fetch the first page
	allData, response, err := fetchPage(1)

	if err != nil {
		return nil, err
	}

	// check if total pages are defined - if not (thanks commit api), we have to work with the next page header
	if response.TotalPages == 0 {
		// work with the next page
		for response.NextPage != 0 {
			// Fetch the page
			pageData, r, err := fetchPage(response.NextPage)

			// update the response - otherwise this loop would run forever
			response = r

			if err != nil {
				break
			}

			wg.Add(1)
			go func() {
				defer wg.Done()
				// Send fetched data to the channel
				dataChan <- pageData
			}()
		}

	} else if response.TotalPages > 1 { // we already fetched one page.
		// Start fetching remaining pages concurrently
		for page := response.NextPage; page <= response.TotalPages; page++ {
			wg.Add(1)
			go func(page int) {
				defer wg.Done()
				// Fetch the page
				pageData, _, err := fetchPage(page)
				if err != nil {
					return
				}

				// Send fetched data to the channel
				dataChan <- pageData
			}(page)
		}
	}

	// Collect all data from the channel
	go func() {
		wg.Wait()
		close(dataChan)
	}()

	// Append data from the first page and the channel
	// collect everything until the channel is closed
	for pageData := range dataChan {
		if pageData != nil {
			allData = append(allData, pageData...)
		}
	}

	return allData, nil
}

func gitlabAccessLevelToRole(accessLevel gitlab.AccessLevelValue) shared.Role {

	if accessLevel >= gitlab.OwnerPermissions {
		return shared.RoleAdmin // there is nothing like an owner on project level, so we map it to admin
	} else if accessLevel >= gitlab.MaintainerPermissions {
		return shared.RoleAdmin
	} else if accessLevel >= gitlab.DeveloperPermissions {
		return shared.RoleMember
	}
	return shared.RoleMember // default to member if no higher access level is found
}

func (g *GitlabIntegration) ListProjects(ctx context.Context, userID string, providerID string, groupID string) ([]models.Asset, []shared.Role, error) {
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

	projects, err := FetchPaginatedData(func(page int) ([]*gitlab.Project, *gitlab.Response, error) {
		// get the projects in the group
		return gitlabClient.ListProjectsInGroup(ctx, groupIDInt, &gitlab.ListGroupProjectsOptions{
			WithShared:     gitlab.Ptr(false),
			MinAccessLevel: gitlab.Ptr(gitlab.DeveloperPermissions), // only list projects where the user has at least developer permissions
			ListOptions:    gitlab.ListOptions{Page: page, PerPage: 100},
		})
	})
	if err != nil {
		slog.Error("failed to list projects in group", "err", err)
		return nil, nil, err
	}

	// convert the projects to assets
	result := make([]models.Asset, 0, len(projects))
	accessLevels := make([]shared.Role, 0, len(projects))
	for _, project := range projects {
		// check if we can fetch the avatar
		var avatarBase64 *string
		if project.AvatarURL != "" {
			avatar, err := gitlabClient.FetchProjectAvatarBase64(project.ID)
			if err != nil {
				slog.Error("failed to fetch avatar", "err", err, "projectID", project.ID)
				// Continue without avatar instead of returning error
			} else {
				avatarBase64 = &avatar
			}
		}

		// do another fetch to get the access level of the user in this project
		accessLevel, _, err := gitlabClient.GetMemberInProject(ctx, token.GitLabUserID, project.ID)
		if err != nil {
			// has to be a member of the project - otherwise we would not see it in the list
			result = append(result, projectToAsset(avatarBase64, project, providerID))
			accessLevels = append(accessLevels, shared.RoleMember)
			continue
		}
		result = append(result, projectToAsset(avatarBase64, project, providerID))
		accessLevels = append(accessLevels, gitlabAccessLevelToRole(accessLevel.AccessLevel))
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

	// check if the group has an avatar
	var avatarBase64 *string
	if group.AvatarURL != "" {
		avatar, err := gitlabClient.FetchGroupAvatarBase64(group.ID)
		if err != nil {
			slog.Error("failed to fetch avatar", "err", err, "groupID", group.ID)
			return models.Project{}, err
		}
		avatarBase64 = &avatar
	}

	return groupToProject(avatarBase64, group, providerID), nil
}

func (g *GitlabIntegration) GetRoleInGroup(ctx context.Context, userID string, providerID string, groupID string) (shared.Role, error) {
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

func (g *GitlabIntegration) GetRoleInProject(ctx context.Context, userID string, providerID string, projectID string) (shared.Role, error) {
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

func (g *GitlabIntegration) ListRepositories(ctx shared.Context) ([]dtos.GitRepository, error) {
	var organizationGitlabIntegrations []models.GitLabIntegration
	if shared.HasOrganization(ctx) {
		org := shared.GetOrg(ctx)
		organizationGitlabIntegrations = org.GitLabIntegrations
	}

	// build all clients
	var clients []GitlabClientFacade
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

	return utils.Map(repos, func(r gitlabRepository) dtos.GitRepository {
		return r.toRepository()
	}), nil
}

// Check if the user who comments on a ticket is authorized to use commands like /accept, more checks can be added later
func isGitlabUserAuthorized(event *gitlab.IssueCommentEvent, client GitlabClientFacade) (bool, error) {
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

func ExtractProjectIDFromRepoID(repoID string) (int, error) {
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

func (g *GitlabIntegration) AutoSetup(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)
	repoID := utils.SafeDereference(asset.RepositoryID)

	var req struct {
		DevguardPrivateKey string `json:"devguardPrivateKey"`
		DevguardAssetName  string `json:"devguardAssetName"`
		DevguardAPIURL     string `json:"devguardApiUrl"`
	}
	err := ctx.Bind(&req)
	if err != nil {
		return errors.Wrap(err, "could not bind request")
	}

	var client GitlabClientFacade
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
			err = g.gitlabOauth2TokenRepository.DeleteByUserIDAndProviderID(shared.GetSession(ctx).GetUserID(), *asset.ExternalEntityProviderID+"autosetup")
			if err != nil {
				slog.Error("could not delete gitlab oauth2 token", "err", err)
			}
		}()

		projectIDInt, err = strconv.Atoi(*asset.ExternalEntityID)
		if err != nil {
			return errors.Wrap(err, "could not convert project id to int")
		}

		// check if the user has a gitlab oauth2 token
		token, err := g.gitlabOauth2TokenRepository.FindByUserIDAndProviderID(shared.GetSession(ctx).GetUserID(), providerID)
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

		projectIDInt, err = ExtractProjectIDFromRepoID(repoID)
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

	err = g.addProjectVariables(ctx.Request().Context(), client, asset, projectIDInt, req.DevguardPrivateKey, req.DevguardAssetName, req.DevguardAPIURL)
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

	templateID := ctx.QueryParam("scanner")

	err = commonint.SetupAndPushPipeline(accessToken, gitlabURL, project.PathWithNamespace, templateID, branchName)
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
			if strings.Contains(err.Error(), " 409 {message: Member already exists}") {
				// user is already a member of the project
			} else {
				return errors.Wrap(err, "could not invite devguard bot to project")
			}
		}

		// notify the user that the devguard bot was invited to the project
		enc.Encode(map[string]string{"step": "inviteDevguardBot", "status": "success"}) //nolint:errcheck
		ctx.Response().Flush()
	}

	return nil
}

func (g *GitlabIntegration) addProjectHook(ctx context.Context, client GitlabClientFacade, asset models.Asset, gitlabProjectID int) error {
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
		slog.Debug("no URL specified in .env file defaulting to api.devguard.org")
		defaultURL := "https://api.devguard.org/api/v1/webhook/"
		projectOptions.URL = &defaultURL
	} else {
		instanceDomain = strings.TrimSuffix(instanceDomain, "/") //Remove trailing slash if it exists
		constructedURL := instanceDomain + "/api/v1/webhook/"
		projectOptions.URL = &constructedURL
		// check if we should really enable ssl verification
		if strings.HasPrefix(instanceDomain, "http://") {
			projectOptions.EnableSSLVerification = gitlab.Ptr(false)
		}
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

func (g *GitlabIntegration) addProjectVariables(ctx context.Context, client GitlabClientFacade, asset models.Asset, gitlabProjectID int, devguardPrivateKey string, devguardAssetName string, devguardAPIURL string) error {
	toCreate := map[string]string{}
	toCreate["DEVGUARD_TOKEN"] = devguardPrivateKey
	toCreate["DEVGUARD_ASSET_NAME"] = devguardAssetName
	toCreate["DEVGUARD_API_URL"] = devguardAPIURL

	// check if the project variable already exists
	variables, _, err := client.ListVariables(ctx, gitlabProjectID, nil)
	if err != nil {
		return fmt.Errorf("could not list project variables: %w", err)
	}

	for _, variable := range variables {
		if _, exists := toCreate[variable.Key]; exists {
			// the variable already exists
			update := &gitlab.UpdateProjectVariableOptions{
				Value:  gitlab.Ptr(toCreate[variable.Key]),
				Masked: gitlab.Ptr(false),
			}

			_, _, err = client.UpdateVariable(ctx, gitlabProjectID, variable.Key, update)
			if err != nil {
				return errors.Wrap(err, "could not update project variable")
			}

			delete(toCreate, variable.Key)
		}
	}

	for key, value := range toCreate {
		variable := &gitlab.CreateProjectVariableOptions{
			Key:    gitlab.Ptr(key),
			Value:  gitlab.Ptr(value),
			Masked: gitlab.Ptr(false),
		}

		if key == "DEVGUARD_TOKEN" {
			variable.Masked = gitlab.Ptr(true)
		}

		_, _, err = client.CreateVariable(ctx, gitlabProjectID, variable)
		if err != nil {
			return fmt.Errorf("could not create project variable: %w", err)
		}
	}

	return err
}

func (g *GitlabIntegration) GetUsers(org models.Org) []dtos.UserDTO {
	return []dtos.UserDTO{}
}

func (g *GitlabIntegration) GetID() shared.IntegrationID {
	return shared.GitLabIntegrationID
}

func (g *GitlabIntegration) Delete(ctx shared.Context) error {
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

func (g *GitlabIntegration) TestAndSave(ctx shared.Context) error {
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
		OrgID:       (shared.GetOrg(ctx).GetID()),
	}

	if err := g.gitlabIntegrationRepository.Save(nil, &integration); err != nil {
		return err
	}

	// return all projects
	return ctx.JSON(200, dtos.GitlabIntegrationDTO{
		ID:              integration.ID.String(),
		URL:             integration.GitLabURL,
		Name:            integration.Name,
		ObfuscatedToken: integration.AccessToken[:4] + "************" + integration.AccessToken[len(integration.AccessToken)-4:],
	})
}

func (g *GitlabIntegration) UpdateIssue(ctx context.Context, asset models.Asset, assetVersionSlug string, vuln models.Vuln) error {
	client, projectID, err := g.GetClientBasedOnAsset(asset)
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
		err = g.updateDependencyVulnIssue(ctx, v, asset, client, assetVersionSlug, org.Slug, project.Slug, projectID)

	case *models.FirstPartyVuln:
		err = g.updateFirstPartyIssue(ctx, v, asset, client, assetVersionSlug, org.Slug, project.Slug, projectID)
	}

	if err != nil {
		//check if err is 404 - if so, we can not reopen the issue
		if err.Error() == "404 Not Found" {

			// we can not reopen the issue - it is deleted
			vulnEvent := models.NewFalsePositiveEvent(vuln.GetID(), vuln.GetType(), "user", "This Vulnerability is marked as a false positive due to deletion", dtos.VulnerableCodeNotInExecutePath, vuln.GetScannerIDsOrArtifactNames(), dtos.UpstreamStateInternal)
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

func (g *GitlabIntegration) updateFirstPartyIssue(ctx context.Context, dependencyVuln *models.FirstPartyVuln, asset models.Asset, client GitlabClientFacade, assetVersionSlug, orgSlug, projectSlug string, projectID int) error {
	stateEvent := "close"
	gitlabTicketID := strings.TrimPrefix(*dependencyVuln.TicketID, "gitlab:")
	gitlabTicketIDInt, err := strconv.Atoi(strings.Split(gitlabTicketID, "/")[1])

	labels := commonint.GetLabels(dependencyVuln)
	if err != nil {
		return err
	}

	if dependencyVuln.State == dtos.VulnStateOpen {
		stateEvent = "reopen"
	}

	_, _, err = client.EditIssue(ctx, projectID, gitlabTicketIDInt, &gitlab.UpdateIssueOptions{
		StateEvent:  gitlab.Ptr(stateEvent),
		Title:       gitlab.Ptr(dependencyVuln.Title()),
		Description: gitlab.Ptr(commonint.RenderMarkdown(*dependencyVuln, g.frontendURL, orgSlug, projectSlug, asset.Slug, assetVersionSlug)),
		Labels:      gitlab.Ptr(gitlab.LabelOptions(labels)),
	})
	return err
}

func (g *GitlabIntegration) updateDependencyVulnIssue(ctx context.Context, dependencyVuln *models.DependencyVuln, asset models.Asset, client GitlabClientFacade, assetVersionSlug, orgSlug, projectSlug string, projectID int) error {

	riskMetrics, vector := vulndb.RiskCalculation(*dependencyVuln.CVE, shared.GetEnvironmentalFromAsset(asset))

	exp := vulndb.Explain(*dependencyVuln, asset, vector, riskMetrics)

	componentTree, err := commonint.RenderPathToComponent(g.componentRepository, asset.ID, dependencyVuln.AssetVersionName, dependencyVuln.Artifacts, exp.ComponentPurl)
	if err != nil {
		return err
	}

	gitlabTicketID := strings.TrimPrefix(*dependencyVuln.TicketID, "gitlab:")
	gitlabTicketIDInt, err := strconv.Atoi(strings.Split(gitlabTicketID, "/")[1])
	if err != nil {
		return err
	}
	labels := commonint.GetLabels(dependencyVuln)

	expectedState := commonint.GetExpectedIssueState(asset, dependencyVuln)

	_, _, err = client.EditIssue(ctx, projectID, gitlabTicketIDInt, &gitlab.UpdateIssueOptions{
		StateEvent:  gitlab.Ptr(expectedState.ToGitlab()),
		Title:       gitlab.Ptr(fmt.Sprintf("%s found in %s", utils.SafeDereference(dependencyVuln.CVEID), utils.RemovePrefixInsensitive(utils.SafeDereference(dependencyVuln.ComponentPurl), "pkg:"))),
		Description: gitlab.Ptr(exp.Markdown(g.frontendURL, orgSlug, projectSlug, asset.Slug, assetVersionSlug, componentTree)),
		Labels:      gitlab.Ptr(gitlab.LabelOptions(labels)),
	})
	return err
}

var notConnectedError = errors.New("not connected to gitlab")

func (g *GitlabIntegration) GetClientBasedOnAsset(asset models.Asset) (GitlabClientFacade, int, error) {
	if asset.RepositoryID != nil && strings.HasPrefix(*asset.RepositoryID, "gitlab:") {
		integrationUUID, err := extractIntegrationIDFromRepoID(*asset.RepositoryID)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to extract integration id from repo id: %w", err)
		}

		client, err := g.clientFactory.FromIntegrationUUID(integrationUUID)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to create gitlab client: %w", err)
		}
		projectID, err := ExtractProjectIDFromRepoID(*asset.RepositoryID)
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
	client, projectID, err := g.GetClientBasedOnAsset(asset)
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

func (g *GitlabIntegration) createFirstPartyVulnIssue(ctx context.Context, vuln *models.FirstPartyVuln, asset models.Asset, client GitlabClientFacade, assetVersionSlug, justification, orgSlug, projectSlug string, projectID int) (*gitlab.Issue, error) {

	labels := commonint.GetLabels(vuln)

	issue := &gitlab.CreateIssueOptions{
		Title:       gitlab.Ptr(vuln.Title()),
		Description: gitlab.Ptr(commonint.RenderMarkdown(*vuln, g.frontendURL, orgSlug, projectSlug, asset.Slug, assetVersionSlug)),
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

func (g *GitlabIntegration) createDependencyVulnIssue(ctx context.Context, dependencyVuln *models.DependencyVuln, asset models.Asset, client GitlabClientFacade, assetVersionSlug, justification, orgSlug, projectSlug string, projectID int) (*gitlab.Issue, error) {
	riskMetrics, vector := vulndb.RiskCalculation(*dependencyVuln.CVE, shared.GetEnvironmentalFromAsset(asset))

	exp := vulndb.Explain(*dependencyVuln, asset, vector, riskMetrics)

	assetSlug := asset.Slug
	labels := commonint.GetLabels(dependencyVuln)
	componentTree, err := commonint.RenderPathToComponent(g.componentRepository, asset.ID, dependencyVuln.AssetVersionName, dependencyVuln.Artifacts, exp.ComponentPurl)
	if err != nil {
		return nil, err
	}

	issue := &gitlab.CreateIssueOptions{
		Title:       gitlab.Ptr(fmt.Sprintf("%s found in %s", utils.SafeDereference(dependencyVuln.CVEID), utils.RemovePrefixInsensitive(utils.SafeDereference(dependencyVuln.ComponentPurl), "pkg:"))),
		Description: gitlab.Ptr(exp.Markdown(g.frontendURL, orgSlug, projectSlug, assetSlug, assetVersionSlug, componentTree)),
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

func (g *GitlabIntegration) CreateLabels(ctx context.Context, asset models.Asset) error {
	client, projectID, err := g.GetClientBasedOnAsset(asset)
	if err != nil {
		if errors.Is(err, notConnectedError) {
			return nil
		}
		slog.Error("failed to get gitlab client based on asset", "err", err, "asset", asset)
		return err
	}

	labels := commonint.GetAllRiskLabelsWithColors()

	labelsToUpdate := []commonint.Label{}

	for _, label := range labels {
		_, _, err := client.CreateNewLabel(ctx, projectID, &gitlab.CreateLabelOptions{
			Name:        gitlab.Ptr(label.Name),
			Color:       gitlab.Ptr(label.Color),
			Description: gitlab.Ptr(label.Description),
		})
		if err != nil {
			if strings.Contains(err.Error(), " 409 {message: Label already exists}") {
				labelsToUpdate = append(labelsToUpdate, label)
				continue
			}
			slog.Error("failed to create label", "err", err, "label", label)
			return err
		}
	}

	if len(labelsToUpdate) > 0 {
		err = g.UpdateLabels(ctx, asset, labelsToUpdate)
		if err != nil {
			slog.Error("failed to update labels", "err", err)
			return err
		}
	}

	return nil
}

func (g *GitlabIntegration) UpdateLabels(ctx context.Context, asset models.Asset, labelsToUpdate []commonint.Label) error {
	if len(labelsToUpdate) == 0 {
		return nil
	}

	client, projectID, err := g.GetClientBasedOnAsset(asset)
	if err != nil {
		if errors.Is(err, notConnectedError) {
			return nil
		}
		slog.Error("failed to get gitlab client based on asset", "err", err, "asset", asset)
		return err
	}

	projectLabels, _, err := client.ListLabels(ctx, projectID, &gitlab.ListLabelsOptions{})
	if err != nil {
		slog.Error("failed to list labels", "err", err)
		return err
	}

	projectLabelsMap := make(map[string]gitlab.Label)
	for _, label := range projectLabels {
		projectLabelsMap[label.Name] = *label
	}

	for _, labelToUpdate := range labelsToUpdate {
		if label, exists := projectLabelsMap[labelToUpdate.Name]; exists {
			_, _, err := client.UpdateLabel(ctx, projectID, label.ID, &gitlab.UpdateLabelOptions{
				Color:       gitlab.Ptr(labelToUpdate.Color),
				Description: gitlab.Ptr(labelToUpdate.Description),
			})
			if err != nil {
				slog.Error("failed to update label", "err", err, "label", label)
				return err
			}
		} else {
			slog.Warn("label does not exist in project", "label", label.Name)
			continue
		}
	}

	return nil

}
