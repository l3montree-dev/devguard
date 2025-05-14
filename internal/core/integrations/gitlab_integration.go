package integrations

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

	"github.com/google/go-github/v62/github"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/org"
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
	return core.Repository{
		ID:    fmt.Sprintf("gitlab:%s:%d", g.gitlabIntegrationId, g.ID),
		Label: g.NameWithNamespace,
	}
}

type gitlabIntegration struct {
	gitlabIntegrationRepository core.GitlabIntegrationRepository
	externalUserRepository      core.ExternalUserRepository

	firstPartyVulnRepository core.FirstPartyVulnRepository
	aggregatedVulnRepository core.VulnRepository
	//TODO: remove this
	dependencyVulnRepository core.DependencyVulnRepository
	vulnEventRepository      core.VulnEventRepository
	frontendUrl              string
	orgRepository            core.OrganizationRepository

	projectRepository      core.ProjectRepository
	assetRepository        core.AssetRepository
	assetVersionRepository core.AssetVersionRepository
	componentRepository    core.ComponentRepository

	gitlabClientFactory func(id uuid.UUID) (core.GitlabClientFacade, error)
}

var _ core.ThirdPartyIntegration = &gitlabIntegration{}

func messageWasCreatedByDevguard(message string) bool {

	return strings.Contains(message, "<devguard>")

}

func NewGitLabIntegration(db core.DB) *gitlabIntegration {
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

	orgRepository := repositories.NewOrgRepository(db)

	frontendUrl := os.Getenv("FRONTEND_URL")
	if frontendUrl == "" {
		panic("FRONTEND_URL is not set")
	}

	return &gitlabIntegration{
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

		gitlabClientFactory: func(id uuid.UUID) (core.GitlabClientFacade, error) {
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
	return len(core.GetOrganization(ctx).GitLabIntegrations) > 0
}

func (g *gitlabIntegration) WantsToHandleWebhook(ctx core.Context) bool {
	event := ctx.Request().Header.Get("X-Gitlab-Event")
	return strings.TrimSpace(event) != ""
}

func isEventSubscribed(event gitlab.EventType) bool {
	for _, e := range []gitlab.EventType{
		gitlab.EventTypeNote,
		gitlab.EventTypeIssue,
	} {
		if event == e {
			return true
		}
	}
	return false
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

func (g *gitlabIntegration) HandleWebhook(ctx core.Context) error {
	fmt.Printf("Webhook Called\n\n")
	event, err := parseWebhook(ctx.Request())
	if err != nil {
		slog.Error("could not parse gitlab webhook", "err", err)
		return err
	}

	switch event := event.(type) {
	case *gitlab.IssueEvent:

		issueId := event.ObjectAttributes.IID

		// look for a dependencyVuln with such a github ticket id
		vuln, err := g.aggregatedVulnRepository.FindByTicketID(nil, fmt.Sprintf("gitlab:%d/%d", event.Project.ID, issueId))
		if err != nil {
			slog.Debug("could not find dependencyVuln by ticket id", "err", err, "ticketId", issueId)
			return nil
		}

		action := event.ObjectAttributes.Action

		// make sure to save the user - it might be a new user or it might have new values defined.
		// we do not care about any error - and we want speed, thus do it on a goroutine
		go func() {
			org, err := g.aggregatedVulnRepository.GetOrgFromVuln(vuln)
			if err != nil {
				slog.Error("could not get org from dependencyVuln id", "err", err)
				return
			}
			// save the user in the database
			user := models.ExternalUser{
				ID:        fmt.Sprintf("gitlab:%d", event.User.ID),
				Username:  event.User.Name,
				AvatarURL: event.User.AvatarURL,
			}

			err = g.externalUserRepository.Save(nil, &user)
			if err != nil {
				slog.Error("could not save github user", "err", err)
				return
			}

			if err = g.externalUserRepository.GetDB(nil).Model(&user).Association("Organizations").Append([]models.Org{org}); err != nil {
				slog.Error("could not append user to organization", "err", err)
			}
		}()

		switch action {
		case "close":

			if vuln.GetState() == models.VulnStateAccepted || vuln.GetState() == models.VulnStateFalsePositive {
				return nil
			}

			vulnDependencyVuln := vuln.(*models.DependencyVuln)
			vulnEvent := models.NewAcceptedEvent(vuln.GetID(), vuln.GetType(), fmt.Sprintf("gitlab:%d", event.User.ID), fmt.Sprintf("This Vulnerability is marked as accepted by %s, due to closing of the github ticket.", event.User.Name))

			err = g.dependencyVulnRepository.ApplyAndSave(nil, vulnDependencyVuln, &vulnEvent)
			if err != nil {
				slog.Error("could not save dependencyVuln and event", "err", err)
			}
		case "reopen":

			if vuln.GetState() == models.VulnStateOpen {
				return nil
			}
			vulnDependencyVuln := vuln.(*models.DependencyVuln)
			vulnEvent := models.NewReopenedEvent(vuln.GetID(), vuln.GetType(), fmt.Sprintf("gitlab:%d", event.User.ID), fmt.Sprintf("This Vulnerability was reopened by %s", event.User.Name))

			err := g.dependencyVulnRepository.ApplyAndSave(nil, vulnDependencyVuln, &vulnEvent)
			if err != nil {
				slog.Error("could not save dependencyVuln and event", "err", err)
			}
		}

	case *gitlab.IssueCommentEvent:
		// check if the issue is a devguard issue
		issueId := event.Issue.IID

		// check if the user is a bot - we do not want to handle bot comments
		// if event.Comment.User.GetType() == "Bot" {
		// 	return nil
		// }
		// look for a dependencyVuln with such a github ticket id
		vuln, err := g.aggregatedVulnRepository.FindByTicketID(nil, fmt.Sprintf("gitlab:%d/%d", event.ProjectID, issueId))
		if err != nil {
			slog.Debug("could not find dependencyVuln by ticket id", "err", err, "ticketId", issueId)
			return nil
		}

		comment := event.ObjectAttributes.Note

		if messageWasCreatedByDevguard(comment) {
			return nil
		}

		// get the asset
		assetVersion, err := g.assetVersionRepository.Read(vuln.GetAssetVersionName(), vuln.GetAssetID())
		if err != nil {
			slog.Error("could not read asset version", "err", err)
			return err
		}

		asset, err := g.assetRepository.Read(assetVersion.AssetID)
		if err != nil {
			slog.Error("could not read asset", "err", err)
			return err
		}

		// make sure to save the user - it might be a new user or it might have new values defined.
		// we do not care about any error - and we want speed, thus do it on a goroutine
		go func() {
			org, err := g.aggregatedVulnRepository.GetOrgFromVuln(vuln)
			if err != nil {
				slog.Error("could not get org from dependencyVuln id", "err", err)
				return
			}
			// save the user in the database
			user := models.ExternalUser{
				ID:        fmt.Sprintf("gitlab:%d", event.User.ID),
				Username:  event.User.Username,
				AvatarURL: event.User.AvatarURL,
			}

			err = g.externalUserRepository.Save(nil, &user)
			if err != nil {
				slog.Error("could not save github user", "err", err)
				return
			}

			if err = g.externalUserRepository.GetDB(nil).Model(&user).Association("Organizations").Append([]models.Org{org}); err != nil {
				slog.Error("could not append user to organization", "err", err)
			}
		}()

		// create a new event based on the comment
		vulnEvent := createNewVulnEventBasedOnComment(vuln.GetID(), vuln.GetType(), fmt.Sprintf("gitlab:%d", event.User.ID), comment, vuln.GetScannerIDs())

		vulnEvent.Apply(vuln)
		// save the dependencyVuln and the event in a transaction
		err = g.aggregatedVulnRepository.Transaction(func(tx core.DB) error {
			err := g.aggregatedVulnRepository.Save(tx, &vuln)
			if err != nil {
				return err
			}
			err = g.vulnEventRepository.Save(tx, &vulnEvent)
			if err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			slog.Error("could not save dependencyVuln and event", "err", err)
			return err
		}

		// get the integration id based on the asset
		integrationId, err := extractIntegrationIdFromRepoId(utils.SafeDereference(asset.RepositoryID))
		if err != nil {
			slog.Error("could not extract integration id from repo id", "err", err)
			return err
		}

		// get the project id based on the asset
		/*gitlabProjectId, err := extractProjectIdFromRepoId(utils.SafeDereference(asset.RepositoryID))
		if err != nil {
			slog.Error("could not extract project id from repo id", "err", err)
			return err
		}*/

		gitlabProjectId := event.ProjectID

		// make sure to update the github issue accordingly
		client, err := g.gitlabClientFactory(integrationId)
		if err != nil {
			slog.Error("could not create github client", "err", err)
			return err
		}

		isMember, err := client.IsProjectMember(context.TODO(), gitlabProjectId, event.User.ID)
		if err != nil {
			return err
		}
		//Check if the user should be able to use commands
		//TODO : Check member role ?
		if isMember {

			switch vulnEvent.Type {
			case models.EventTypeAccepted:
				labels := getLabels(vuln)
				_, _, err = client.EditIssue(ctx.Request().Context(), gitlabProjectId, issueId, &gitlab.UpdateIssueOptions{
					StateEvent: gitlab.Ptr("close"),
					Labels:     gitlab.Ptr(gitlab.LabelOptions(labels)),
				})
				return err
			case models.EventTypeFalsePositive:
				labels := getLabels(vuln)
				_, _, err = client.EditIssue(ctx.Request().Context(), gitlabProjectId, issueId, &gitlab.UpdateIssueOptions{
					StateEvent: gitlab.Ptr("close"),
					Labels:     gitlab.Ptr(gitlab.LabelOptions(labels)),
				})
				return err
			case models.EventTypeReopened:
				labels := getLabels(vuln)
				_, _, err = client.EditIssue(ctx.Request().Context(), gitlabProjectId, issueId, &gitlab.UpdateIssueOptions{
					StateEvent: gitlab.Ptr("reopen"),
					Labels:     gitlab.Ptr(gitlab.LabelOptions(labels)),
				})
				return err
			}
		}
	}

	return ctx.JSON(200, "ok")
}

func (g *gitlabIntegration) ListRepositories(ctx core.Context) ([]core.Repository, error) {
	org := core.GetOrganization(ctx)
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

func (g *gitlabIntegration) AutoSetup(ctx core.Context) error {
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
	branchName := fmt.Sprintf("devguard-autosetup-%s", strconv.Itoa(generateFourDigitNumber()))

	projectName, err := g.getRepoNameFromProjectId(ctx, projectId)
	if err != nil {
		return errors.Wrap(err, "could not get project name")
	}

	templatePath := getTemplatePath(ctx.QueryParam("scanner"))
	err = setupAndPushPipeline(accessToken, gitlabUrl, projectName, templatePath, branchName)
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

func (g *gitlabIntegration) addProjectHook(ctx core.Context) error {
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

func (g *gitlabIntegration) addProjectVariables(ctx core.Context, devguardPrivateKey, assetName string) error {

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
func (g *gitlabIntegration) addProjectVariable(ctx core.Context, key string, value string, Masked bool, projectId int, client core.GitlabClientFacade) error {

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

func (g *gitlabIntegration) getRepoNameFromProjectId(ctx core.Context, projectId int) (string, error) {
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

func (g *gitlabIntegration) HandleEvent(event any) error {
	switch event := event.(type) {
	case core.ManualMitigateEvent:
		asset := core.GetAsset(event.Ctx)
		assetVersionName := core.GetAssetVersion(event.Ctx).Name
		repoId, err := core.GetRepositoryID(event.Ctx)
		if err != nil {
			return err
		}
		projectSlug, err := core.GetProjectSlug(event.Ctx)

		if err != nil {
			return err
		}
		vulnID, vulnType, err := core.GetVulnID(event.Ctx)
		if err != nil {
			return err
		}

		var vuln models.Vuln

		switch vulnType {
		case models.VulnTypeDependencyVuln:
			// we have a dependency vuln
			v, err := g.dependencyVulnRepository.Read(vulnID)
			if err != nil {
				return err
			}
			vuln = &v
		case models.VulnTypeFirstPartyVuln:
			v, err := g.firstPartyVulnRepository.Read(vulnID)
			if err != nil {
				return err
			}
			vuln = &v
		}

		orgSlug, err := core.GetOrgSlug(event.Ctx)
		if err != nil {
			return err
		}

		session := core.GetSession(event.Ctx)

		return g.CreateIssue(event.Ctx.Request().Context(), asset, assetVersionName, repoId, vuln, projectSlug, orgSlug, event.Justification, session.GetUserID())
	case core.VulnEvent:
		ev := event.Event

		vulnType := ev.VulnType

		var vuln models.Vuln
		switch vulnType {
		case models.VulnTypeDependencyVuln:
			v, err := g.dependencyVulnRepository.Read(ev.VulnID)
			if err != nil {
				return err
			}
			vuln = &v
		case models.VulnTypeFirstPartyVuln:
			v, err := g.firstPartyVulnRepository.Read(ev.VulnID)
			if err != nil {
				return err
			}
			vuln = &v
		}

		asset := core.GetAsset(event.Ctx)

		if vuln.GetTicketID() == nil {
			// we do not have a ticket id - we do not need to do anything
			return nil
		}

		repoId := utils.SafeDereference(asset.RepositoryID)
		if !strings.HasPrefix(repoId, "gitlab:") || !strings.HasPrefix(*vuln.GetTicketID(), "gitlab:") {
			// this integration only handles gitlab repositories.
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

		// we create a new ticket in github
		client, err := g.gitlabClientFactory(integrationUUID)
		if err != nil {
			return err
		}

		gitlabTicketID := strings.TrimPrefix(*vuln.GetTicketID(), "gitlab:")
		gitlabTicketIDInt, err := strconv.Atoi(strings.Split(gitlabTicketID, "/")[1])
		if err != nil {
			return err
		}

		members, err := org.FetchMembersOfOrganization(event.Ctx)
		if err != nil {
			return err
		}

		// find the member which created the event
		member, ok := utils.Find(
			members,
			func(member core.User) bool {
				return member.ID == ev.UserID
			},
		)
		if !ok {
			member = core.User{
				Name: "unknown",
			}
		}

		switch ev.Type {
		case models.EventTypeAccepted:
			// if a dependencyVuln gets accepted, we close the issue and create a comment with that justification
			_, _, err = client.CreateIssueComment(event.Ctx.Request().Context(), projectId, gitlabTicketIDInt, &gitlab.CreateIssueNoteOptions{
				Body: github.String(fmt.Sprintf("<devguard> %s\n----\n%s", member.Name+" accepted the vulnerability", utils.SafeDereference(ev.Justification))),
			})
			if err != nil {
				return err
			}
			return g.CloseIssue(event.Ctx.Request().Context(), "accepted", repoId, vuln)
		case models.EventTypeFalsePositive:
			_, _, err = client.CreateIssueComment(event.Ctx.Request().Context(), projectId, gitlabTicketIDInt, &gitlab.CreateIssueNoteOptions{
				Body: github.String(fmt.Sprintf("<devguard> %s\n----\n%s", member.Name+" marked the vulnerability as false positive", utils.SafeDereference(ev.Justification))),
			})
			if err != nil {
				return err
			}
			return g.CloseIssue(event.Ctx.Request().Context(), "false-positive", repoId, vuln)
		case models.EventTypeReopened:
			_, _, err = client.CreateIssueComment(event.Ctx.Request().Context(), projectId, gitlabTicketIDInt, &gitlab.CreateIssueNoteOptions{
				Body: github.String(fmt.Sprintf("<devguard> %s\n----\n%s", member.Name+" reopened the vulnerability", utils.SafeDereference(ev.Justification))),
			})
			if err != nil {
				return err
			}

			return g.ReopenIssue(event.Ctx.Request().Context(), repoId, vuln)
		case models.EventTypeComment:
			_, _, err = client.CreateIssueComment(event.Ctx.Request().Context(), projectId, gitlabTicketIDInt, &gitlab.CreateIssueNoteOptions{
				Body: github.String(fmt.Sprintf("<devguard> %s\n----\n%s", member.Name+" commented on the vulnerability", utils.SafeDereference(ev.Justification))),
			})
			return err
		}
	}
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
		OrgID:       (core.GetOrganization(ctx).GetID()),
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

func (g *gitlabIntegration) ReopenIssue(ctx context.Context, repoId string, vuln models.Vuln) error {
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
	labels := getLabels(vuln)

	_, _, err = client.EditIssue(ctx, projectId, gitlabTicketIDInt, &gitlab.UpdateIssueOptions{
		StateEvent: gitlab.Ptr("reopen"),
		Labels:     gitlab.Ptr(gitlab.LabelOptions(labels)),
	})
	if err != nil {
		return err
	}

	return nil
}

func (g *gitlabIntegration) UpdateIssue(ctx context.Context, asset models.Asset, repoId string, vuln models.Vuln) error {
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

func (g *gitlabIntegration) updateFirstPartyIssue(ctx context.Context, dependencyVuln *models.FirstPartyVuln, asset models.Asset, client core.GitlabClientFacade, assetVersionName, justification, orgSlug, projectSlug string, projectId int) error {
	stateEvent := "close"
	gitlabTicketID := strings.TrimPrefix(*dependencyVuln.TicketID, "gitlab:")
	gitlabTicketIDInt, err := strconv.Atoi(strings.Split(gitlabTicketID, "/")[1])

	labels := getLabels(dependencyVuln)

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

func (g *gitlabIntegration) updateDependencyVulnIssue(ctx context.Context, dependencyVuln *models.DependencyVuln, asset models.Asset, client core.GitlabClientFacade, assetVersionName, justification, orgSlug, projectSlug string, projectId int) error {

	riskMetrics, vector := risk.RiskCalculation(*dependencyVuln.CVE, core.GetEnvironmentalFromAsset(asset))

	exp := risk.Explain(*dependencyVuln, asset, vector, riskMetrics)

	componentTree, err := renderPathToComponent(g.componentRepository, asset.ID, dependencyVuln.AssetVersionName, dependencyVuln.ScannerIDs, exp.AffectedComponentName)
	if err != nil {
		return err
	}

	gitlabTicketID := strings.TrimPrefix(*dependencyVuln.TicketID, "gitlab:")
	gitlabTicketIDInt, err := strconv.Atoi(strings.Split(gitlabTicketID, "/")[1])
	if err != nil {
		return err
	}
	labels := getLabels(dependencyVuln)

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

func (g *gitlabIntegration) CloseIssue(ctx context.Context, state string, repoId string, vuln models.Vuln) error {
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

func (g *gitlabIntegration) closeFirstPartyIssue(ctx context.Context, vuln *models.FirstPartyVuln, asset models.Asset, client core.GitlabClientFacade, assetVersionName, justification, orgSlug, projectSlug string, projectId int) error {
	gitlabTicketID := strings.TrimPrefix(*vuln.TicketID, "gitlab:")
	gitlabTicketIDInt, err := strconv.Atoi(strings.Split(gitlabTicketID, "/")[1])
	if err != nil {
		return err
	}
	labels := getLabels(vuln)

	_, _, err = client.EditIssue(ctx, projectId, gitlabTicketIDInt, &gitlab.UpdateIssueOptions{
		StateEvent: gitlab.Ptr("close"),
		Labels:     gitlab.Ptr(gitlab.LabelOptions(labels)),
	})
	return err
}

func (g *gitlabIntegration) closeDependencyVulnIssue(ctx context.Context, vuln *models.DependencyVuln, asset models.Asset, client core.GitlabClientFacade, assetVersionName, justification, orgSlug, projectSlug string, projectId int) error {
	riskMetrics, vector := risk.RiskCalculation(*vuln.CVE, core.GetEnvironmentalFromAsset(asset))

	exp := risk.Explain(*vuln, asset, vector, riskMetrics)

	componentTree, err := renderPathToComponent(g.componentRepository, asset.ID, vuln.AssetVersionName, vuln.ScannerIDs, exp.AffectedComponentName)
	if err != nil {
		return err
	}

	gitlabTicketID := strings.TrimPrefix(*vuln.TicketID, "gitlab:")
	gitlabTicketIDInt, err := strconv.Atoi(strings.Split(gitlabTicketID, "/")[1])
	if err != nil {
		return err
	}
	labels := getLabels(vuln)

	_, _, err = client.EditIssue(ctx, projectId, gitlabTicketIDInt, &gitlab.UpdateIssueOptions{
		StateEvent: gitlab.Ptr("close"),
		Labels:     gitlab.Ptr(gitlab.LabelOptions(labels)),

		Title:       gitlab.Ptr(fmt.Sprintf("%s found in %s", utils.SafeDereference(vuln.CVEID), utils.RemovePrefixInsensitive(utils.SafeDereference(vuln.ComponentPurl), "pkg:"))),
		Description: gitlab.Ptr(exp.Markdown(g.frontendUrl, orgSlug, projectSlug, asset.Slug, vuln.AssetVersionName, componentTree)),
	})
	return err
}

func (g *gitlabIntegration) CreateIssue(ctx context.Context, asset models.Asset, assetVersionName string, repoId string, vuln models.Vuln, projectSlug string, orgSlug string, justification string, userID string) error {

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

func (g *gitlabIntegration) createFirstPartyVulnIssue(ctx context.Context, vuln *models.FirstPartyVuln, asset models.Asset, client core.GitlabClientFacade, assetVersionName, justification, orgSlug, projectSlug string, projectId int) (*gitlab.Issue, error) {

	labels := getLabels(vuln)

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

func (g *gitlabIntegration) createDependencyVulnIssue(ctx context.Context, dependencyVuln *models.DependencyVuln, asset models.Asset, client core.GitlabClientFacade, assetVersionName, justification, orgSlug, projectSlug string, projectId int) (*gitlab.Issue, error) {
	riskMetrics, vector := risk.RiskCalculation(*dependencyVuln.CVE, core.GetEnvironmentalFromAsset(asset))

	exp := risk.Explain(*dependencyVuln, asset, vector, riskMetrics)

	assetSlug := asset.Slug
	labels := getLabels(dependencyVuln)
	componentTree, err := renderPathToComponent(g.componentRepository, asset.ID, assetVersionName, dependencyVuln.ScannerIDs, exp.AffectedComponentName)
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
