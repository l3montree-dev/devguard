// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package jiraint

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"

	"github.com/l3montree-dev/devguard/internal/core/integrations/commonint"
	"github.com/l3montree-dev/devguard/internal/core/integrations/jira"
	"github.com/l3montree-dev/devguard/internal/core/org"
	"github.com/l3montree-dev/devguard/internal/core/risk"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/utils"
)

type jiraRepository struct {
	*jira.Project
	JiraIntegrationID uuid.UUID `json:"jiraIntegrationID"`
}

func (r *jiraRepository) toRepository() core.Repository {
	return core.Repository{
		ID:          fmt.Sprintf("jira:%s:%s", r.JiraIntegrationID, r.ID),
		Label:       r.Name,
		Description: r.Description,
	}
}

type JiraIntegration struct {
	jiraIntegrationRepository core.JiraIntegrationRepository
	aggregatedVulnRepository  core.VulnRepository
	dependencyVulnRepository  core.DependencyVulnRepository
	firstPartyVulnRepository  core.FirstPartyVulnRepository
	componentRepository       core.ComponentRepository
	externalUserRepository    core.ExternalUserRepository
	vulnEventRepository       core.VulnEventRepository
	assetVersionRepository    core.AssetVersionRepository
	assetRepository           core.AssetRepository
	frontendUrl               string
}

var _ core.ThirdPartyIntegration = &JiraIntegration{}

func NewJiraIntegration(db core.DB) *JiraIntegration {
	jiraIntegrationRepository := repositories.NewJiraIntegrationRepository(db)
	aggregatedVulnRepository := repositories.NewAggregatedVulnRepository(db)
	dependencyVulnRepository := repositories.NewDependencyVulnRepository(db)
	firstPartyVulnRepository := repositories.NewFirstPartyVulnerabilityRepository(db)
	componentRepository := repositories.NewComponentRepository(db)
	externalUserRepository := repositories.NewExternalUserRepository(db)
	vulnEventRepository := repositories.NewVulnEventRepository(db)
	frontendUrl := os.Getenv("FRONTEND_URL")
	if frontendUrl == "" {
		panic("FRONTEND_URL is not set")
	}

	return &JiraIntegration{
		jiraIntegrationRepository: jiraIntegrationRepository,
		aggregatedVulnRepository:  aggregatedVulnRepository,
		dependencyVulnRepository:  dependencyVulnRepository,
		firstPartyVulnRepository:  firstPartyVulnRepository,
		vulnEventRepository:       vulnEventRepository,
		externalUserRepository:    externalUserRepository,
		assetRepository:           repositories.NewAssetRepository(db),
		assetVersionRepository:    repositories.NewAssetVersionRepository(db),
		componentRepository:       componentRepository,
		frontendUrl:               frontendUrl,
	}
}

func (i *JiraIntegration) WantsToHandleWebhook(ctx core.Context) bool {
	return true
}
func (i *JiraIntegration) HandleWebhook(ctx core.Context) error {

	//TODO dont save the comment if it was created by devguard

	//TODO: add webhooksecret
	req := ctx.Request()
	if req.Method != "POST" {
		return ctx.JSON(405, "Method Not Allowed")
	}

	payload, err := io.ReadAll(req.Body)
	if err != nil {
		slog.Error("failed to read request body", "err", err)
		return ctx.JSON(400, "Invalid request body")
	}

	defer req.Body.Close()
	event, err := jira.ParseWebHook(payload)
	if err != nil {
		slog.Error("failed to parse Jira webhook event", "err", err)
		return ctx.JSON(400, fmt.Sprintf("Invalid Jira webhook event: %v", err))
	}

	fmt.Println("Received Jira webhook event:", event)

	var vulnEvent models.VulnEvent
	var vuln models.Vuln
	var issueID string
	var projectID string

	issueID = event.Issue.ID
	projectID = event.Issue.Fields.Project.ID

	vuln, err = i.aggregatedVulnRepository.FindByTicketID(nil, fmt.Sprintf("jira:%s:%s", projectID, issueID))
	if err != nil {
		slog.Error("failed to find vulnerability by ticket ID", "err", err, "ticketID", fmt.Sprintf("jira:%d:%d", projectID, issueID))
		return ctx.JSON(404, fmt.Sprintf("Vulnerability not found for ticket ID: jira:%d:%d", projectID, issueID))
	}

	userID := ""
	username := ""
	userAvatarUrl := ""
	if event.User != nil {
		userID = fmt.Sprintf("jira:%s", event.User.AccountID)
		username = event.User.DisplayName
		userAvatarUrl = event.User.AvatarUrls.Two4X24
	} else if event.Comment != nil && event.Comment.Author != nil {
		userID = fmt.Sprintf("jira:%s", event.Comment.Author.AccountID)
		username = event.Comment.Author.DisplayName
		userAvatarUrl = event.Comment.Author.AvatarUrls.Two4X24
	} else {
		slog.Error("no user information found in Jira webhook event")

	}
	// make sure to save the user - it might be a new user or it might have new values defined.
	// we do not care about any error - and we want speed, thus do it on a goroutine
	go func() {
		org, err := i.aggregatedVulnRepository.GetOrgFromVuln(vuln)
		if err != nil {
			slog.Error("could not get org from dependencyVuln id", "err", err)
			return
		}
		// save the user in the database
		user := models.ExternalUser{
			ID:        fmt.Sprintf("jira:%s", userID),
			Username:  username,
			AvatarURL: userAvatarUrl,
		}

		err = i.externalUserRepository.Save(nil, &user)
		if err != nil {
			slog.Error("could not save github user", "err", err)
			return
		}

		if err = i.externalUserRepository.GetDB(nil).Model(&user).Association("Organizations").Append([]models.Org{org}); err != nil {
			slog.Error("could not append user to organization", "err", err)
		}
	}()

	fmt.Println("statusCategory", event.Issue.Fields.Status.StatusCategory)

	statusCategory := event.Issue.Fields.Status.StatusCategory.ID

	switch event.Event {
	case jira.CommentCreated:
		// Handle comment created event
		slog.Info("Handling comment created event", "event", event.Event)

		// get the asset
		assetVersion, err := i.assetVersionRepository.Read(vuln.GetAssetVersionName(), vuln.GetAssetID())
		if err != nil {
			slog.Error("could not read asset version", "err", err)
			return err
		}

		asset, err := i.assetRepository.Read(assetVersion.AssetID)
		if err != nil {
			slog.Error("could not read asset", "err", err)
			return err
		}

		comment := event.Comment.Body
		//jira adds {{ and }} around the comment, which starts with /
		comment = strings.ReplaceAll(comment, "{{", "")
		comment = strings.ReplaceAll(comment, "}}", "")

		// create a new event based on the comment
		vulnEvent := commonint.CreateNewVulnEventBasedOnComment(vuln.GetID(), vuln.GetType(), fmt.Sprintf("jira:%s", userID), comment, vuln.GetScannerIDs())

		vulnEvent.Apply(vuln)
		// save the vuln and the event in a transaction
		err = i.aggregatedVulnRepository.Transaction(func(tx core.DB) error {
			err := i.aggregatedVulnRepository.Save(tx, &vuln)
			if err != nil {
				return err
			}
			err = i.vulnEventRepository.Save(tx, &vulnEvent)
			if err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			slog.Error("could not save the vulnerability and the event", "err", err)
			return err
		}

		err = i.UpdateIssue(ctx.Request().Context(), asset, vuln)

		if err != nil {
			slog.Error("could not update issue", "err", err)
			return err
		}

	case jira.EventIssueUpdated:
		// Handle issue updated event
		switch statusCategory {
		case jira.StatusCategoryDone:
			if vuln.GetState() == models.VulnStateAccepted || vuln.GetState() == models.VulnStateFalsePositive {
				return nil
			}
			vulnDependencyVuln := vuln.(*models.DependencyVuln)
			vulnEvent = models.NewAcceptedEvent(vuln.GetID(), vuln.GetType(), fmt.Sprintf("jira:%s", userID), fmt.Sprintf("This Vulnerability is marked as accepted by %s, due to closing of the jira ticket.", username))

			err = i.dependencyVulnRepository.ApplyAndSave(nil, vulnDependencyVuln, &vulnEvent)
			if err != nil {
				slog.Error("could not save dependencyVuln and event", "err", err)
			}
		case jira.StatusCategoryToDo, jira.StatusCategoryInProgress:
			if vuln.GetState() == models.VulnStateOpen || vuln.GetState() == models.VulnStateFixed {
				return nil
			}
			vulnDependencyVuln := vuln.(*models.DependencyVuln)
			vulnEvent = models.NewReopenedEvent(vuln.GetID(), vuln.GetType(), fmt.Sprintf("jira:%s", userID), fmt.Sprintf("This Vulnerability was reopened by %s", username))

			err := i.dependencyVulnRepository.ApplyAndSave(nil, vulnDependencyVuln, &vulnEvent)
			if err != nil {
				slog.Error("could not save dependencyVuln and event", "err", err)
			}

		}
	case jira.EventIssueDeleted:
		if vuln.GetState() == models.VulnStateFalsePositive {
			return nil
		}
		vulnEvent := models.NewFalsePositiveEvent(vuln.GetID(), vuln.GetType(), fmt.Sprintf("jira:%s", userID), fmt.Sprintf("This Vulnerability is marked as a false positive by %s, due to the deletion of the jira ticket.", username), models.VulnerableCodeNotInExecutePath, vuln.GetScannerIDs())

		err := i.aggregatedVulnRepository.ApplyAndSave(nil, vuln, &vulnEvent)
		if err != nil {
			slog.Error("could not save vuln and event", "err", err)
		}
	}

	return nil
}
func (i *JiraIntegration) ListOrgs(ctx core.Context) ([]models.Org, error) {
	// Jira integration does not have organizations in the same way as GitLab or GitHub
	return nil, fmt.Errorf("Jira integration does not support listing organizations")
}
func (i *JiraIntegration) ListGroups(ctx core.Context, userID string, providerID string) ([]models.Project, error) {
	// Jira integration does not have groups in the same way as GitLab or GitHub
	return nil, fmt.Errorf("Jira integration does not support listing groups")
}
func (i *JiraIntegration) ListProjects(ctx core.Context, userID string, providerID string, groupID string) ([]models.Asset, error) {
	// Jira integration does not have projects in the same way as GitLab or GitHub
	return nil, fmt.Errorf("Jira integration does not support listing projects")
}
func (i *JiraIntegration) ListRepositories(ctx core.Context) ([]core.Repository, error) {

	if !core.HasOrganization(ctx) {
		return nil, fmt.Errorf("organization is required to list repositories")
	}

	org := core.GetOrg(ctx)

	repos := []core.Repository{}

	if org.JiraIntegrations != nil {
		jiraClient, err := NewJiraBatchClient(org.JiraIntegrations)
		if err != nil {
			return nil, fmt.Errorf("failed to create Jira client: %w", err)
		}

		// get the repos
		r, err := jiraClient.ListRepositories(ctx.QueryParam("search"))
		if err != nil {
			return nil, fmt.Errorf("failed to get repositories from Jira: %w", err)
		}

		repos = append(repos, utils.Map(r, func(repo jiraRepository) core.Repository {
			return repo.toRepository()
		})...)
		return repos, nil
	}
	return nil, fmt.Errorf("no Jira integration found for organization %s", org.GetID())

}
func (i *JiraIntegration) HasAccessToExternalEntityProvider(ctx core.Context, externalEntityProviderID string) (bool, error) {
	// Jira integration does not have access control in the same way as GitLab or GitHub
	return false, fmt.Errorf("Jira integration does not support access control for external entity providers")
}
func (i *JiraIntegration) GetRoleInGroup(ctx context.Context, userID string, providerID string, groupID string) (string, error) {
	// Jira integration does not have groups in the same way as GitLab or GitHub
	return "", fmt.Errorf("Jira integration does not support getting role in group")
}
func (i *JiraIntegration) GetRoleInProject(ctx context.Context, userID string, providerID string, projectID string) (string, error) {
	// Jira integration does not have projects in the same way as GitLab or GitHub
	return "", fmt.Errorf("Jira integration does not support getting role in project")
}
func (i *JiraIntegration) HandleEvent(event any) error {
	switch event := event.(type) {
	case core.ManualMitigateEvent:
		asset := core.GetAsset(event.Ctx)

		repoId, err := core.GetRepositoryID(&asset)
		if err != nil {
			return err
		}
		if !strings.HasPrefix(repoId, "jira:") {
			return fmt.Errorf("asset %s is not a Jira repository", asset.ID)
		}

		assetVersionName := core.GetAssetVersion(event.Ctx).Name
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
			v, err := i.dependencyVulnRepository.Read(vulnID)
			if err != nil {
				return err
			}
			vuln = &v
		case models.VulnTypeFirstPartyVuln:
			v, err := i.firstPartyVulnRepository.Read(vulnID)
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

		return i.CreateIssue(event.Ctx.Request().Context(), asset, assetVersionName, vuln, projectSlug, orgSlug, event.Justification, session.GetUserID())
	case core.VulnEvent:
		ev := event.Event

		asset := core.GetAsset(event.Ctx)
		vulnType := ev.VulnType

		var vuln models.Vuln
		switch vulnType {
		case models.VulnTypeDependencyVuln:
			v, err := i.dependencyVulnRepository.Read(ev.VulnID)
			if err != nil {
				return err
			}
			vuln = &v
		case models.VulnTypeFirstPartyVuln:
			v, err := i.firstPartyVulnRepository.Read(ev.VulnID)
			if err != nil {
				return err
			}
			vuln = &v
		}

		if vuln.GetTicketID() == nil {
			// we do not have a ticket id - we do not need to do anything
			return nil
		}
		repoId := utils.SafeDereference(asset.RepositoryID)
		if !strings.HasPrefix(repoId, "jira:") || !strings.HasPrefix(*vuln.GetTicketID(), "jira:") {
			// this integration only handles github repositories.
			return nil
		}

		client, projectId, err := i.getClientBasedOnAsset(asset)
		if err != nil {
			return fmt.Errorf("failed to get Jira client for asset %s: %w", asset.ID, err)
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

		ticketID := utils.SafeDereference(vuln.GetTicketID())
		if !strings.HasPrefix(ticketID, "jira:") {
			return fmt.Errorf("vulnerability %s does not have a Jira ticket ID", vuln.GetID())
		}
		ticketID = strings.TrimPrefix(ticketID, "jira:")
		ticketIDParts := strings.Split(ticketID, ":")
		if len(ticketIDParts) != 2 {
			return fmt.Errorf("vulnerability %s has an invalid Jira ticket ID format", vuln.GetID())
		}
		ticketID = ticketIDParts[1]

		switch ev.Type {
		case models.EventTypeAccepted:
			_, _, err = client.CreateIssueComment(
				event.Ctx.Request().Context(),
				ticketID,
				strconv.Itoa(projectId),
				fmt.Sprintf("%s\n----\n%s", member.Name+" accepted the vulnerability", utils.SafeDereference(ev.Justification)))

			if err != nil {
				slog.Error("failed to create Jira issue comment", "err", err, "issue", vuln.GetTicketID())
				return fmt.Errorf("failed to create Jira issue comment: %w", err)
			}
		case models.EventTypeFalsePositive:
			justification := fmt.Sprintf("%s\n----\n%s", member.Name+"  commented on the vulnerability", utils.SafeDereference(ev.Justification))

			_, _, err = client.CreateIssueComment(
				event.Ctx.Request().Context(),
				ticketID,
				strconv.Itoa(projectId),
				justification)
			if err != nil {
				slog.Error("failed to create Jira issue comment", "err", err, "issue", vuln.GetTicketID())
				return fmt.Errorf("failed to create Jira issue comment: %w", err)
			}

		case models.EventTypeReopened:
			justification := fmt.Sprintf("%s\n----\n%s", member.Name+" reopened the vulnerability", utils.SafeDereference(ev.Justification))

			_, _, err = client.CreateIssueComment(
				event.Ctx.Request().Context(),
				ticketID,
				strconv.Itoa(projectId),
				justification)

			if err != nil {

				slog.Error("failed to create Jira issue comment", "err", err, "issue", vuln.GetTicketID())
				return fmt.Errorf("failed to create Jira issue comment: %w", err)
			}

		case models.EventTypeComment:
			justification := fmt.Sprintf("%s\n----\n%s", member.Name+" commented on the vulnerability", utils.SafeDereference(ev.Justification))

			_, _, err = client.CreateIssueComment(
				event.Ctx.Request().Context(),
				ticketID,
				strconv.Itoa(projectId),
				justification)

			if err != nil {
				slog.Error("failed to create Jira issue comment", "err", err, "issue", vuln.GetTicketID())
				return fmt.Errorf("failed to create Jira issue comment: %w", err)
			}
		}

		//TODO
		//return i.UpdateIssue(context.Background(), asset, vuln)
	}
	return nil

}

func extractIntegrationIdFromRepoId(repoId string) (uuid.UUID, error) {
	return uuid.Parse(strings.Split(repoId, ":")[1])
}

func extractProjectIdFromRepoId(repoId string) (int, error) {
	return strconv.Atoi(strings.Split(repoId, ":")[2])
}

func (i *JiraIntegration) getClientBasedOnAsset(asset models.Asset) (*jira.Client, int, error) {
	if asset.RepositoryID == nil || !strings.HasPrefix(*asset.RepositoryID, "jira:") {
		return nil, 0, fmt.Errorf("asset %s is not a Jira repository", asset.ID)
	}

	integrationUUID, err := extractIntegrationIdFromRepoId(*asset.RepositoryID)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to extract integration id from repo id: %w", err)
	}

	jiraIntegration, err := i.jiraIntegrationRepository.GetClientByIntegrationID(integrationUUID)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get Jira client for integration %s: %w", integrationUUID, err)
	}

	projectId, err := extractProjectIdFromRepoId(*asset.RepositoryID)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to extract project id from repo id: %w", err)
	}

	client, err := jira.NewJiraClient(
		jiraIntegration.AccessToken,
		jiraIntegration.URL,
		jiraIntegration.UserEmail,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create Jira client from integration %s: %w", integrationUUID, err)
	}

	client.SetJiraIntegrationID(integrationUUID)

	return client, projectId, nil
}

func (i *JiraIntegration) createDependencyVulnIssue(ctx context.Context, dependencyVuln *models.DependencyVuln, asset models.Asset, client *jira.Client, assetVersionName string, justification string, orgSlug string, projectSlug string, projectId int) (*jira.CreateIssueResponse, error) {

	riskMetrics, vector := risk.RiskCalculation(*dependencyVuln.CVE, core.GetEnvironmentalFromAsset(asset))

	exp := risk.Explain(*dependencyVuln, asset, vector, riskMetrics)

	assetSlug := asset.Slug

	labels := commonint.GetLabels(dependencyVuln)
	componentTree, err := commonint.RenderPathToComponent(i.componentRepository, asset.ID, assetVersionName, dependencyVuln.ScannerIDs, exp.ComponentPurl)
	if err != nil {
		return nil, err
	}

	jiraClient, _, err := i.getClientBasedOnAsset(asset)
	if err != nil {
		return nil, fmt.Errorf("failed to get Jira integration for client %s: %w", client.JiraIntegrationID, err)
	}
	jiraIntegration, err := i.jiraIntegrationRepository.GetClientByIntegrationID(jiraClient.JiraIntegrationID)
	if err != nil {
		return nil, fmt.Errorf("failed to get Jira integration for client %s: %w", client.JiraIntegrationID, err)
	}

	description := exp.GenerateADF(client.BaseURL, orgSlug, projectSlug, assetSlug, assetVersionName, componentTree)

	issue := &jira.Issue{
		Fields: &jira.IssueFields{
			Project: jira.Project{
				ID: strconv.Itoa(projectId),
			},
			Type: jira.IssueType{
				Name: "Task",
			},
			Reporter: &jira.User{
				AccountID: jiraIntegration.AccountID,
			},
			Description: description,
			Labels:      labels,
			Summary:     fmt.Sprintf("%s found in %s", utils.SafeDereference(dependencyVuln.CVEID), utils.RemovePrefixInsensitive(utils.SafeDereference(dependencyVuln.ComponentPurl), "pkg:")),
		},
	}

	// the priority schema could be customized by jira, so we do not which priorities are available, a direct request to the Jira API to check the priorities of a project is not possible.
	// a possible workaround is to ask which priority schema are available, then check which projects are using which priority schema, and then check the priorities of the project.
	//so for now we will just set the priority to "highest" if the risk is critical or high
	// check if the risk is critical or high and set the priority accordingly
	riskSeverity, err := risk.RiskToSeverity(*dependencyVuln.RawRiskAssessment)
	if err != nil {
		return nil, fmt.Errorf("failed to convert risk assessment to severity: %w", err)
	}

	if riskSeverity == "Critical" || riskSeverity == "High" {
		issue.Fields.Priority = &jira.Priority{
			ID: "1",
		}
	}

	createdIssue, _, err := client.CreateIssue(ctx, issue)
	if err != nil {
		slog.Error("failed to create Jira issue", "err", err, "issue", issue)
		return nil, fmt.Errorf("failed to create Jira issue: %w", err)
	}

	_, _, err = client.CreateIssueComment(ctx, createdIssue.ID, strconv.Itoa(projectId), justification)
	if err != nil {
		slog.Error("failed to create Jira issue comment", "err", err, "issue", createdIssue)
		return nil, fmt.Errorf("failed to create Jira issue comment: %w", err)
	}

	return createdIssue, nil
}

func (i *JiraIntegration) createFirstPartyVulnIssue(ctx context.Context, vuln *models.FirstPartyVuln, asset models.Asset, client *jira.Client, assetVersionName string, justification string, orgSlug string, projectSlug string, projectId int) (*jira.CreateIssueResponse, error) {
	// Implementation for creating a first-party vulnerability issue in Jira
	return nil, fmt.Errorf("createFirstPartyVulnIssue not implemented")
}

func (i *JiraIntegration) CreateIssue(ctx context.Context, asset models.Asset, assetVersionName string, vuln models.Vuln, projectSlug string, orgSlug string, justification string, userID string) error {
	repoId := utils.SafeDereference(asset.RepositoryID)
	if !strings.HasPrefix(repoId, "jira:") {
		return fmt.Errorf("asset %s is not a Jira repository", asset.ID)
	}

	client, projectId, err := i.getClientBasedOnAsset(asset)
	if err != nil {
		return fmt.Errorf("failed to get Jira client for asset %s: %w", asset.ID, err)
	}
	var createdIssue *jira.CreateIssueResponse

	switch v := vuln.(type) {
	case *models.DependencyVuln:
		createdIssue, err = i.createDependencyVulnIssue(ctx, v, asset, client, assetVersionName, justification, orgSlug, projectSlug, projectId)
		if err != nil {
			return err
		}
	case *models.FirstPartyVuln:
		createdIssue, err = i.createFirstPartyVulnIssue(ctx, v, asset, client, assetVersionName, justification, orgSlug, projectSlug, projectId)
		if err != nil {
			return err
		}
	}

	vuln.SetTicketID(fmt.Sprintf("jira:%d:%s", projectId, createdIssue.GetID()))
	vuln.SetTicketURL(fmt.Sprintf("%s/browse/%s", client.BaseURL, createdIssue.Key))
	vuln.SetManualTicketCreation(userID != "system")

	vulnEvent := models.NewMitigateEvent(
		vuln.GetID(),
		vuln.GetType(),
		userID,
		justification,
		map[string]any{
			"ticketId": vuln.GetTicketID(),
			//TODO: set the right ticket URL
			"ticketUrl": vuln.GetTicketURL(),
		})

	err = i.aggregatedVulnRepository.ApplyAndSave(nil, vuln, &vulnEvent)
	if err != nil {
		slog.Error("failed to save vulnerability with ticket information", "err", err, "vuln", vuln)
		//TODO: if error did happen, we should remove the issue from Jira
		return fmt.Errorf("failed to save vulnerability with ticket information: %w", err)
	}

	return nil
}
func (i *JiraIntegration) UpdateIssue(ctx context.Context, asset models.Asset, vuln models.Vuln) error {
	// Jira integration does not support updating issues in the same way as GitLab or GitHub
	return fmt.Errorf("Jira integration does not support updating issues")
}
func (i *JiraIntegration) GetUsers(org models.Org) []core.User {
	// Jira integration does not have users in the same way as GitLab or GitHub
	return nil
}
func (i *JiraIntegration) GetID() core.IntegrationID {
	return core.JiraIntegrationID
}

func (i *JiraIntegration) TestAndSave(ctx core.Context) error {
	var data struct {
		Url       string `json:"url"`
		Token     string `json:"token"`
		Name      string `json:"name"`
		UserEmail string `json:"userEmail"`
	}

	if err := ctx.Bind(&data); err != nil {
		return ctx.JSON(400, "invalid request data")
	}
	if data.Url == "" || data.Token == "" || data.UserEmail == "" {
		return ctx.JSON(400, "url, token and userEmail are required")
	}
	jiraIntegration := &models.JiraIntegration{
		URL:         data.Url,
		AccessToken: data.Token,
		Name:        data.Name,
		UserEmail:   data.UserEmail,
		OrgID:       (core.GetOrg(ctx).GetID()),
	}

	// check if the token valid and get the account ID
	client, err := jira.NewJiraClient(data.Token, data.Url, data.UserEmail)
	if err != nil {
		slog.Error("failed to create Jira client", "err", err)
		return ctx.JSON(400, fmt.Sprintf("invalid Jira integration data: %v", err))
	}

	accountID, err := client.GetAccountIDByEmail(ctx.Request().Context(), data.UserEmail)
	if err != nil {
		slog.Error("failed to get account ID for email", "email", data.UserEmail, "err", err)
		return ctx.JSON(400, fmt.Sprintf("failed to get account ID for email %s: %v", data.UserEmail, err))
	}

	jiraIntegration.AccountID = accountID

	if err := i.jiraIntegrationRepository.Save(nil, jiraIntegration); err != nil {
		return err
	}
	return ctx.JSON(200, common.JiraIntegrationDTO{
		ID:              jiraIntegration.ID.String(),
		Name:            jiraIntegration.Name,
		URL:             jiraIntegration.URL,
		UserEmail:       jiraIntegration.UserEmail,
		ObfuscatedToken: jiraIntegration.AccessToken[:4] + "************" + jiraIntegration.AccessToken[len(jiraIntegration.AccessToken)-4:],
	})
}
