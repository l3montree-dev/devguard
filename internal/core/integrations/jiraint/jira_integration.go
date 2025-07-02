// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package jiraint

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"

	"github.com/l3montree-dev/devguard/internal/core/integrations/commonint"
	"github.com/l3montree-dev/devguard/internal/core/integrations/jira"
	"github.com/l3montree-dev/devguard/internal/core/risk"
	"github.com/l3montree-dev/devguard/internal/core/vuln"
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
	orgRepository             core.OrganizationRepository
	projectRepository         core.ProjectRepository
	frontendURL               string
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
	projectRepository := repositories.NewProjectRepository(db)
	orgRepository := repositories.NewOrgRepository(db)
	frontendURL := os.Getenv("FRONTEND_URL")
	if frontendURL == "" {
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
		projectRepository:         projectRepository,
		orgRepository:             orgRepository,
		frontendURL:               frontendURL,
	}
}

func (i *JiraIntegration) WantsToHandleWebhook(ctx core.Context) bool {
	return true
}

func (i *JiraIntegration) CheckWebhookSecretToken(hash string, payload []byte, assetID uuid.UUID) error {
	asset, err := i.assetRepository.Read(assetID)
	if err != nil {
		slog.Error("could not read asset", "err", err)
		return err
	}

	jiraSecretToken := asset.WebhookSecret
	if jiraSecretToken == nil {
		return nil
	}

	mac := hmac.New(sha256.New, []byte(jiraSecretToken.String()))
	_, err = mac.Write(payload)
	if err != nil {
		slog.Error("failed to write payload to HMAC", "err", err)
		return fmt.Errorf("failed to write payload to HMAC: %w", err)
	}

	hexDigest := fmt.Sprintf("%x", mac.Sum(nil))

	hash = strings.TrimPrefix(hash, "sha256=")
	check := hmac.Equal([]byte(hash), []byte(hexDigest))
	if !check {
		slog.Error("invalid webhook secret")
		return fmt.Errorf("invalid webhook secret")
	}

	return nil
}

func (i *JiraIntegration) Delete(ctx core.Context) error {
	id := ctx.Param("jira_integration_id")

	if id == "" {
		return ctx.JSON(400, map[string]any{
			"message": "Jira integration ID is required",
		})
	}

	// parse the id
	parsedID, err := uuid.Parse(id)
	if err != nil {
		return ctx.JSON(400, map[string]any{
			"message": "Invalid Jira integration ID format",
		})
	}

	err = i.jiraIntegrationRepository.Delete(nil, parsedID)
	if err != nil {
		return err
	}

	return ctx.JSON(200, map[string]any{
		"message": "Jira integration deleted successfully",
	})
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

func (i *JiraIntegration) createADFComment(author string, commentText string, justification string) jira.ADF {

	adfComment := jira.ADF{
		Version: 1,
		Type:    "doc",
		Content: []jira.ADFContent{},
	}

	if author != "" && commentText != "" {
		adfComment.Content = append(adfComment.Content, jira.ADFContent{
			Type: "paragraph",
			Content: []jira.ADFContent{
				{
					Type: "text",
					Text: fmt.Sprintf("%s %s:", author, commentText),
				},
			},
		})

	}

	if justification != "" {
		adfComment.Content = append(adfComment.Content, jira.ADFContent{
			Type: "paragraph",
			Content: []jira.ADFContent{
				{
					Type: "text",
					Text: justification,
				},
			},
		})
	}

	return adfComment

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

func jiraTicketIDToProjectIDAndIssueID(id string) (string, string, error) {
	parts := strings.Split(id, ":")
	if len(parts) != 3 {
		return "", "", fmt.Errorf("invalid Jira ticket ID format: %s", id)
	}
	if parts[0] != "jira" {
		return "", "", fmt.Errorf("invalid Jira ticket ID prefix: %s", parts[0])
	}
	return parts[1], parts[2], nil
}

func extractIntegrationIDFromRepoID(repoID string) (uuid.UUID, error) {
	return uuid.Parse(strings.Split(repoID, ":")[1])
}

func extractProjectIDFromRepoID(repoID string) (int, error) {
	return strconv.Atoi(strings.Split(repoID, ":")[2])
}

func (i *JiraIntegration) getClientBasedOnAsset(asset models.Asset) (*jira.Client, int, error) {
	if asset.RepositoryID == nil || !strings.HasPrefix(*asset.RepositoryID, "jira:") {
		return nil, 0, fmt.Errorf("asset %s is not a Jira repository", asset.ID)
	}

	integrationUUID, err := extractIntegrationIDFromRepoID(*asset.RepositoryID)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to extract integration id from repo id: %w", err)
	}

	jiraIntegration, err := i.jiraIntegrationRepository.GetClientByIntegrationID(integrationUUID)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get Jira client for integration %s: %w", integrationUUID, err)
	}

	projectID, err := extractProjectIDFromRepoID(*asset.RepositoryID)
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

	return client, projectID, nil
}

func (i *JiraIntegration) createDependencyVulnIssue(ctx context.Context, dependencyVuln *models.DependencyVuln, asset models.Asset, client *jira.Client, assetVersionName string, justification string, orgSlug string, projectSlug string, projectID int) (*jira.CreateIssueResponse, error) {

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

	description := exp.GenerateADF(i.frontendURL, orgSlug, projectSlug, assetSlug, assetVersionName, componentTree)

	issue := &jira.Issue{
		Fields: &jira.IssueFields{
			Project: jira.Project{
				ID: strconv.Itoa(projectID),
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
		slog.Error("failed to create Jira issue", "err", err)
		return nil, fmt.Errorf("failed to create Jira issue: %w", err)
	}

	_, _, err = client.CreateIssueComment(ctx, createdIssue.ID, strconv.Itoa(projectID), i.createADFComment("", "", justification))
	if err != nil {
		slog.Error("failed to create Jira issue comment", "err", err, "issue", createdIssue)
		return nil, fmt.Errorf("failed to create Jira issue comment: %w", err)
	}

	return createdIssue, nil
}

func (i *JiraIntegration) createFirstPartyVulnIssue(ctx context.Context, firstPartyVuln *models.FirstPartyVuln, asset models.Asset, client *jira.Client, assetVersionName string, justification string, orgSlug string, projectSlug string, projectID int) (*jira.CreateIssueResponse, error) {

	labels := commonint.GetLabels(firstPartyVuln)

	jiraClient, _, err := i.getClientBasedOnAsset(asset)
	if err != nil {
		return nil, fmt.Errorf("failed to get Jira integration for client %s: %w", client.JiraIntegrationID, err)
	}
	jiraIntegration, err := i.jiraIntegrationRepository.GetClientByIntegrationID(jiraClient.JiraIntegrationID)
	if err != nil {
		return nil, fmt.Errorf("failed to get Jira integration for client %s: %w", client.JiraIntegrationID, err)
	}

	description := firstPartyVuln.RenderADF()
	summary := firstPartyVuln.Title()

	issue := &jira.Issue{
		Fields: &jira.IssueFields{
			Project: jira.Project{
				ID: strconv.Itoa(projectID),
			},
			Type: jira.IssueType{
				Name: "Task",
			},
			Reporter: &jira.User{
				AccountID: jiraIntegration.AccountID,
			},
			Description: description,
			Labels:      labels,
			Summary:     summary,
		},
	}

	createdIssue, _, err := client.CreateIssue(ctx, issue)
	if err != nil {
		slog.Error("failed to create Jira issue", "err", err, "issue", issue)
		return nil, fmt.Errorf("failed to create Jira issue: %w", err)
	}

	_, _, err = client.CreateIssueComment(ctx, createdIssue.ID, strconv.Itoa(projectID), i.createADFComment("", "", justification))
	if err != nil {
		slog.Error("failed to create Jira issue comment", "err", err, "issue", createdIssue)
		return nil, fmt.Errorf("failed to create Jira issue comment: %w", err)
	}

	return createdIssue, nil
}

func (i *JiraIntegration) CreateIssue(ctx context.Context, asset models.Asset, assetVersionName string, vuln models.Vuln, projectSlug string, orgSlug string, justification string, userID string) error {
	repoID := utils.SafeDereference(asset.RepositoryID)
	if !strings.HasPrefix(repoID, "jira:") {
		return fmt.Errorf("asset %s is not a Jira repository", asset.ID)
	}

	client, projectID, err := i.getClientBasedOnAsset(asset)
	if err != nil {
		return fmt.Errorf("failed to get Jira client for asset %s: %w", asset.ID, err)
	}
	var createdIssue *jira.CreateIssueResponse

	switch v := vuln.(type) {
	case *models.DependencyVuln:
		createdIssue, err = i.createDependencyVulnIssue(ctx, v, asset, client, assetVersionName, justification, orgSlug, projectSlug, projectID)
		if err != nil {
			return err
		}
	case *models.FirstPartyVuln:
		createdIssue, err = i.createFirstPartyVulnIssue(ctx, v, asset, client, assetVersionName, justification, orgSlug, projectSlug, projectID)
		if err != nil {
			return err
		}
	}

	vuln.SetTicketID(fmt.Sprintf("jira:%d:%s", projectID, createdIssue.GetID()))
	vuln.SetTicketURL(fmt.Sprintf("%s/browse/%s", client.BaseURL, createdIssue.Key))
	vuln.SetManualTicketCreation(userID != "system")

	vulnEvent := models.NewMitigateEvent(
		vuln.GetID(),
		vuln.GetType(),
		userID,
		justification,
		map[string]any{
			"ticketID": vuln.GetTicketID(),
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

func getOpenAndDoneStatusIDs(transitions []jira.Transition) (openStatusID, doneStatusID string, err error) {

	openIDs := []struct {
		ID  string
		Key string
	}{}
	doneIDs := []struct {
		ID  string
		Key string
	}{}
	var openID string
	var doneID string

	for _, transition := range transitions {
		if transition.To.StatusCategory.ID == jira.StatusCategoryToDo {
			openIDs = append(openIDs, struct {
				ID  string
				Key string
			}{
				ID:  transition.ID,
				Key: transition.To.StatusCategory.Key,
			})
		}
		if transition.To.StatusCategory.ID == jira.StatusCategoryDone {
			doneIDs = append(doneIDs, struct {
				ID  string
				Key string
			}{
				ID:  transition.ID,
				Key: transition.To.StatusCategory.Key,
			})
		}
	}

	if len(openIDs) == 0 {
		return "", "", fmt.Errorf("no open status found in Jira transitions")
	}
	if len(doneIDs) == 0 {
		return "", "", fmt.Errorf("no done status found in Jira transitions")
	}

	openID = openIDs[0].ID
	doneID = doneIDs[0].ID

	if len(openIDs) > 1 {
		for _, oid := range openIDs {
			if oid.Key == "Open" || oid.Key == "To Do" {
				openID = oid.ID
				break
			}
		}
	}

	if len(doneIDs) > 1 {
		for _, d := range doneIDs {
			if d.Key == "Done" || d.Key == "Closed" {
				doneID = d.ID
				break
			}
		}
	}

	return openID, doneID, nil

}

func (i *JiraIntegration) UpdateIssue(ctx context.Context, asset models.Asset, vuln models.Vuln) error {
	repoID := utils.SafeDereference(asset.RepositoryID)
	if !strings.HasPrefix(repoID, "jira:") {
		return fmt.Errorf("asset %s is not a Jira repository", asset.ID)
	}

	client, _, err := i.getClientBasedOnAsset(asset)
	if err != nil {
		return fmt.Errorf("failed to get Jira client for asset %s: %w", asset.ID, err)
	}

	project, err := i.projectRepository.GetProjectByAssetID(asset.ID)
	if err != nil {
		slog.Error("could not get project by asset id", "err", err)
		return err
	}

	org, err := i.orgRepository.Read(project.OrganizationID)
	if err != nil {
		slog.Error("could not get org by id", "err", err)
		return err
	}

	switch v := vuln.(type) {
	case *models.DependencyVuln:
		err = i.updateDependencyVulnTicket(ctx, v, asset, client, vuln.GetAssetVersionName(), org.Slug, project.Slug)
	case *models.FirstPartyVuln:
		err = i.updateFirstPartyVulnTicket(ctx, v, asset, client, vuln.GetAssetVersionName(), org.Slug, project.Slug)
	}

	if err != nil {
		//check if err is 404 - if so, we can not reopen the issue
		if err.Error() == "404 Not Found" {
			// we can not reopen the issue - it is deleted
			vulnEvent := models.NewFalsePositiveEvent(vuln.GetID(), vuln.GetType(), "system", "This Vulnerability is marked as a false positive due to deletion", models.VulnerableCodeNotInExecutePath, vuln.GetScannerIDs())
			// save the event
			err = i.aggregatedVulnRepository.ApplyAndSave(nil, vuln, &vulnEvent)
			if err != nil {
				slog.Error("could not save dependencyVuln and event", "err", err)
			}
			return nil
		}
		return err
	}

	return nil
}

func (i *JiraIntegration) updateIssueState(ctx context.Context, expectedIssueState vuln.ExpectedIssueState, client *jira.Client, vulnTicketID *string) error {

	doUpdateStatus := false

	_, ticketID, err := jiraTicketIDToProjectIDAndIssueID(utils.SafeDereference(vulnTicketID))
	if err != nil {
		slog.Error("failed to parse Jira ticket ID", "err", err, "ticketID", utils.SafeDereference(vulnTicketID))
		return fmt.Errorf("failed to parse Jira ticket ID: %w", err)
	}

	issue, err := client.GetIssue(ctx, ticketID)
	if err != nil {
		slog.Error("failed to get Jira issue", "err", err, "ticketID", ticketID)
		return fmt.Errorf("failed to get Jira issue: %w", err)
	}
	issueStatusID := issue.Fields.Status.StatusCategory.ID

	//get open and done statusIDs from the Jira
	transitions, err := client.GetTransitions(ctx, ticketID)
	if err != nil {
		slog.Error("failed to get Jira transitions", "err", err, "ticketID", ticketID)
		return fmt.Errorf("failed to get Jira transitions: %w", err)
	}

	openStatusID, doneStatusID, err := getOpenAndDoneStatusIDs(transitions)
	if err != nil {
		slog.Error("failed to get open and done status IDs from Jira transitions", "err", err, "ticketID", ticketID)
		return fmt.Errorf("failed to get open and done status IDs from Jira transitions: %w", err)
	}

	var stateID string

	if issueStatusID == jira.StatusCategoryToDo || issueStatusID == jira.StatusCategoryInProgress {
		if expectedIssueState != vuln.ExpectedIssueStateOpen {
			doUpdateStatus = true
			stateID = doneStatusID
		}
	}
	if issueStatusID == jira.StatusCategoryDone {
		if expectedIssueState != vuln.ExpectedIssueStateClosed {
			doUpdateStatus = true
			stateID = openStatusID
		}
	}

	if !doUpdateStatus {
		slog.Info("Jira issue is already in the expected state", "issueID", ticketID, "status", issue.Fields.Status.Name)
		return nil
	}

	// set the status of the issue
	err = client.TransitionIssue(ctx, ticketID, stateID)
	if err != nil {
		slog.Error("failed to get Jira transition by name", "err", err, "state", stateID, "ticketID", ticketID)
		return fmt.Errorf("failed to get Jira transition by name: %w", err)
	}

	slog.Info("Jira issue status updated", "issueID", ticketID, "status", stateID)

	return nil
}

func (i *JiraIntegration) updateDependencyVulnTicket(ctx context.Context, dependencyVuln *models.DependencyVuln, asset models.Asset, client *jira.Client, assetVersionName string, orgSlug string, projectSlug string) error {
	riskMetrics, vector := risk.RiskCalculation(*dependencyVuln.CVE, core.GetEnvironmentalFromAsset(asset))

	exp := risk.Explain(*dependencyVuln, asset, vector, riskMetrics)

	componentTree, err := commonint.RenderPathToComponent(i.componentRepository, asset.ID, dependencyVuln.AssetVersionName, dependencyVuln.ScannerIDs, exp.ComponentPurl)
	if err != nil {
		return err
	}

	jiraProjectID, ticketID, err := jiraTicketIDToProjectIDAndIssueID(utils.SafeDereference(dependencyVuln.GetTicketID()))
	if err != nil {
		slog.Error("failed to parse Jira ticket ID", "err", err, "ticketID", utils.SafeDereference(dependencyVuln.GetTicketID()))
		return fmt.Errorf("failed to parse Jira ticket ID: %w", err)
	}

	jiraClient, _, err := i.getClientBasedOnAsset(asset)
	if err != nil {
		return fmt.Errorf("failed to get Jira integration for client %s: %w", client.JiraIntegrationID, err)
	}
	jiraIntegration, err := i.jiraIntegrationRepository.GetClientByIntegrationID(jiraClient.JiraIntegrationID)
	if err != nil {
		return fmt.Errorf("failed to get Jira integration for client %s: %w", client.JiraIntegrationID, err)
	}

	//edit issue
	issue := &jira.Issue{
		ID: ticketID,
		Fields: &jira.IssueFields{
			Project: jira.Project{
				ID: jiraProjectID,
			},
			Type: jira.IssueType{
				Name: "Task",
			},
			Reporter: &jira.User{
				AccountID: jiraIntegration.AccountID,
			},
			Description: exp.GenerateADF(i.frontendURL, orgSlug, projectSlug, asset.Slug, assetVersionName, componentTree),
			Summary:     fmt.Sprintf("%s found in %s", utils.SafeDereference(dependencyVuln.CVEID), utils.RemovePrefixInsensitive(utils.SafeDereference(dependencyVuln.ComponentPurl), "pkg:")),
		},
	}

	riskSeverity, err := risk.RiskToSeverity(*dependencyVuln.RawRiskAssessment)
	if err != nil {
		slog.Error("failed to convert risk assessment to severity", "err", err, "vuln", dependencyVuln)
		return fmt.Errorf("failed to convert risk assessment to severity: %w", err)
	}
	if riskSeverity == "Critical" || riskSeverity == "High" {
		issue.Fields.Priority = &jira.Priority{
			ID: "1",
		}
	}

	err = client.EditIssue(ctx, issue)
	if err != nil {
		slog.Error("failed to edit Jira issue", "err", err, "issue", issue)
		return fmt.Errorf("failed to edit Jira issue: %w", err)
	}

	expectedIssueState := vuln.GetExpectedIssueState(asset, dependencyVuln)

	err = i.updateIssueState(ctx, expectedIssueState, client, dependencyVuln.GetTicketID())
	if err != nil {
		slog.Error("failed to update Jira issue state", "err", err, "ticketID", ticketID)
		return fmt.Errorf("failed to update Jira issue state: %w", err)
	}

	slog.Info("Jira issue updated successfully", "issueID", ticketID, "projectID", jiraProjectID)

	return nil
}

func (i *JiraIntegration) updateFirstPartyVulnTicket(ctx context.Context, firstPartyVuln *models.FirstPartyVuln, asset models.Asset, client *jira.Client, assetVersionName string, orgSlug string, projectSlug string) error {

	jiraProjectID, ticketID, err := jiraTicketIDToProjectIDAndIssueID(utils.SafeDereference(firstPartyVuln.GetTicketID()))
	if err != nil {
		slog.Error("failed to parse Jira ticket ID", "err", err, "ticketID", utils.SafeDereference(firstPartyVuln.GetTicketID()))
		return fmt.Errorf("failed to parse Jira ticket ID: %w", err)
	}
	jiraClient, _, err := i.getClientBasedOnAsset(asset)
	if err != nil {
		return fmt.Errorf("failed to get Jira integration for client %s: %w", client.JiraIntegrationID, err)
	}
	jiraIntegration, err := i.jiraIntegrationRepository.GetClientByIntegrationID(jiraClient.JiraIntegrationID)
	if err != nil {
		return fmt.Errorf("failed to get Jira integration for client %s: %w", client.JiraIntegrationID, err)
	}

	//edit issue
	issue := &jira.Issue{
		ID: ticketID,
		Fields: &jira.IssueFields{
			Project: jira.Project{
				ID: jiraProjectID,
			},
			Type: jira.IssueType{
				Name: "Task",
			},
			Reporter: &jira.User{
				AccountID: jiraIntegration.AccountID,
			},
			Description: firstPartyVuln.RenderADF(),
			Summary:     firstPartyVuln.Title(),
		},
	}

	err = client.EditIssue(ctx, issue)
	if err != nil {
		slog.Error("failed to edit Jira issue", "err", err, "issue", issue)
		return fmt.Errorf("failed to edit Jira issue: %w", err)
	}

	expectedIssueState := vuln.GetExpectedIssueStateForFirstPartyVuln(asset, firstPartyVuln)

	err = i.updateIssueState(ctx, expectedIssueState, client, firstPartyVuln.GetTicketID())
	if err != nil {
		slog.Error("failed to update Jira issue state", "err", err, "ticketID", ticketID)
		return fmt.Errorf("failed to update Jira issue state: %w", err)
	}

	return nil
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
		URL       string `json:"url"`
		Token     string `json:"token"`
		Name      string `json:"name"`
		UserEmail string `json:"userEmail"`
	}

	if err := ctx.Bind(&data); err != nil {
		return ctx.JSON(400, "invalid request data")
	}
	if data.URL == "" || data.Token == "" || data.UserEmail == "" {
		return ctx.JSON(400, "url, token and userEmail are required")
	}
	jiraIntegration := &models.JiraIntegration{
		URL:         data.URL,
		AccessToken: data.Token,
		Name:        data.Name,
		UserEmail:   data.UserEmail,
		OrgID:       (core.GetOrg(ctx).GetID()),
	}

	// check if the token valid and get the account ID
	client, err := jira.NewJiraClient(data.Token, data.URL, data.UserEmail)
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
