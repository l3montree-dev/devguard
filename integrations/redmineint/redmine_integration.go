package redmineint

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/integrations/commonint"

	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/l3montree-dev/devguard/vulndb"
)

type redmineRepository struct {
	*Project
	RedmineIntegrationID uuid.UUID `json:"redmineIntegrationID"`
}

func (r *redmineRepository) toRepository() dtos.GitRepository {
	return dtos.GitRepository{
		ID:          fmt.Sprintf("redmine:%s:%s", r.RedmineIntegrationID, strconv.Itoa(r.ID)),
		Label:       r.Name,
		Description: r.Description,
	}
}

type RedmineIntegration struct {
	redmineIntegrationRepository shared.RedmineIntegrationRepository
	aggregatedVulnRepository     shared.VulnRepository
	dependencyVulnRepository     shared.DependencyVulnRepository
	firstPartyVulnRepository     shared.FirstPartyVulnRepository
	orgRepository                shared.OrganizationRepository
	projectRepository            shared.ProjectRepository
	frontendURL                  string
	utils.FireAndForgetSynchronizer
}

var _ shared.ThirdPartyIntegration = &RedmineIntegration{}

func NewRedmineIntegration(redmineIntegrationRepository shared.RedmineIntegrationRepository,
	aggregatedVulnRepository shared.VulnRepository,
	dependencyVulnRepository shared.DependencyVulnRepository,
	firstPartyVulnRepository shared.FirstPartyVulnRepository,
	orgRepository shared.OrganizationRepository,
	projectRepository shared.ProjectRepository,
	synchronizer utils.FireAndForgetSynchronizer) *RedmineIntegration {
	frontendURL := os.Getenv("FRONTEND_URL")
	if frontendURL == "" {
		panic("FRONTEND_URL is not set")
	}

	return &RedmineIntegration{
		redmineIntegrationRepository: redmineIntegrationRepository,
		aggregatedVulnRepository:     aggregatedVulnRepository,
		dependencyVulnRepository:     dependencyVulnRepository,
		firstPartyVulnRepository:     firstPartyVulnRepository,
		projectRepository:            projectRepository,
		orgRepository:                orgRepository,
		frontendURL:                  frontendURL,
		FireAndForgetSynchronizer:    synchronizer,
	}
}

func (i *RedmineIntegration) WantsToHandleWebhook(ctx shared.Context) bool {
	// TODO: Implement webhook handling for Redmine integration
	return false
}

func (i *RedmineIntegration) HandleWebhook(ctx shared.Context) error {
	return nil
}

func (i *RedmineIntegration) CompareIssueStatesAndResolveDifferences(ctx context.Context, asset models.Asset, vulnsWithTickets []models.DependencyVuln) error {
	return nil
}

func (i *RedmineIntegration) GetExcessTicketIDs(ctx context.Context, asset models.Asset, vulnsWithTickets []models.DependencyVuln) ([]string, error) {
	return nil, nil
}

func (i *RedmineIntegration) Delete(ctx shared.Context) error {
	id := ctx.Param("redmine_integration_id")

	if id == "" {
		return ctx.JSON(400, map[string]any{
			"message": "Redmine integration ID is required",
		})
	}

	// parse the id
	parsedID, err := uuid.Parse(id)
	if err != nil {
		return ctx.JSON(400, map[string]any{
			"message": "Invalid Redmine integration ID format",
		})
	}

	err = i.redmineIntegrationRepository.Delete(ctx.Request().Context(), nil, parsedID)
	if err != nil {
		if shared.IsNotFound(err) {
			return ctx.JSON(404, map[string]any{
				"message": "Redmine integration not found",
			})
		}
		return err
	}

	return ctx.JSON(200, map[string]any{
		"message": "Redmine integration deleted successfully",
	})
}

func (i *RedmineIntegration) CreateLabels(ctx context.Context, asset models.Asset) error {
	return nil
}

func (i *RedmineIntegration) ListOrgs(ctx shared.Context) ([]models.Org, error) {
	// Redmine integration does not have organizations in the same way as GitLab or GitHub
	return nil, fmt.Errorf("Redmine integration does not support listing organizations")
}
func (i *RedmineIntegration) ListGroups(ctx context.Context, userID string, providerID string) ([]models.Project, []shared.Role, error) {
	// Redmine integration does not have groups in the same way as GitLab or GitHub
	return nil, nil, fmt.Errorf("Redmine integration does not support listing groups")
}
func (i *RedmineIntegration) ListProjects(ctx context.Context, userID string, providerID string, groupID string) ([]models.Asset, []shared.Role, error) {
	// Redmine integration does not have projects in the same way as GitLab or GitHub
	return nil, nil, fmt.Errorf("Redmine integration does not support listing projects")
}
func (i *RedmineIntegration) ListRepositories(ctx shared.Context) ([]dtos.GitRepository, error) {

	if !shared.HasOrganization(ctx) {
		return nil, fmt.Errorf("organization is required to list repositories")
	}

	org := shared.GetOrg(ctx)

	repos := []dtos.GitRepository{}

	if org.RedmineIntegrations != nil {
		slog.Info("found Redmine integration for organization", "orgID", org.GetID(), "integrationCount", len(org.RedmineIntegrations))
		redmineClient, err := NewRedmineBatchClient(i.redmineIntegrationRepository, org.RedmineIntegrations)
		if err != nil {
			return nil, fmt.Errorf("failed to create Redmine client: %w", err)
		}

		// get the repos
		r, err := redmineClient.ListRepositories(ctx.QueryParam("search"))
		slog.Info("listing repositories for Redmine integration", "orgID", org.GetID(), "reposCount", len(r), "err", err)
		if err != nil {
			return nil, fmt.Errorf("failed to get repositories from Redmine: %w", err)
		}

		repos = append(repos, utils.Map(r, func(repo redmineRepository) dtos.GitRepository {
			return repo.toRepository()
		})...)
		return repos, nil
	}
	slog.Warn("no Redmine integration found for organization", "orgID", org.GetID())
	return nil, fmt.Errorf("no Redmine integration found for organization %s", org.GetID())

}

func redmineTicketIDToIssueID(id string) (int, error) {
	parts := strings.Split(id, ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid Redmine ticket ID format: %s", id)
	}
	if parts[0] != "redmine" {
		return 0, fmt.Errorf("invalid Redmine ticket ID prefix: %s", parts[0])
	}

	return strconv.Atoi(parts[1])
}

func extractIntegrationIDFromRepoID(repoID string) (uuid.UUID, error) {
	return uuid.Parse(strings.Split(repoID, ":")[1])
}

func extractProjectIDFromRepoID(repoID string) (int, error) {
	slog.Info("extracting project ID from repo ID", "repoID", repoID)
	return strconv.Atoi(strings.Split(repoID, ":")[2])
}

func (i *RedmineIntegration) getClientBasedOnAsset(ctx context.Context, asset models.Asset) (*Client, int, error) {
	if asset.RepositoryID == nil || !strings.HasPrefix(*asset.RepositoryID, "redmine:") {
		return nil, 0, fmt.Errorf("asset %s is not a Redmine repository", asset.ID)
	}

	integrationUUID, err := extractIntegrationIDFromRepoID(*asset.RepositoryID)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to extract integration id from repo id: %w", err)
	}

	client, err := i.getClientBasedOnIntegrationID(ctx, integrationUUID)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get Redmine client based on integration ID: %w", err)
	}

	projectID, err := extractProjectIDFromRepoID(*asset.RepositoryID)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to extract project id from repo id: %w", err)
	}

	return client, projectID, nil
}

func (i *RedmineIntegration) getClientBasedOnIntegrationID(ctx context.Context, integrationUUID uuid.UUID) (*Client, error) {
	redmineIntegration, err := i.redmineIntegrationRepository.GetClientByIntegrationID(ctx, nil, integrationUUID)
	if err != nil {
		return nil, fmt.Errorf("%w: integration %s: %v", commonint.ErrNotConnected, integrationUUID, err)
	}

	client, err := NewRedmineClient(
		redmineIntegration.AccessToken,
		redmineIntegration.URL,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Redmine client from integration %s: %w", integrationUUID, err)
	}

	client.SetRedmineIntegrationID(integrationUUID)

	return client, nil
}

func (i *RedmineIntegration) createDependencyVulnIssue(ctx context.Context, dependencyVuln *models.DependencyVuln, asset models.Asset, client *Client, assetVersionName string, justification string, orgSlug string, projectSlug string, projectID int) (*Issue, error) {

	riskMetrics, vector := vulndb.RiskCalculation(dependencyVuln.CVE, asset.Environmental)
	exp := vulndb.Explain(*dependencyVuln, asset, vector, riskMetrics)
	assetSlug := asset.Slug
	settings, err := i.redmineIntegrationRepository.Read(ctx, nil, client.RedmineIntegrationID)
	if err != nil {
		slog.Error("failed to read Redmine integration settings", "err", err, "integrationID", client.RedmineIntegrationID)
		return nil, fmt.Errorf("failed to read Redmine integration settings: %w", err)
	}
	priority := riskToPriorityID(settings, *dependencyVuln.RiskAssessment)

	componentTree := FormatComponentTree(settings, dependencyVuln)

	issue := &IssueCreateOptions{
		ProjectID:   projectID,
		Subject:     new(fmt.Sprintf("%s found in %s", dependencyVuln.CVEID, utils.RemovePrefixInsensitive(dependencyVuln.ComponentPurl, "pkg:"))),
		Description: new(Markdown(exp, i.frontendURL, orgSlug, projectSlug, assetSlug, assetVersionName, componentTree)),
		StatusID:    settings.DefaultStatusID,
		TrackerID:   settings.TrackerID,
		PriorityID:  priority,
	}

	createdIssue, err := client.CreateIssue(ctx, issue)
	if err != nil {
		slog.Error("failed to create Redmine issue", "err", err)
		return nil, fmt.Errorf("failed to create Redmine issue: %w", err)
	}

	err = client.EditIssue(ctx, createdIssue.ID, &IssueEditOptions{Notes: GenerateComment("", "", justification)})
	if err != nil {
		slog.Error("failed to create Redmine issue comment", "err", err, "issue", createdIssue)
		return nil, fmt.Errorf("failed to create Redmine issue comment: %w", err)
	}

	return createdIssue, nil
}

func (i *RedmineIntegration) createLicenseRiskIssue(ctx context.Context, licenseRisk *models.LicenseRisk, asset models.Asset, client *Client, assetVersionSlug, justification, orgSlug, projectSlug string, projectID int) (*Issue, error) {
	settings, err := i.redmineIntegrationRepository.Read(ctx, nil, client.RedmineIntegrationID)
	if err != nil {
		slog.Error("failed to read Redmine integration settings", "err", err, "integrationID", client.RedmineIntegrationID)
		return nil, fmt.Errorf("failed to read Redmine integration settings: %w", err)
	}

	issue := &IssueCreateOptions{
		ProjectID:   projectID,
		Subject:     new(licenseRisk.Title()),
		Description: new(commonint.RenderMarkdownForLicenseRisk(*licenseRisk, i.frontendURL, orgSlug, projectSlug, asset.Slug, assetVersionSlug)),
		StatusID:    settings.DefaultStatusID,
		TrackerID:   settings.TrackerID,
	}

	createdIssue, err := client.CreateIssue(ctx, issue)
	if err != nil {
		slog.Error("failed to create Redmine issue", "err", err, "issue", issue)
		return nil, fmt.Errorf("failed to create Redmine issue: %w", err)
	}

	err = client.EditIssue(ctx, createdIssue.ID, &IssueEditOptions{Notes: GenerateComment("", "", justification)})
	if err != nil {
		slog.Error("failed to create Redmine issue comment", "err", err, "issue", createdIssue)
		return nil, fmt.Errorf("failed to create Redmine issue comment: %w", err)
	}

	return createdIssue, nil
}

func (i *RedmineIntegration) createFirstPartyVulnIssue(ctx context.Context, firstPartyVuln *models.FirstPartyVuln, asset models.Asset, client *Client, assetVersionSlug string, justification string, orgSlug string, projectSlug string, projectID int) (*Issue, error) {
	settings, err := i.redmineIntegrationRepository.Read(ctx, nil, client.RedmineIntegrationID)
	if err != nil {
		slog.Error("failed to read Redmine integration settings", "err", err, "integrationID", client.RedmineIntegrationID)
		return nil, fmt.Errorf("failed to read Redmine integration settings: %w", err)
	}

	issue := &IssueCreateOptions{
		ProjectID:   projectID,
		Subject:     new(firstPartyVuln.Title()),
		Description: new(commonint.RenderMarkdownForFirstPartyVuln(*firstPartyVuln, i.frontendURL, orgSlug, projectSlug, asset.Slug, assetVersionSlug)),
		StatusID:    settings.DefaultStatusID,
		TrackerID:   settings.TrackerID,
	}

	createdIssue, err := client.CreateIssue(ctx, issue)
	if err != nil {
		slog.Error("failed to create Redmine issue", "err", err, "issue", issue)
		return nil, fmt.Errorf("failed to create Redmine issue: %w", err)
	}

	err = client.EditIssue(ctx, createdIssue.ID, &IssueEditOptions{Notes: GenerateComment("", "", justification)})
	if err != nil {
		slog.Error("failed to create Redmine issue comment", "err", err, "issue", createdIssue)
		return nil, fmt.Errorf("failed to create Redmine issue comment: %w", err)
	}

	return createdIssue, nil
}

func (i *RedmineIntegration) CreateIssue(ctx context.Context, asset models.Asset, assetVersionSlug string, vuln models.Vuln, projectSlug string, orgSlug string, justification string, userID string, userAgent *string) error {
	repoID := utils.SafeDereference(asset.RepositoryID)
	if !strings.HasPrefix(repoID, "redmine:") {
		return nil
	}

	client, projectID, err := i.getClientBasedOnAsset(ctx, asset)
	if err != nil {
		return fmt.Errorf("failed to get Redmine client for asset %s: %w", asset.ID, err)
	}
	var createdIssue *Issue

	switch v := vuln.(type) {
	case *models.DependencyVuln:
		createdIssue, err = i.createDependencyVulnIssue(ctx, v, asset, client, assetVersionSlug, justification, orgSlug, projectSlug, projectID)
		if err != nil {
			return err
		}
	case *models.FirstPartyVuln:
		createdIssue, err = i.createFirstPartyVulnIssue(ctx, v, asset, client, assetVersionSlug, justification, orgSlug, projectSlug, projectID)
		if err != nil {
			return err
		}
	case *models.LicenseRisk:
		createdIssue, err = i.createLicenseRiskIssue(ctx, v, asset, client, assetVersionSlug, justification, orgSlug, projectSlug, projectID)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported vulnerability type: %T", v)
	}

	vuln.SetTicketID(fmt.Sprintf("redmine:%d", createdIssue.ID))
	vuln.SetTicketURL(fmt.Sprintf("%s/issues/%d", client.BaseURL, createdIssue.ID))
	vuln.SetManualTicketCreation(userID != "system")

	slog.Info("created redmine ticket", "assetID", asset.ID, "vulnID", vuln.GetID(), "ticketURL", fmt.Sprintf("%s/issues/%d", client.BaseURL, createdIssue.ID))

	vulnEvent := models.NewMitigateEvent(
		vuln.GetID(),
		vuln.GetType(),
		userID,
		justification,
		userAgent)

	err = i.aggregatedVulnRepository.ApplyAndSave(ctx, nil, vuln, &vulnEvent)
	if err != nil {
		slog.Error("failed to save vulnerability with ticket information", "err", err, "vuln", vuln)
		//TODO: if error did happen, we should remove the issue from Redmine
		return fmt.Errorf("failed to save vulnerability with ticket information: %w", err)
	}

	return nil
}

func (i *RedmineIntegration) UpdateIssue(ctx context.Context, asset models.Asset, assetVersionSlug string, vuln models.Vuln, userAgent *string) error {
	repoID := utils.SafeDereference(asset.RepositoryID)
	if !strings.HasPrefix(repoID, "redmine:") {
		return nil
	}

	client, _, err := i.getClientBasedOnAsset(ctx, asset)
	if err != nil {
		return fmt.Errorf("failed to get Redmine client for asset %s: %w", asset.ID, err)
	}

	project, err := i.projectRepository.GetProjectByAssetID(ctx, nil, asset.ID)
	if err != nil {
		slog.Error("could not get project by asset id", "err", err)
		return err
	}

	org, err := i.orgRepository.Read(ctx, nil, project.OrganizationID)
	if err != nil {
		slog.Error("could not get org by id", "err", err)
		return err
	}

	switch v := vuln.(type) {
	case *models.DependencyVuln:
		err = i.updateDependencyVulnTicket(ctx, v, asset, client, assetVersionSlug, org.Slug, project.Slug)
	case *models.FirstPartyVuln:
		err = i.updateFirstPartyVulnTicket(ctx, v, asset, client, assetVersionSlug, org.Slug, project.Slug)
	}

	if err != nil {
		//check if err is 404 - if so, we can not reopen the issue
		if err.Error() == `failed to create issue comment, status code: 404, response: {"errorMessages":["Issue does not exist or you do not have permission to see it."],"errors":{}}` {
			// we can not reopen the issue - it is deleted
			vulnEvent := models.NewFalsePositiveEvent(vuln.GetID(), vuln.GetType(), "system", "This Vulnerability is marked as a false positive due to deletion", dtos.VulnerableCodeNotInExecutePath, false, userAgent)
			// save the event
			err = i.aggregatedVulnRepository.ApplyAndSave(ctx, nil, vuln, &vulnEvent)
			if err != nil {
				slog.Error("could not save dependencyVuln and event", "err", err)
			}
			return nil
		}
		return err
	}

	return nil
}

func (i *RedmineIntegration) updateDependencyVulnTicket(
	ctx context.Context,
	dependencyVuln *models.DependencyVuln,
	asset models.Asset,
	client *Client,
	assetVersionSlug string,
	orgSlug string,
	projectSlug string,
) error {
	riskMetrics, vector := vulndb.RiskCalculation(dependencyVuln.CVE, asset.Environmental)

	exp := vulndb.Explain(*dependencyVuln, asset, vector, riskMetrics)

	ticketID, err := redmineTicketIDToIssueID(utils.SafeDereference(dependencyVuln.GetTicketID()))
	if err != nil {
		slog.Error("failed to parse Redmine ticket ID", "err", err, "ticketID", utils.SafeDereference(dependencyVuln.GetTicketID()))
		return fmt.Errorf("failed to parse Redmine ticket ID: %w", err)
	}

	settings, err := i.redmineIntegrationRepository.Read(ctx, nil, client.RedmineIntegrationID)
	if err != nil {
		slog.Error("failed to read Redmine integration settings", "err", err, "integrationID", client.RedmineIntegrationID)
		return fmt.Errorf("failed to read Redmine integration settings: %w", err)
	}

	assetSlug := asset.Slug
	expectedIssueState := expectedIssueStateToId(settings, commonint.GetExpectedIssueState(asset, dependencyVuln))
	priority := riskToPriorityID(settings, *dependencyVuln.RiskAssessment)
	componentTree := FormatComponentTree(settings, dependencyVuln)

	issue := &IssueEditOptions{
		Subject:     new(fmt.Sprintf("%s found in %s", dependencyVuln.CVEID, utils.RemovePrefixInsensitive(dependencyVuln.ComponentPurl, "pkg:"))),
		Description: new(Markdown(exp, i.frontendURL, orgSlug, projectSlug, assetSlug, assetVersionSlug, componentTree)),
		StatusID:    expectedIssueState,
		PriorityID:  priority,
	}

	slog.Info("updating redmine ticket", "assetID", asset.ID, "vulnID", dependencyVuln.ID, "ticketURL", utils.SafeDereference(dependencyVuln.TicketURL), "expectedState", string(*expectedIssueState))

	err = client.EditIssue(ctx, ticketID, issue)
	if err != nil {
		slog.Error("failed to edit Redmine issue", "err", err, "issue", issue)
		return fmt.Errorf("failed to edit Redmine issue: %w", err)
	}

	return nil
}

func (i *RedmineIntegration) updateFirstPartyVulnTicket(ctx context.Context, firstPartyVuln *models.FirstPartyVuln, asset models.Asset, client *Client, assetVersionSlug string, orgSlug string, projectSlug string) error {

	ticketID, err := redmineTicketIDToIssueID(utils.SafeDereference(firstPartyVuln.GetTicketID()))
	if err != nil {
		slog.Error("failed to parse Redmine ticket ID", "err", err, "ticketID", utils.SafeDereference(firstPartyVuln.GetTicketID()))
		return fmt.Errorf("failed to parse Redmine ticket ID: %w", err)
	}

	settings, err := i.redmineIntegrationRepository.Read(ctx, nil, client.RedmineIntegrationID)
	if err != nil {
		slog.Error("failed to read Redmine integration settings", "err", err, "integrationID", client.RedmineIntegrationID)
		return fmt.Errorf("failed to read Redmine integration settings: %w", err)
	}

	expectedIssueState := expectedIssueStateToId(settings, commonint.GetExpectedIssueStateForFirstPartyVuln(asset, firstPartyVuln))

	issue := &IssueEditOptions{
		Subject:     new(firstPartyVuln.Title()),
		Description: new(commonint.RenderMarkdownForFirstPartyVuln(*firstPartyVuln, i.frontendURL, orgSlug, projectSlug, asset.Slug, assetVersionSlug)),
		StatusID:    expectedIssueState,
	}

	err = client.EditIssue(ctx, ticketID, issue)
	if err != nil {
		slog.Error("failed to edit Redmine issue", "err", err, "issue", issue)
		return fmt.Errorf("failed to edit Redmine issue: %w", err)
	}

	return nil
}

func (i *RedmineIntegration) GetUsers(org models.Org) []dtos.User {
	// Redmine integration does not have users in the same way as GitLab or GitHub
	return nil
}
func (i *RedmineIntegration) GetID() shared.IntegrationID {
	return shared.RedmineIntegrationID
}

func (i *RedmineIntegration) TestAndSave(ctx shared.Context) error {
	var data struct {
		URL     string `json:"url"`
		Token   string `json:"token"`
		Name    string `json:"name"`
		Tracker string `json:"tracker"`
	}

	if err := ctx.Bind(&data); err != nil {
		return ctx.JSON(400, "invalid request data")
	}
	if data.URL == "" || data.Token == "" {
		return ctx.JSON(400, "url and token are required")
	}
	redmineIntegration := &models.RedmineIntegration{
		URL:         data.URL,
		AccessToken: data.Token,
		Name:        data.Name,
		OrgID:       (shared.GetOrg(ctx).GetID()),
	}

	// check if the token valid and get the account ID
	client, err := NewRedmineClient(data.Token, data.URL)
	if err != nil {
		slog.Error("failed to create Redmine client", "err", err)
		return ctx.JSON(400, fmt.Sprintf("invalid Redmine integration data: %v", err))
	}

	trackers, err := client.FetchIssueTrackers(ctx.Request().Context())
	if err != nil {
		slog.Error("failed to fetch trackers from Redmine", "err", err)
		return ctx.JSON(400, fmt.Sprintf("failed to fetch trackers from Redmine: %v", err))
	}

	var tracker *Tracker
	for _, t := range trackers {
		if t.Name == data.Tracker || strconv.Itoa(t.ID) == data.Tracker {
			tracker = t
			break
		}
	}
	if tracker == nil {
		return ctx.JSON(400, fmt.Sprintf("tracker %s not found in Redmine", data.Tracker))
	}
	redmineIntegration.TrackerID = tracker.ID

	if err := i.redmineIntegrationRepository.Save(context.Background(), nil, redmineIntegration); err != nil {
		return err
	}
	return ctx.JSON(200, transformer.ObfuscateRedmineIntegrations(*redmineIntegration))
}

func (i *RedmineIntegration) GetIntegrationProperties(ctx shared.Context) error {
	integrationID := ctx.Param("redmineIntegrationID")
	integrationUUID, err := uuid.Parse(integrationID)
	if err != nil {
		slog.Error("invalid Redmine integration ID", "err", err, "integrationID", integrationID)
		return ctx.JSON(400, fmt.Sprintf("invalid Redmine integration ID: %v", err))
	}

	client, err := i.getClientBasedOnIntegrationID(ctx.Request().Context(), integrationUUID)
	if err != nil {
		slog.Error("failed to get Redmine client", "err", err)
		return ctx.JSON(400, fmt.Sprintf("failed to get Redmine client: %v", err))
	}

	trackers, err := client.FetchIssueTrackers(ctx.Request().Context())
	if err != nil {
		slog.Error("failed to fetch trackers from Redmine", "err", err)
		return ctx.JSON(400, fmt.Sprintf("failed to fetch trackers from Redmine: %v", err))
	}
	statuses, err := client.FetchIssueStatuses(ctx.Request().Context())
	if err != nil {
		slog.Error("failed to fetch statuses from Redmine", "err", err)
		return ctx.JSON(400, fmt.Sprintf("failed to fetch statuses from Redmine: %v", err))
	}
	priorities, err := client.FetchIssuePriorities(ctx.Request().Context())
	if err != nil {
		slog.Error("failed to fetch priorities from Redmine", "err", err)
		return ctx.JSON(400, fmt.Sprintf("failed to fetch priorities from Redmine: %v", err))
	}

	trackersDTO := utils.Map(trackers, func(t *Tracker) dtos.RedmineTracker {
		return dtos.RedmineTracker{
			ID:   t.ID,
			Name: t.Name,
		}
	})
	statusesDTO := transform(statuses, func(s *Status) dtos.RedmineStatus {
		return dtos.RedmineStatus{
			ID:   s.ID,
			Name: s.Name,
		}
	})
	prioritiesDTO := transform(priorities, func(p *Priority) dtos.RedminePriority {
		return dtos.RedminePriority{
			ID:   p.ID,
			Name: p.Name,
		}
	})

	return ctx.JSON(200, &dtos.RedmineIntegrationProperties{
		Trackers:   trackersDTO,
		Statuses:   statusesDTO,
		Priorities: prioritiesDTO,
	})
}

func (i *RedmineIntegration) UpdateIntegrationSettings(ctx shared.Context) error {
	integrationID := ctx.Param("redmineIntegrationID")
	integrationUUID, err := uuid.Parse(integrationID)
	if err != nil {
		slog.Error("invalid Redmine integration ID", "err", err, "integrationID", integrationID)
		return ctx.JSON(400, fmt.Sprintf("invalid Redmine integration ID: %v", err))
	}

	integration, err := i.redmineIntegrationRepository.Read(ctx.Request().Context(), nil, integrationUUID)
	if err != nil {
		slog.Error("failed to get Redmine integration", "err", err, "integrationID", integrationUUID)
		return ctx.JSON(400, fmt.Sprintf("failed to get Redmine integration: %v", err))
	}

	var data struct {
		TrackerID          int    `json:"tracker"`
		DefaultStatusID    *int   `json:"defaultStatus"`
		CloseStatusID      *int   `json:"closeStatus"`
		LowPriorityID      *int   `json:"lowPriority"`
		MediumPriorityID   *int   `json:"mediumPriority"`
		HighPriorityID     *int   `json:"highPriority"`
		CriticalPriorityID *int   `json:"criticalPriority"`
		MermaidIntegration string `json:"mermaidIntegration"`
	}

	if err := ctx.Bind(&data); err != nil {
		return ctx.JSON(400, "invalid request data")
	}

	integration.TrackerID = data.TrackerID
	integration.DefaultStatusID = data.DefaultStatusID
	integration.CloseStatusID = data.CloseStatusID
	integration.LowPriorityID = data.LowPriorityID
	integration.MediumPriorityID = data.MediumPriorityID
	integration.HighPriorityID = data.HighPriorityID
	integration.CriticalPriorityID = data.CriticalPriorityID
	if data.MermaidIntegration != "none" && data.MermaidIntegration != "macro" && data.MermaidIntegration != "commonmark" {
		return ctx.JSON(400, "invalid mermaidIntegration value")
	}
	integration.MermaidIntegration = models.MermaidIntegrationType(data.MermaidIntegration)

	if err := i.redmineIntegrationRepository.Save(ctx.Request().Context(), nil, &integration); err != nil {
		slog.Error("failed to save Redmine integration", "err", err)
		return ctx.JSON(400, fmt.Sprintf("failed to save Redmine integration: %v", err))
	}

	return ctx.JSON(200, transformer.ObfuscateRedmineIntegrations(integration))
}

func expectedIssueStateToId(settings models.RedmineIntegration, state commonint.ExpectedIssueState) *int {
	switch state {
	case commonint.ExpectedIssueStateClosed:
		return settings.CloseStatusID
	default:
		return settings.DefaultStatusID
	}
}

func riskToPriorityID(settings models.RedmineIntegration, risk float64) *int {
	switch {
	case risk < 4:
		return settings.LowPriorityID
	case risk < 7:
		return settings.MediumPriorityID
	case risk < 9:
		return settings.HighPriorityID
	default:
		return settings.CriticalPriorityID
	}
}

func transform[T, V any](ts []T, fn func(T) V) []V {
	result := make([]V, len(ts))
	for i, t := range ts {
		result[i] = fn(t)
	}
	return result
}
