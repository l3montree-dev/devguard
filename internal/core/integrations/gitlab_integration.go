package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/go-github/v62/github"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/flaw"
	"github.com/l3montree-dev/devguard/internal/core/org"
	"github.com/l3montree-dev/devguard/internal/core/risk"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/obj"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/xanzy/go-gitlab"
)

type gitlabClientFacade interface {
	CreateIssue(ctx context.Context, pid int, opt *gitlab.CreateIssueOptions) (*gitlab.Issue, *gitlab.Response, error)
	CreateIssueComment(ctx context.Context, pid int, issue int, opt *gitlab.CreateIssueNoteOptions) (*gitlab.Note, *gitlab.Response, error)
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

func messageWasCreatedByDevguard(message string) bool {
	var messages = map[string]string{
		"accept":         "accepted the flaw",
		"false-positive": "marked the flaw as false positive",
		"reopen":         "reopened the flaw",
		"comment":        "commented on the flaw",
	}

	if !strings.Contains(message, "----") {
		return false
	}

	// check if one of the messages is in the comment
	for _, m := range messages {
		if strings.Contains(message, m) {
			return true
		}
	}

	return false
}

func NewGitLabIntegration(db core.DB) *gitlabIntegration {
	gitlabIntegrationRepository := repositories.NewGitLabIntegrationRepository(db)
	flawRepository := repositories.NewFlawRepository(db)
	flawEventRepository := repositories.NewFlawEventRepository(db)
	externalUserRepository := repositories.NewExternalUserRepository(db)
	assetRepository := repositories.NewAssetRepository(db)
	cveRepository := repositories.NewCVERepository(db)

	return &gitlabIntegration{
		gitlabIntegrationRepository: gitlabIntegrationRepository,

		flawRepository:         flawRepository,
		flawService:            flaw.NewService(flawRepository, flawEventRepository, assetRepository, cveRepository),
		flawEventRepository:    flawEventRepository,
		assetRepository:        assetRepository,
		externalUserRepository: externalUserRepository,

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
	event, err := parseWebhook(ctx.Request())
	if err != nil {
		slog.Error("could not parse gitlab webhook", "err", err)
		return err
	}

	switch event := event.(type) {
	case *gitlab.IssueCommentEvent:
		// check if the issue is a devguard issue
		issueId := event.Issue.IID

		// check if the user is a bot - we do not want to handle bot comments
		// if event.Comment.User.GetType() == "Bot" {
		// 	return nil
		// }
		// look for a flaw with such a github ticket id
		flaw, err := g.flawRepository.FindByTicketID(nil, fmt.Sprintf("gitlab:%d/%d", event.ProjectID, issueId))
		if err != nil {
			slog.Debug("could not find flaw by ticket id", "err", err, "ticketId", issueId)
			return nil
		}

		comment := event.ObjectAttributes.Note

		if messageWasCreatedByDevguard(comment) {
			return nil
		}

		// make sure to save the user - it might be a new user or it might have new values defined.
		// we do not care about any error - and we want speed, thus do it on a goroutine
		go func() {
			org, err := g.flawRepository.GetOrgFromFlawID(nil, flaw.ID)
			if err != nil {
				slog.Error("could not get org from flaw id", "err", err)
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
		flawEvent := createNewFlawEventBasedOnComment(flaw.ID, fmt.Sprintf("gitlab:%d", event.User.ID), comment)

		flawEvent.Apply(&flaw)
		// save the flaw and the event in a transaction
		err = g.flawRepository.Transaction(func(tx core.DB) error {
			err := g.flawRepository.Save(tx, &flaw)
			if err != nil {
				return err
			}
			err = g.flawEventRepository.Save(tx, &flawEvent)
			if err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			slog.Error("could not save flaw and event", "err", err)
			return err
		}

		// get the asset
		asset, err := g.assetRepository.Read(flaw.AssetID)
		if err != nil {
			slog.Error("could not read asset", "err", err)
			return err
		}
		// get the integration id based on the asset
		integrationId, err := extractIntegrationIdFromRepoId(utils.SafeDereference(asset.RepositoryID))
		if err != nil {
			slog.Error("could not extract integration id from repo id", "err", err)
			return err
		}

		// get the project id based on the asset
		projectId, err := extractProjectIdFromRepoId(utils.SafeDereference(asset.RepositoryID))
		if err != nil {
			slog.Error("could not extract project id from repo id", "err", err)
			return err
		}

		// make sure to update the github issue accordingly
		client, err := g.gitlabClientFactory(integrationId)
		if err != nil {
			slog.Error("could not create github client", "err", err)
			return err
		}

		switch flawEvent.Type {
		case models.EventTypeAccepted:

			labels := []string{
				"devguard",
				"severity:" + strings.ToLower(risk.RiskToSeverity(*flaw.RawRiskAssessment)),
				"state:accepted",
			}

			_, _, err = client.EditIssue(context.Background(), projectId, issueId, &gitlab.UpdateIssueOptions{
				StateEvent: gitlab.Ptr("close"),
				Labels:     gitlab.Ptr(gitlab.LabelOptions(labels)),
			})
			return err
		case models.EventTypeFalsePositive:

			labels := []string{
				"devguard",
				"severity:" + strings.ToLower(risk.RiskToSeverity(*flaw.RawRiskAssessment)),
				"state:false-positive",
			}

			_, _, err = client.EditIssue(context.Background(), projectId, issueId, &gitlab.UpdateIssueOptions{
				StateEvent: gitlab.Ptr("close"),
				Labels:     gitlab.Ptr(gitlab.LabelOptions(labels)),
			})
			return err
		case models.EventTypeReopened:

			labels := []string{
				"devguard",
				"severity:" + strings.ToLower(risk.RiskToSeverity(*flaw.RawRiskAssessment)),
				"state:open",
			}

			_, _, err = client.EditIssue(context.Background(), projectId, issueId, &gitlab.UpdateIssueOptions{
				StateEvent: gitlab.Ptr("reopen"),
				Labels:     gitlab.Ptr(gitlab.LabelOptions(labels)),
			})
			return err
		}
	}

	return ctx.JSON(200, "ok")
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

func (g *gitlabIntegration) HandleEvent(event any) error {
	switch event := event.(type) {
	case core.ManualMitigateEvent:
		asset := core.GetAsset(event.Ctx)
		repoId := utils.SafeDereference(asset.RepositoryID)
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

		flawId, err := core.GetFlawID(event.Ctx)
		if err != nil {
			return err
		}

		flaw, err := g.flawRepository.Read(flawId)
		if err != nil {
			return err
		}

		// we create a new ticket in github
		client, err := g.gitlabClientFactory(integrationUUID)
		if err != nil {
			return err
		}

		riskMetrics, vector := risk.RiskCalculation(*flaw.CVE, core.GetEnvironmentalFromAsset(asset))

		exp := risk.Explain(flaw, asset, vector, riskMetrics)

		// print json stringify to the console
		orgSlug, _ := core.GetOrgSlug(event.Ctx)
		projectSlug, _ := core.GetProjectSlug(event.Ctx)
		assetSlug, _ := core.GetAssetSlug(event.Ctx)

		// read the justification from the body
		var justification map[string]string
		err = json.NewDecoder(event.Ctx.Request().Body).Decode(&justification)
		if err != nil {
			return err
		}

		labels := []string{
			"devguard",
			"severity:" + strings.ToLower(risk.RiskToSeverity(*flaw.RawRiskAssessment)),
		}
		issue := &gitlab.CreateIssueOptions{
			Title:       gitlab.Ptr(fmt.Sprintf("Flaw %s", flaw.CVE.CVE)),
			Description: gitlab.Ptr(exp.Markdown(g.frontendUrl, orgSlug, projectSlug, assetSlug) + "\n\n------\n\n" + justification["comment"]),
			Labels:      gitlab.Ptr(gitlab.LabelOptions(labels)),
		}

		createdIssue, _, err := client.CreateIssue(context.Background(), projectId, issue)
		if err != nil {
			return err
		}

		flaw.TicketID = utils.Ptr(fmt.Sprintf("gitlab:%d/%d", createdIssue.ProjectID, createdIssue.IID))
		flaw.TicketURL = utils.Ptr(createdIssue.WebURL)

		userId := core.GetSession(event.Ctx).GetUserID()
		flawEvent := models.NewMitigateEvent(
			flaw.ID,
			userId,
			justification["comment"],
			map[string]any{
				"ticketId":  *flaw.TicketID,
				"ticketUrl": createdIssue.WebURL,
			})

		return g.flawService.ApplyAndSave(nil, &flaw, &flawEvent)
	case core.FlawEvent:
		ev := event.Event

		asset := core.GetAsset(event.Ctx)
		flaw, err := g.flawRepository.Read(ev.FlawID)

		if err != nil {
			return err
		}

		if flaw.TicketID == nil {
			// we do not have a ticket id - we do not need to do anything
			return nil
		}

		repoId := utils.SafeDereference(asset.RepositoryID)
		if !strings.HasPrefix(repoId, "gitlab:") || !strings.HasPrefix(*flaw.TicketID, "gitlab:") {
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

		gitlabTicketID := strings.TrimPrefix(*flaw.TicketID, "gitlab:")
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
			// if a flaw gets accepted, we close the issue and create a comment with that justification
			_, _, err = client.CreateIssueComment(context.Background(), projectId, gitlabTicketIDInt, &gitlab.CreateIssueNoteOptions{
				Body: github.String(fmt.Sprintf("%s\n----\n%s", member.Name+" accepted the flaw", utils.SafeDereference(ev.Justification))),
			})
			if err != nil {
				return err
			}
			labels := []string{
				"devguard",
				"severity:" + strings.ToLower(risk.RiskToSeverity(*flaw.RawRiskAssessment)),
				"state:accepted",
			}
			_, _, err = client.EditIssue(context.Background(), projectId, gitlabTicketIDInt, &gitlab.UpdateIssueOptions{
				StateEvent: gitlab.Ptr("close"),
				Labels:     gitlab.Ptr(gitlab.LabelOptions(labels)),
			})
			return err
		case models.EventTypeFalsePositive:

			_, _, err = client.CreateIssueComment(context.Background(), projectId, gitlabTicketIDInt, &gitlab.CreateIssueNoteOptions{
				Body: github.String(fmt.Sprintf("%s\n----\n%s", member.Name+" marked the flaw as false positive", utils.SafeDereference(ev.Justification))),
			})
			if err != nil {
				return err
			}

			labels := []string{
				"devguard",
				"severity:" + strings.ToLower(risk.RiskToSeverity(*flaw.RawRiskAssessment)),
				"state:false-positive",
			}
			_, _, err = client.EditIssue(context.Background(), projectId, gitlabTicketIDInt, &gitlab.UpdateIssueOptions{
				StateEvent: gitlab.Ptr("close"),
				Labels:     gitlab.Ptr(gitlab.LabelOptions(labels)),
			})
			return err
		case models.EventTypeReopened:
			_, _, err = client.CreateIssueComment(context.Background(), projectId, gitlabTicketIDInt, &gitlab.CreateIssueNoteOptions{
				Body: github.String(fmt.Sprintf("%s\n----\n%s", member.Name+" reopened the flaw", utils.SafeDereference(ev.Justification))),
			})
			if err != nil {
				return err
			}

			labels := []string{
				"devguard",
				"severity:" + strings.ToLower(risk.RiskToSeverity(*flaw.RawRiskAssessment)),
				"state:open",
			}

			_, _, err = client.EditIssue(context.Background(), projectId, gitlabTicketIDInt, &gitlab.UpdateIssueOptions{
				StateEvent: gitlab.Ptr("reopen"),
				Labels:     gitlab.Ptr(gitlab.LabelOptions(labels)),
			})
			return err

		case models.EventTypeComment:
			_, _, err = client.CreateIssueComment(context.Background(), projectId, gitlabTicketIDInt, &gitlab.CreateIssueNoteOptions{
				Body: github.String(fmt.Sprintf("%s\n----\n%s", member.Name+" commented on the flaw", utils.SafeDereference(ev.Justification))),
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