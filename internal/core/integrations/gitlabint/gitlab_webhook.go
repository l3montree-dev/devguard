package gitlabint

import (
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/integrations/commonint"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/pkg/errors"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

func (g *GitlabIntegration) checkWebhookSecretToken(gitlabSecretToken string, assetID uuid.UUID) error {
	asset, err := g.assetRepository.Read(assetID)
	if err != nil {
		slog.Error("could not read asset", "err", err)
		return err
	}

	if asset.WebhookSecret != nil {
		if asset.WebhookSecret.String() != gitlabSecretToken {
			slog.Error("invalid webhook secret")
			return errors.New("invalid webhook secret")
		}
	}

	return nil
}

func (g *GitlabIntegration) HandleWebhook(ctx core.Context) error {

	event, err := parseWebhook(ctx.Request())
	if err != nil {
		slog.Error("could not parse gitlab webhook", "err", err)
		return err
	}

	gitlabSecretToken := ctx.Request().Header.Get("X-Gitlab-Token")

	switch event := event.(type) {
	case *gitlab.IssueEvent:

		issueId := event.ObjectAttributes.IID

		// look for a dependencyVuln with such a github ticket id
		vuln, err := g.aggregatedVulnRepository.FindByTicketID(nil, fmt.Sprintf("gitlab:%d/%d", event.Project.ID, issueId))
		if err != nil {
			slog.Debug("could not find dependencyVuln by ticket id", "err", err, "ticketId", issueId)
			return nil
		}

		err = g.checkWebhookSecretToken(gitlabSecretToken, vuln.GetAssetID())
		if err != nil {
			return err
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

		err = g.checkWebhookSecretToken(gitlabSecretToken, vuln.GetAssetID())
		if err != nil {
			return err
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

		// get the integration id based on the asset
		integrationId, err := extractIntegrationIdFromRepoId(utils.SafeDereference(asset.RepositoryID))
		if err != nil {
			slog.Error("could not extract integration id from repo id", "err", err)
			return err
		}

		// make sure to update the github issue accordingly
		client, err := g.clientFactory.FromIntegrationUUID(integrationId)
		if err != nil {
			slog.Error("could not create github client", "err", err)
			return err
		}

		isAuthorized, err := isGitlabUserAuthorized(event, client)
		if err != nil {
			return err
		}
		//if the user is not authorized we are done here
		if !isAuthorized {
			slog.Info("user not authorized for commands")
			return ctx.JSON(200, "ok")
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
		vulnEvent := commonint.CreateNewVulnEventBasedOnComment(vuln.GetID(), vuln.GetType(), fmt.Sprintf("gitlab:%d", event.User.ID), comment, vuln.GetScannerIDs())

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

		}

		gitlabProjectID := event.ProjectID
		switch vulnEvent.Type {
		case models.EventTypeAccepted, models.EventTypeFalsePositive:
			labels := commonint.GetLabels(vuln)
			_, _, err = client.EditIssue(ctx.Request().Context(), gitlabProjectID, issueId, &gitlab.UpdateIssueOptions{
				StateEvent: gitlab.Ptr("close"),
				Labels:     gitlab.Ptr(gitlab.LabelOptions(labels)),
			})
			return err
		case models.EventTypeReopened:
			labels := commonint.GetLabels(vuln)
			_, _, err = client.EditIssue(ctx.Request().Context(), gitlabProjectID, issueId, &gitlab.UpdateIssueOptions{
				StateEvent: gitlab.Ptr("reopen"),
				Labels:     gitlab.Ptr(gitlab.LabelOptions(labels)),
			})
			return err
		}
	}
	return ctx.JSON(200, "ok")
}
