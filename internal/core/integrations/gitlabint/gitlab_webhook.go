package gitlabint

import (
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/integrations/commonint"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/pkg/errors"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

func (g *GitlabIntegration) checkWebhookSecretToken(gitlabSecretToken string, assetID uuid.UUID) error {
	asset, err := g.assetRepository.Read(assetID)
	if err != nil {
		slog.Error("could not read asset", "err", err)
		return err
	}

	if asset.WebhookSecret == nil {
		slog.Error("webhook secret is not set for asset", "assetID", asset.ID)
		return errors.New("webhook secret is not set for asset")
	}

	if asset.WebhookSecret.String() != gitlabSecretToken {
		slog.Error("invalid webhook secret")
		return errors.New("invalid webhook secret")
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

	var vulnEvent models.VulnEvent
	var client core.GitlabClientFacade
	var vuln models.Vuln
	var issueID int
	var projectID int

	switch event := event.(type) {
	case *gitlab.IssueEvent:
		// the even was triggered by devguard - the user which triggered the event is the same as the author of the issue
		// WE only want to handle tickets created by devguard right here.
		// thus, if the event user id is the same it HAS to be devguard as well.
		if event.User.ID == event.ObjectAttributes.AuthorID {
			slog.Debug("ignoring gitlab issue event created by devguard", "userID", event.User.ID, "authorId", event.ObjectAttributes.AuthorID)
			return nil
		}

		issueID = event.ObjectAttributes.IID
		projectID = event.Project.ID

		// look for a dependencyVuln with such a github ticket id
		vuln, err = g.aggregatedVulnRepository.FindByTicketID(nil, fmt.Sprintf("gitlab:%d/%d", event.Project.ID, issueID))
		if err != nil {
			slog.Debug("could not find dependencyVuln by ticket id", "err", err, "ticketID", issueID)
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

			vulnEvent = models.NewAcceptedEvent(vuln.GetID(), vuln.GetType(), fmt.Sprintf("gitlab:%d", event.User.ID), fmt.Sprintf("This Vulnerability is marked as accepted by %s, due to closing of the gitlab ticket.", event.User.Name))

			err = g.aggregatedVulnRepository.ApplyAndSave(nil, vuln, &vulnEvent)
			if err != nil {
				slog.Error("could not save vuln and event", "err", err)
			}

		case "reopen":
			if vuln.GetState() == models.VulnStateOpen || vuln.GetState() == models.VulnStateFixed {
				return nil
			}

			vulnEvent = models.NewReopenedEvent(vuln.GetID(), vuln.GetType(), fmt.Sprintf("gitlab:%d", event.User.ID), fmt.Sprintf("This Vulnerability is marked as accepted by %s, due to closing of the gitlab ticket.", event.User.Name))

			err := g.aggregatedVulnRepository.ApplyAndSave(nil, vuln, &vulnEvent)
			if err != nil {
				slog.Error("could not save vuln and event", "err", err)

			}
		}
		asset, err := g.assetRepository.Read(vuln.GetAssetID())
		if err != nil {
			slog.Error("could not read asset", "err", err)
			return err
		}
		client, _, err = g.getClientBasedOnAsset(asset)
		if err != nil {
			slog.Error("could not get gitlab client based on asset", "err", err)
			return err
		}

	case *gitlab.IssueCommentEvent:
		// check if the issue is a devguard issue
		issueID = event.Issue.IID
		projectID = event.ProjectID
		// look for a dependencyVuln with such a github ticket id
		vuln, err = g.aggregatedVulnRepository.FindByTicketID(nil, fmt.Sprintf("gitlab:%d/%d", event.ProjectID, issueID))
		if err != nil {
			slog.Debug("could not find dependencyVuln by ticket id", "err", err, "ticketID", issueID)
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

		client, _, err = g.getClientBasedOnAsset(asset)
		if err != nil {
			slog.Error("could not get gitlab client based on asset", "err", err)
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
		vulnEvent = commonint.CreateNewVulnEventBasedOnComment(vuln.GetID(), vuln.GetType(), fmt.Sprintf("gitlab:%d", event.User.ID), comment, vuln.GetScannerIDs())

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
	}
	switch vulnEvent.Type {
	case models.EventTypeAccepted, models.EventTypeFalsePositive:
		labels := commonint.GetLabels(vuln)
		_, _, err = client.EditIssue(ctx.Request().Context(), projectID, issueID, &gitlab.UpdateIssueOptions{
			StateEvent: gitlab.Ptr("close"),
			Labels:     gitlab.Ptr(gitlab.LabelOptions(labels)),
		})
		return err
	case models.EventTypeReopened:
		labels := commonint.GetLabels(vuln)
		_, _, err = client.EditIssue(ctx.Request().Context(), projectID, issueID, &gitlab.UpdateIssueOptions{
			StateEvent: gitlab.Ptr("reopen"),
			Labels:     gitlab.Ptr(gitlab.LabelOptions(labels)),
		})
		return err

	}
	return ctx.JSON(200, "ok")
}
