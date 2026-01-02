// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package jiraint

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/integrations/commonint"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/statemachine"
)

func (i *JiraIntegration) HandleWebhook(ctx shared.Context) error {
	req := ctx.Request()
	if req.Method != "POST" {
		return ctx.JSON(405, "Method Not Allowed")
	}

	payload, err := io.ReadAll(req.Body)
	if err != nil {
		return ctx.JSON(400, "Invalid request body")
	}

	defer req.Body.Close()
	event, err := ParseWebhook(payload)
	if err != nil {
		return nil
	}

	// Currently, we only handle "comment created" events (without IssueEventType)
	// and status changes on the issue (IssueEventType = "issue_generic").
	// "issue_updated" events are ignored because creating a comment also triggers an "issue_updated" event.
	if event.IssueEventType == "issue_updated" {
		return nil
	}

	var vulnEvent models.VulnEvent
	var vuln models.Vuln
	var issueID string
	var projectID string

	doUpdateArtifactRiskHistory := false

	issueID = event.Issue.ID
	projectID = event.Issue.Fields.Project.ID

	vuln, err = i.aggregatedVulnRepository.FindByTicketID(nil, fmt.Sprintf("jira:%s:%s", projectID, issueID))
	if err != nil {
		slog.Error("failed to find vulnerability by ticket ID", "err", err, "ticketID", fmt.Sprintf("jira:%s:%s", projectID, issueID))
		return nil
	}

	sig := req.Header.Get("X-Hub-Signature")
	err = i.CheckWebhookSecretToken(sig, payload, vuln.GetAssetID())
	if err != nil {
		slog.Error("failed to check webhook secret token", "err", err, "ticketID", fmt.Sprintf("jira:%s:%s", projectID, issueID))
		return ctx.JSON(403, fmt.Sprintf("Forbidden: %v", err))
	}

	userID := ""
	username := ""
	userAvatarURL := ""
	if event.User != nil {
		userID = fmt.Sprintf("jira:%s", event.User.AccountID)
		username = event.User.DisplayName
		userAvatarURL = event.User.AvatarUrls.Two4X24
	} else if event.Comment != nil && event.Comment.Author != nil {
		userID = fmt.Sprintf("jira:%s", event.Comment.Author.AccountID)
		username = event.Comment.Author.DisplayName
		userAvatarURL = event.Comment.Author.AvatarUrls.Two4X24
	} else {
		slog.Error("no user information found in Jira webhook event")

	}
	// make sure to save the user - it might be a new user or it might have new values defined.
	// we do not care about any error - and we want speed, thus do it on a goroutine
	i.FireAndForget(func() {
		org, err := i.aggregatedVulnRepository.GetOrgFromVuln(vuln)
		if err != nil {
			slog.Error("could not get org from dependencyVuln id", "err", err)
			return
		}
		// save the user in the database
		user := models.ExternalUser{
			ID:        fmt.Sprintf("jira:%s", userID),
			Username:  username,
			AvatarURL: userAvatarURL,
		}

		err = i.externalUserRepository.Save(nil, &user)
		if err != nil {
			slog.Error("could not save github user", "err", err)
			return
		}

		if err = i.externalUserRepository.GetDB(nil).Model(&user).Association("Organizations").Append([]models.Org{org}); err != nil {
			slog.Error("could not append user to organization", "err", err)
		}
	})

	statusCategory := event.Issue.Fields.Status.StatusCategory.ID

	switch event.Event {
	case CommentCreated:
		// Handle comment created event

		//check if the event is triggered by a DevGuard
		if strings.Contains(event.Comment.Body, DevguardCommentText) {
			return nil
		}

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
		vulnEvent := commonint.CreateNewVulnEventBasedOnComment(vuln.GetID(), vuln.GetType(), fmt.Sprintf("jira:%s", userID), comment, vuln.GetScannerIDsOrArtifactNames())
		statemachine.Apply(vuln, vulnEvent)

		// save the vuln and the event in a transaction
		err = i.aggregatedVulnRepository.Transaction(func(tx shared.DB) error {
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

		if vulnEvent.Type == dtos.EventTypeAccepted || vulnEvent.Type == dtos.EventTypeFalsePositive || vulnEvent.Type == dtos.EventTypeReopened {
			doUpdateArtifactRiskHistory = true
		}

		err = i.UpdateIssue(ctx.Request().Context(), asset, assetVersion.Slug, vuln)

		if err != nil {
			slog.Error("could not update issue", "err", err)
			return err
		}

	case EventIssueUpdated:

		// Handle issue updated event
		switch statusCategory {
		case StatusCategoryDone:
			if vuln.GetState() != dtos.VulnStateOpen {
				return nil
			}
			vulnEvent = models.NewAcceptedEvent(vuln.GetID(), vuln.GetType(), fmt.Sprintf("jira:%s", userID), fmt.Sprintf("This Vulnerability is marked as accepted by %s, due to closing of the jira ticket.", username), dtos.UpstreamStateInternal)

			err = i.aggregatedVulnRepository.ApplyAndSave(nil, vuln, &vulnEvent)
			if err != nil {
				slog.Error("could not save dependencyVuln and event", "err", err)
			}
			doUpdateArtifactRiskHistory = true
		case StatusCategoryToDo, StatusCategoryInProgress:
			if vuln.GetState() == dtos.VulnStateOpen {
				return nil
			}
			vulnEvent = models.NewReopenedEvent(vuln.GetID(), vuln.GetType(), fmt.Sprintf("jira:%s", userID), fmt.Sprintf("This Vulnerability was reopened by %s", username), dtos.UpstreamStateInternal)

			err := i.aggregatedVulnRepository.ApplyAndSave(nil, vuln, &vulnEvent)
			if err != nil {
				slog.Error("could not save dependencyVuln and event", "err", err)
			}
			doUpdateArtifactRiskHistory = true

		}
	case EventIssueDeleted:
		if vuln.GetState() == dtos.VulnStateFalsePositive {
			return nil
		}
		vulnEvent := models.NewFalsePositiveEvent(vuln.GetID(), vuln.GetType(), fmt.Sprintf("jira:%s", userID), fmt.Sprintf("This Vulnerability is marked as a false positive by %s, due to the deletion of the jira ticket.", username), dtos.VulnerableCodeNotInExecutePath, vuln.GetScannerIDsOrArtifactNames(), dtos.UpstreamStateInternal)

		err := i.aggregatedVulnRepository.ApplyAndSave(nil, vuln, &vulnEvent)
		if err != nil {
			slog.Error("could not save vuln and event", "err", err)
		}
		doUpdateArtifactRiskHistory = true
	}

	if doUpdateArtifactRiskHistory {
		for _, artifact := range vuln.GetArtifacts() {
			if err := i.statisticsService.UpdateArtifactRiskAggregation(&artifact, vuln.GetAssetID(), time.Now(), time.Now()); err != nil {
				slog.Error("could not recalculate risk history", "err", err)
			}
		}
	}
	return nil
}
