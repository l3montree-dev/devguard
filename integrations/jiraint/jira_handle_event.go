// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package jiraint

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
)

func (i *JiraIntegration) HandleEvent(event any) error {
	switch event := event.(type) {
	case shared.ManualMitigateEvent:
		asset := shared.GetAsset(event.Ctx)

		repoID, err := shared.GetRepositoryID(&asset)
		if err != nil {
			return err
		}
		if !strings.HasPrefix(repoID, "jira:") {
			return nil
		}

		assetVersionName := shared.GetAssetVersion(event.Ctx).Name

		projectSlug, err := shared.GetProjectSlug(event.Ctx)

		if err != nil {
			return err
		}

		vulnID, vulnType, err := shared.GetVulnID(event.Ctx)

		if err != nil {
			return err
		}

		var vuln models.Vuln
		switch vulnType {
		case dtos.VulnTypeDependencyVuln:
			// we have a dependency vuln
			v, err := i.dependencyVulnRepository.Read(vulnID)
			if err != nil {
				return err
			}
			vuln = &v
		case dtos.VulnTypeFirstPartyVuln:
			v, err := i.firstPartyVulnRepository.Read(vulnID)
			if err != nil {
				return err
			}
			vuln = &v
		}

		orgSlug, err := shared.GetOrgSlug(event.Ctx)
		if err != nil {
			return err
		}

		session := shared.GetSession(event.Ctx)

		return i.CreateIssue(event.Ctx.Request().Context(), asset, assetVersionName, vuln, projectSlug, orgSlug, event.Justification, session.GetUserID())
	case shared.VulnEvent:
		ev := event.Event

		asset := shared.GetAsset(event.Ctx)
		assetVersionSlug := shared.GetAssetVersion(event.Ctx).Slug
		vulnType := ev.VulnType

		var vuln models.Vuln
		switch vulnType {
		case dtos.VulnTypeLicenseRisk:
			return nil
		case dtos.VulnTypeDependencyVuln:
			v, err := i.dependencyVulnRepository.Read(ev.VulnID)
			if err != nil {
				return err
			}
			vuln = &v
		case dtos.VulnTypeFirstPartyVuln:
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
		repoID := utils.SafeDereference(asset.RepositoryID)
		if !strings.HasPrefix(repoID, "jira:") || !strings.HasPrefix(*vuln.GetTicketID(), "jira:") {
			// this integration only handles github repositories.
			return nil
		}

		client, projectID, err := i.getClientBasedOnAsset(asset)
		if err != nil {
			return fmt.Errorf("failed to get Jira client for asset %s: %w", asset.ID, err)
		}

		members, err := services.FetchMembersOfOrganization(event.Ctx)
		if err != nil {
			return err
		}

		// find the member which created the event
		member, ok := utils.Find(
			members,
			func(member dtos.UserDTO) bool {
				return member.ID == ev.UserID
			},
		)
		if !ok {
			member = dtos.UserDTO{
				Name: "unknown",
			}
		}

		ticketID := utils.SafeDereference(vuln.GetTicketID())
		_, ticketID, err = jiraTicketIDToProjectIDAndIssueID(ticketID)
		if err != nil {
			slog.Error("failed to parse Jira ticket ID", "err", err, "ticketID", ticketID)
			return fmt.Errorf("failed to parse Jira ticket ID: %w", err)
		}

		switch ev.Type {
		case dtos.EventTypeAccepted:
			err = client.CreateIssueComment(
				event.Ctx.Request().Context(),
				ticketID,
				strconv.Itoa(projectID),
				i.createADFComment(member.Name,
					"accepted the vulnerability",
					utils.SafeDereference(ev.Justification)))

			if err != nil {
				slog.Error("failed to create Jira issue comment", "err", err, "issue", vuln.GetTicketID())
				return fmt.Errorf("failed to create Jira issue comment: %w", err)
			}
		case dtos.EventTypeFalsePositive:
			justification := i.createADFComment(member.Name,
				"  marked the vulnerability as false positive",
				utils.SafeDereference(ev.Justification))
			err = client.CreateIssueComment(
				event.Ctx.Request().Context(),
				ticketID,
				strconv.Itoa(projectID),
				justification)
			if err != nil {
				slog.Error("failed to create Jira issue comment", "err", err, "issue", vuln.GetTicketID())
				return fmt.Errorf("failed to create Jira issue comment: %w", err)
			}

		case dtos.EventTypeReopened:
			justification := i.createADFComment(member.Name, " reopened the vulnerability", utils.SafeDereference(ev.Justification))

			err = client.CreateIssueComment(
				event.Ctx.Request().Context(),
				ticketID,
				strconv.Itoa(projectID),
				justification)

			if err != nil {
				if err.Error() == `failed to create issue comment, status code: 404, response: {"errorMessages":["Issue does not exist or you do not have permission to see it."],"errors":{}}` {

					assetVersionName := shared.GetAssetVersion(event.Ctx).Name

					projectSlug, err := shared.GetProjectSlug(event.Ctx)

					if err != nil {
						return err
					}
					orgSlug, err := shared.GetOrgSlug(event.Ctx)
					if err != nil {
						return err
					}

					session := shared.GetSession(event.Ctx)
					err = i.CreateIssue(event.Ctx.Request().Context(), asset, assetVersionName, vuln, projectSlug, orgSlug, utils.SafeDereference(ev.Justification), session.GetUserID())
					if err != nil {
						slog.Error("failed to create Jira issue", "err", err, "issue", vuln.GetTicketID())
						return fmt.Errorf("failed to create Jira issue: %w", err)
					}
				}
				slog.Error("failed to create Jira issue comment", "err", err, "issue", vuln.GetTicketID())
				return fmt.Errorf("failed to create Jira issue comment: %w", err)
			}

		case dtos.EventTypeComment:
			justification := i.createADFComment(utils.SafeDereference(ev.Justification), "", "Sent from "+member.Name+" using DevGuard")

			err = client.CreateIssueComment(
				event.Ctx.Request().Context(),
				ticketID,
				strconv.Itoa(projectID),
				justification)

			if err != nil {

				slog.Error("failed to create Jira issue comment", "err", err, "issue", vuln.GetTicketID())
				/* 				return fmt.Errorf("failed to create Jira issue comment: %w", err) */
			}

		}
		return i.UpdateIssue(context.Background(), asset, assetVersionSlug, vuln)
	}
	return nil

}
