package redmineint

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
)

func (i *RedmineIntegration) HandleEvent(ctx context.Context, event any, userAgent *string) error {
	switch event := event.(type) {
	case shared.ManualMitigateEvent:
		asset := shared.GetAsset(event.Ctx)

		// An asset with no repository configured at all is not an error here -
		// it just means this integration doesn't apply, same as a non-redmine repo.
		repoID, err := shared.GetRepositoryID(&asset)
		if err != nil || !strings.HasPrefix(repoID, "redmine:") {
			return nil
		}

		vulnID, vulnType, err := shared.GetVulnID(event.Ctx)

		if err != nil {
			return err
		}

		var vuln models.Vuln
		switch vulnType {
		case dtos.VulnTypeDependencyVuln:
			// we have a dependency vuln
			v, err := i.dependencyVulnRepository.Read(ctx, nil, vulnID)
			if err != nil {
				return err
			}
			vuln = &v
		case dtos.VulnTypeFirstPartyVuln:
			v, err := i.firstPartyVulnRepository.Read(ctx, nil, vulnID)
			if err != nil {
				return err
			}
			vuln = &v
		}

		return i.createIssueFromEvent(event.Ctx, asset, vuln, event.Justification, userAgent)
	case shared.VulnEvent:
		ev := event.Event

		asset := shared.GetAsset(event.Ctx)
		assetVersionSlug := shared.GetAssetVersion(event.Ctx).Slug
		vulnType := ev.GetVulnType()
		vulnID := ev.GetVulnID()

		var vuln models.Vuln
		switch vulnType {
		case dtos.VulnTypeLicenseRisk:
			return nil
		case dtos.VulnTypeDependencyVuln:
			v, err := i.dependencyVulnRepository.Read(ctx, nil, vulnID)
			if err != nil {
				return err
			}
			vuln = &v
		case dtos.VulnTypeFirstPartyVuln:
			v, err := i.firstPartyVulnRepository.Read(ctx, nil, vulnID)
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
		if !strings.HasPrefix(repoID, "redmine:") || !strings.HasPrefix(*vuln.GetTicketID(), "redmine:") {
			// this integration only handles redmine repositories.
			return nil
		}

		members, err := shared.FetchMembersOfOrganization(event.Ctx)
		if err != nil {
			return err
		}

		// find the member which created the event
		member, ok := utils.Find(
			members,
			func(member dtos.User) bool {
				return member.ID == ev.UserID
			},
		)
		if !ok {
			member = dtos.User{
				Name: "unknown",
			}
		}

		issueID, err := redmineTicketIDToIssueID(utils.SafeDereference(vuln.GetTicketID()))
		if err != nil {
			slog.Error("failed to parse Redmine ticket ID", "err", err, "ticketID", issueID)
			return fmt.Errorf("failed to parse Redmine ticket ID: %w", err)
		}

		var comments string
		switch ev.Type {
		case dtos.EventTypeAccepted:
			comments = GenerateComment(member.Name, "accepted the vulnerability", utils.SafeDereference(ev.Justification))
		case dtos.EventTypeFalsePositive:
			comments = GenerateComment(member.Name, "marked the vulnerability as false positive", utils.SafeDereference(ev.Justification))
		case dtos.EventTypeReopened:
			comments = GenerateComment(member.Name, "reopened the vulnerability", utils.SafeDereference(ev.Justification))
			err := i.createIssueFromEvent(event.Ctx, asset, vuln, utils.SafeDereference(ev.Justification), userAgent)
			if err != nil {
				slog.Error("failed to recreate issue for reopened vulnerability", "err", err, "vulnID", vuln.GetID())
				return fmt.Errorf("failed to recreate issue for reopened vulnerability: %w", err)
			}
		case dtos.EventTypeComment:
			comments = GenerateComment(member.Name, "commented on DevGuard", utils.SafeDereference(ev.Justification))
		}

		if len(comments) > 0 {
			client, _, err := i.getClientBasedOnAsset(ctx, asset)
			if err != nil {
				return fmt.Errorf("failed to get Redmine client for asset %s: %w", asset.ID, err)
			}

			update := IssueEditOptions{
				Notes: comments,
			}
			err = client.EditIssue(ctx, issueID, &update)
			if err != nil {
				slog.Error("failed to edit issue", "err", err, "issueID", issueID)
				return fmt.Errorf("failed to edit issue: %w", err)
			}
		}

		return i.UpdateIssue(ctx, asset, assetVersionSlug, vuln, userAgent)
	}
	return nil

}

func (i *RedmineIntegration) createIssueFromEvent(ctx shared.Context, asset models.Asset, vuln models.Vuln, justification string, userAgent *string) error {
	assetVersionName := shared.GetAssetVersion(ctx).Name
	projectSlug, err := shared.GetProjectSlug(ctx)
	if err != nil {
		slog.Error("failed to get project slug", "err", err)
		return err
	}
	orgSlug, err := shared.GetOrgSlug(ctx)
	if err != nil {
		slog.Error("failed to get org slug", "err", err)
		return err
	}
	session := shared.GetSession(ctx)

	err = i.CreateIssue(ctx.Request().Context(), asset, assetVersionName, vuln, projectSlug, orgSlug, justification, session.GetActorName(), userAgent)
	return nil
}
