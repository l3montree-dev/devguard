package gitlabint

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/org"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

func (g *GitlabIntegration) HandleEvent(event any) error {
	switch event := event.(type) {
	case core.ManualMitigateEvent:
		asset := core.GetAsset(event.Ctx)
		assetVersionName := core.GetAssetVersion(event.Ctx).Name

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

		return g.CreateIssue(event.Ctx.Request().Context(), asset, assetVersionName, vuln, projectSlug, orgSlug, event.Justification, session.GetUserID())
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

		// we create a new ticket in github
		client, projectId, err := g.getClientBasedOnAsset(asset)
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
				Body: gitlab.Ptr(fmt.Sprintf("<devguard> %s\n----\n%s", member.Name+" accepted the vulnerability", utils.SafeDereference(ev.Justification))),
			})
			if err != nil {
				return err
			}
		case models.EventTypeFalsePositive:
			_, _, err = client.CreateIssueComment(event.Ctx.Request().Context(), projectId, gitlabTicketIDInt, &gitlab.CreateIssueNoteOptions{
				Body: gitlab.Ptr(fmt.Sprintf("<devguard> %s\n----\n%s", member.Name+" marked the vulnerability as false positive", utils.SafeDereference(ev.Justification))),
			})
			if err != nil {
				return err
			}

		case models.EventTypeReopened:
			_, _, err = client.CreateIssueComment(event.Ctx.Request().Context(), projectId, gitlabTicketIDInt, &gitlab.CreateIssueNoteOptions{
				Body: gitlab.Ptr(fmt.Sprintf("<devguard> %s\n----\n%s", member.Name+" reopened the vulnerability", utils.SafeDereference(ev.Justification))),
			})
			if err != nil {
				return err
			}

		case models.EventTypeComment:
			_, _, err = client.CreateIssueComment(event.Ctx.Request().Context(), projectId, gitlabTicketIDInt, &gitlab.CreateIssueNoteOptions{
				Body: gitlab.Ptr(fmt.Sprintf("<devguard> %s\n----\n%s", member.Name+" commented on the vulnerability", utils.SafeDereference(ev.Justification))),
			})
			if err != nil {
				return err
			}
		}
		return g.UpdateIssue(event.Ctx.Request().Context(), asset, vuln)
	}
	return nil
}
