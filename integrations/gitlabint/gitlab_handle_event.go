package gitlabint

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

func (g *GitlabIntegration) HandleEvent(event any) error {
	switch event := event.(type) {
	case shared.ManualMitigateEvent:
		asset := shared.GetAsset(event.Ctx)

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
			v, err := g.dependencyVulnRepository.Read(vulnID)
			if err != nil {
				return err
			}
			vuln = &v
		case dtos.VulnTypeFirstPartyVuln:
			v, err := g.firstPartyVulnRepository.Read(vulnID)
			if err != nil {
				return err
			}
			vuln = &v
		case dtos.VulnTypeLicenseRisk:
			licenseRisk, err := g.licenseRiskRepository.Read(vulnID)
			if err != nil {
				return err
			}
			vuln = &licenseRisk
		}

		orgSlug, err := shared.GetOrgSlug(event.Ctx)
		if err != nil {
			return err
		}

		session := shared.GetSession(event.Ctx)

		//check if we have already created the labels in gitlab, if not create them
		if asset.Metadata == nil {
			asset.Metadata = map[string]any{}
		}
		if asset.Metadata["gitlabLabels"] == nil {
			err = g.CreateLabels(event.Ctx.Request().Context(), asset)
			if err != nil {
				return err
			}
			asset.Metadata["gitlabLabels"] = true
			err = g.assetRepository.Update(nil, &asset)
			if err != nil {
				return err
			}
		}

		return g.CreateIssue(event.Ctx.Request().Context(), asset, assetVersionName, vuln, projectSlug, orgSlug, event.Justification, session.GetUserID())
	case shared.VulnEvent:
		ev := event.Event

		vulnType := ev.VulnType

		var vuln models.Vuln
		switch vulnType {
		case dtos.VulnTypeDependencyVuln:
			v, err := g.dependencyVulnRepository.Read(ev.VulnID)
			if err != nil {
				return err
			}
			vuln = &v
		case dtos.VulnTypeFirstPartyVuln:
			v, err := g.firstPartyVulnRepository.Read(ev.VulnID)
			if err != nil {
				return err
			}
			vuln = &v
		case dtos.VulnTypeLicenseRisk:
			licenseRisk, err := g.licenseRiskRepository.Read(ev.VulnID)
			if err != nil {
				return err
			}
			vuln = &licenseRisk
		}

		asset := shared.GetAsset(event.Ctx)
		assetVersionSlug := shared.GetAssetVersion(event.Ctx).Slug

		if vuln.GetTicketID() == nil {
			// we do not have a ticket id - we do not need to do anything
			return nil
		}

		// we create a new ticket in github
		client, projectID, err := g.GetClientBasedOnAsset(asset)
		if err == notConnectedError {
			return nil
		} else if err != nil {
			return err
		}

		// connected to gitlab
		gitlabTicketID := strings.TrimPrefix(*vuln.GetTicketID(), "gitlab:")
		gitlabTicketIDInt, err := strconv.Atoi(strings.Split(gitlabTicketID, "/")[1])
		if err != nil {
			return err
		}

		members, err := shared.FetchMembersOfOrganization(event.Ctx)
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

		switch ev.Type {
		case dtos.EventTypeAccepted:
			// if a dependencyVuln gets accepted, we close the issue and create a comment with that justification
			_, _, err = client.CreateIssueComment(event.Ctx.Request().Context(), projectID, gitlabTicketIDInt, &gitlab.CreateIssueNoteOptions{
				Body: gitlab.Ptr(fmt.Sprintf("<devguard> %s\n----\n%s", member.Name+" accepted the vulnerability", utils.SafeDereference(ev.Justification))),
			})
			if err != nil {
				return err
			}
		case dtos.EventTypeFalsePositive:
			_, _, err = client.CreateIssueComment(event.Ctx.Request().Context(), projectID, gitlabTicketIDInt, &gitlab.CreateIssueNoteOptions{
				Body: gitlab.Ptr(fmt.Sprintf("<devguard> %s\n----\n%s", member.Name+" marked the vulnerability as false positive", utils.SafeDereference(ev.Justification))),
			})
			if err != nil {
				return err
			}

		case dtos.EventTypeReopened:
			_, _, err = client.CreateIssueComment(event.Ctx.Request().Context(), projectID, gitlabTicketIDInt, &gitlab.CreateIssueNoteOptions{
				Body: gitlab.Ptr(fmt.Sprintf("<devguard> %s\n----\n%s", member.Name+" reopened the vulnerability", utils.SafeDereference(ev.Justification))),
			})
			if err != nil {
				return err
			}

		case dtos.EventTypeComment:
			_, _, err = client.CreateIssueComment(event.Ctx.Request().Context(), projectID, gitlabTicketIDInt, &gitlab.CreateIssueNoteOptions{
				Body: gitlab.Ptr(fmt.Sprintf("<devguard> %s\n \n%s", utils.SafeDereference(ev.Justification), "*Sent from "+member.Name+" using DevGuard*")),
			})
			if err != nil {
				return err
			}
		}
		return g.UpdateIssue(event.Ctx.Request().Context(), asset, assetVersionSlug, vuln)
	}
	return nil
}
