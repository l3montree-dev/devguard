// Copyright (C) 2024 Tim Bastin, l3montree UG (haftungsbeschränkt)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package integrations

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type integrationController struct {
}

func commentTrimmedFalsePositivePrefix(comment string) (models.VulnEventType, models.MechanicalJustificationType, string) {

	if strings.HasPrefix(comment, "/component-missing") {
		return models.EventTypeFalsePositive, models.ComponentMissing, strings.TrimSpace(strings.TrimPrefix(comment, "/component-missing"))
	} else if strings.HasPrefix(comment, "/code-missing") {
		return models.EventTypeFalsePositive, models.CodeMissing, strings.TrimSpace(strings.TrimPrefix(comment, "/code-missing"))
	} else if strings.HasPrefix(comment, "/code-inaccessible") {
		return models.EventTypeFalsePositive, models.CodeInaccessible, strings.TrimSpace(strings.TrimPrefix(comment, "/code-inaccessible"))
	} else if strings.HasPrefix(comment, "/mitigations-exist") {
		return models.EventTypeFalsePositive, models.MitigationsExist, strings.TrimSpace(strings.TrimPrefix(comment, "/mitigations-exist"))
	} else if strings.HasPrefix(comment, "/code-uncontrollable") {
		return models.EventTypeFalsePositive, models.MitigationsExist, strings.TrimSpace(strings.TrimPrefix(comment, "/code-uncontrollable"))
	} else if strings.HasPrefix(comment, "/accept") {
		return models.EventTypeAccepted, "", strings.TrimSpace(strings.TrimPrefix(comment, "/accept"))
	} else if strings.HasPrefix(comment, "/reopen") {
		return models.EventTypeReopened, "", strings.TrimSpace(strings.TrimPrefix(comment, "/reopen"))
	}
	return models.EventTypeComment, "", comment
}

func createNewVulnEventBasedOnComment(vulnId string, vulnType models.VulnType, userId, comment string, scannerIds string) models.VulnEvent {

	event, mechanicalJustification, justification := commentTrimmedFalsePositivePrefix(comment)

	if event == models.EventTypeAccepted {
		fmt.Println("NEIN accepted")
		return models.NewAcceptedEvent(vulnId, vulnType, userId, justification)
	} else if event == models.EventTypeFalsePositive {
		fmt.Println("ja false positive")
		return models.NewFalsePositiveEvent(vulnId, vulnType, userId, justification, mechanicalJustification, scannerIds)
	} else if event == models.EventTypeReopened {
		return models.NewReopenedEvent(vulnId, vulnType, userId, justification)
	} else if event == models.EventTypeComment {
		return models.NewCommentEvent(vulnId, vulnType, userId, comment)
	}

	return models.VulnEvent{}
}

func NewIntegrationController() *integrationController {
	return &integrationController{}
}

func (c *integrationController) AutoSetup(ctx core.Context) error {
	thirdPartyIntegration := core.GetThirdPartyIntegration(ctx)
	gl := thirdPartyIntegration.GetIntegration(core.GitLabIntegrationID)
	if gl != nil {
		return gl.(*gitlabIntegration).AutoSetup(ctx)
	}

	return nil
}

func (c *integrationController) ListRepositories(ctx core.Context) error {
	thirdPartyIntegration := core.GetThirdPartyIntegration(ctx)

	if !thirdPartyIntegration.IntegrationEnabled(ctx) {
		return ctx.JSON(404, "no integration enabled")
	}

	repos, err := thirdPartyIntegration.ListRepositories(ctx)
	if err != nil {
		return ctx.JSON(500, "could not list repositories")
	}

	return ctx.JSON(200, repos)
}

func (c *integrationController) FinishInstallation(ctx core.Context) error {
	thirdPartyIntegration := core.GetThirdPartyIntegration(ctx)
	gh := thirdPartyIntegration.GetIntegration(core.GitHubIntegrationID)
	if gh != nil {
		if err := gh.(*githubIntegration).FinishInstallation(ctx); err != nil {
			slog.Error("could not finish installation", "err", err)
			return err
		}
	}

	return ctx.JSON(200, "Installation finished")
}

func (c *integrationController) HandleWebhook(ctx core.Context) error {
	thirdPartyIntegration := core.GetThirdPartyIntegration(ctx)
	if err := thirdPartyIntegration.HandleWebhook(ctx); err != nil {
		slog.Error("could not handle webhook", "err", err)
		return err
	}

	return ctx.JSON(200, "Webhook handled")
}

func (c *integrationController) TestAndSaveGitLabIntegration(ctx core.Context) error {
	thirdPartyIntegration := core.GetThirdPartyIntegration(ctx)
	gl := thirdPartyIntegration.GetIntegration(core.GitLabIntegrationID)
	if gl == nil {
		return ctx.JSON(404, "GitLab integration not enabled")
	}

	if err := gl.(*gitlabIntegration).TestAndSave(ctx); err != nil {
		slog.Error("could not test GitLab integration", "err", err)
		return err
	}

	return nil
}

func (c *integrationController) DeleteGitLabAccessToken(ctx core.Context) error {
	thirdPartyIntegration := core.GetThirdPartyIntegration(ctx)
	gl := thirdPartyIntegration.GetIntegration(core.GitLabIntegrationID)
	if gl == nil {
		return ctx.JSON(404, "GitLab integration not enabled")
	}

	if err := gl.(*gitlabIntegration).Delete(ctx); err != nil {
		slog.Error("could not delete GitLab integration", "err", err)
		return err
	}

	return nil
}
