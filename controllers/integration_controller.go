// Copyright (C) 2024 Tim Bastin, l3montree GmbH
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

package controllers

import (
	"log/slog"

	"github.com/l3montree-dev/devguard/integrations/githubint"
	"github.com/l3montree-dev/devguard/integrations/gitlabint"
	"github.com/l3montree-dev/devguard/integrations/jiraint"
	"github.com/l3montree-dev/devguard/shared"
)

type integrationController struct {
	gitlabOauth2Integration map[string]*gitlabint.GitlabOauth2Config
}

func NewIntegrationController(gitlabOauth2Integration map[string]*gitlabint.GitlabOauth2Config) *integrationController {
	return &integrationController{
		gitlabOauth2Integration: gitlabOauth2Integration,
	}

}

func (c *integrationController) AutoSetup(ctx shared.Context) error {
	thirdPartyIntegration := shared.GetThirdPartyIntegration(ctx)
	gl := thirdPartyIntegration.GetIntegration(shared.GitLabIntegrationID)
	if gl != nil {
		return gl.(*gitlabint.GitlabIntegration).AutoSetup(ctx)
	}

	return nil
}

func (c *integrationController) ListRepositories(ctx shared.Context) error {
	thirdPartyIntegration := shared.GetThirdPartyIntegration(ctx)

	repos, err := thirdPartyIntegration.ListRepositories(ctx)
	if err != nil {
		return ctx.JSON(500, "could not list repositories")
	}

	return ctx.JSON(200, repos)
}

func (c *integrationController) FinishInstallation(ctx shared.Context) error {
	thirdPartyIntegration := shared.GetThirdPartyIntegration(ctx)
	gh := thirdPartyIntegration.GetIntegration(shared.GitHubIntegrationID)
	if gh != nil {
		if err := gh.(*githubint.GithubIntegration).FinishInstallation(ctx); err != nil {
			slog.Error("could not finish installation", "err", err)
			return err
		}
	}

	return ctx.JSON(200, "Installation finished")
}

func (c *integrationController) HandleWebhook(ctx shared.Context) error {
	thirdPartyIntegration := shared.GetThirdPartyIntegration(ctx)
	if err := thirdPartyIntegration.HandleWebhook(ctx); err != nil {
		slog.Error("could not handle webhook", "err", err)
		return err
	}

	return ctx.JSON(200, "Webhook handled")
}

func (c *integrationController) TestAndSaveGitlabIntegration(ctx shared.Context) error {
	thirdPartyIntegration := shared.GetThirdPartyIntegration(ctx)
	gl := thirdPartyIntegration.GetIntegration(shared.GitLabIntegrationID)
	if gl == nil {
		return ctx.JSON(404, "GitLab integration not enabled")
	}

	if err := gl.(*gitlabint.GitlabIntegration).TestAndSave(ctx); err != nil {
		slog.Error("could not test GitLab integration", "err", err)
		return err
	}

	return nil
}

func (c *integrationController) TestAndSaveJiraIntegration(ctx shared.Context) error {
	thirdPartyIntegration := shared.GetThirdPartyIntegration(ctx)
	gl := thirdPartyIntegration.GetIntegration(shared.JiraIntegrationID)
	if gl == nil {
		return ctx.JSON(404, "Jira integration not enabled")
	}

	if err := gl.(*jiraint.JiraIntegration).TestAndSave(ctx); err != nil {
		slog.Error("could not test GitLab integration", "err", err)
		return err
	}

	return nil
}

func (c *integrationController) GitLabOauth2Callback(ctx shared.Context) error {
	integrationName := shared.GetParam(ctx, "integrationName")
	if integrationName == "" {
		return ctx.JSON(400, "integrationName is missing")
	}

	oauth2Integration := c.gitlabOauth2Integration[integrationName]
	if oauth2Integration == nil {
		return ctx.JSON(404, "GitLab integration not found")
	}

	if err := oauth2Integration.Oauth2Callback(ctx); err != nil {
		slog.Error("could not handle GitLab oauth2 callback", "err", err)
		return err
	}
	return nil
}

func (c *integrationController) GitLabOauth2Login(ctx shared.Context) error {
	integrationName := shared.GetParam(ctx, "integrationName")
	if integrationName == "" {
		return ctx.JSON(400, "integrationName is missing")
	}

	oauth2Integration := c.gitlabOauth2Integration[integrationName]
	if oauth2Integration == nil {
		return ctx.JSON(404, "GitLab integration not found")
	}

	if err := oauth2Integration.Oauth2Login(ctx); err != nil {
		slog.Error("could not handle GitLab oauth2 login", "err", err)
		return err
	}
	return nil
}

func (c *integrationController) DeleteGitLabAccessToken(ctx shared.Context) error {
	thirdPartyIntegration := shared.GetThirdPartyIntegration(ctx)
	gl := thirdPartyIntegration.GetIntegration(shared.GitLabIntegrationID)
	if gl == nil {
		return ctx.JSON(404, "GitLab integration not enabled")
	}

	if err := gl.(*gitlabint.GitlabIntegration).Delete(ctx); err != nil {
		slog.Error("could not delete GitLab integration", "err", err)
		return err
	}

	return nil
}

func (c *integrationController) DeleteJiraAccessToken(ctx shared.Context) error {
	thirdPartyIntegration := shared.GetThirdPartyIntegration(ctx)
	jira := thirdPartyIntegration.GetIntegration(shared.JiraIntegrationID)
	if jira == nil {
		return ctx.JSON(404, "Jira integration not enabled")
	}

	if err := jira.(*jiraint.JiraIntegration).Delete(ctx); err != nil {
		slog.Error("could not delete Jira integration", "err", err)
		return err
	}

	return nil
}
