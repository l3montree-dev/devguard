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
	"log/slog"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/integrations/githubint"
	"github.com/l3montree-dev/devguard/internal/core/integrations/gitlabint"
)

type integrationController struct {
	gitlabOauth2Integration map[string]*gitlabint.GitlabOauth2Config
}

func NewIntegrationController(gitlabOauth2Integration map[string]*gitlabint.GitlabOauth2Config) *integrationController {
	return &integrationController{
		gitlabOauth2Integration: gitlabOauth2Integration,
	}

}

func (c *integrationController) AutoSetup(ctx core.Context) error {
	thirdPartyIntegration := core.GetThirdPartyIntegration(ctx)
	gl := thirdPartyIntegration.GetIntegration(core.GitLabIntegrationID)
	if gl != nil {
		return gl.(*gitlabint.GitlabIntegration).AutoSetup(ctx)
	}

	return nil
}

func (c *integrationController) ListRepositories(ctx core.Context) error {
	thirdPartyIntegration := core.GetThirdPartyIntegration(ctx)

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
		if err := gh.(*githubint.GithubIntegration).FinishInstallation(ctx); err != nil {
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

func (c *integrationController) TestAndSaveGitlabIntegration(ctx core.Context) error {
	thirdPartyIntegration := core.GetThirdPartyIntegration(ctx)
	gl := thirdPartyIntegration.GetIntegration(core.GitLabIntegrationID)
	if gl == nil {
		return ctx.JSON(404, "GitLab integration not enabled")
	}

	if err := gl.(*gitlabint.GitlabIntegration).TestAndSave(ctx); err != nil {
		slog.Error("could not test GitLab integration", "err", err)
		return err
	}

	return nil
}

func (c *integrationController) GitLabOauth2Callback(ctx core.Context) error {
	integrationName := core.GetParam(ctx, "integrationName")
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

func (c *integrationController) GitLabOauth2Login(ctx core.Context) error {
	integrationName := core.GetParam(ctx, "integrationName")
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

func (c *integrationController) DeleteGitLabAccessToken(ctx core.Context) error {
	thirdPartyIntegration := core.GetThirdPartyIntegration(ctx)
	gl := thirdPartyIntegration.GetIntegration(core.GitLabIntegrationID)
	if gl == nil {
		return ctx.JSON(404, "GitLab integration not enabled")
	}

	if err := gl.(*gitlabint.GitlabIntegration).Delete(ctx); err != nil {
		slog.Error("could not delete GitLab integration", "err", err)
		return err
	}

	return nil
}
