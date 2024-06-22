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

import "github.com/l3montree-dev/flawfix/internal/core"

type integrationController struct {
	githubIntegration *githubIntegration
}

func NewIntegrationController(githubIntegration *githubIntegration) *integrationController {
	return &integrationController{
		githubIntegration: githubIntegration,
	}
}

func (c *integrationController) ListRepositories(ctx core.Context) error {
	githubClient, err := c.githubIntegration.GetOrgGithubClientFromContext(ctx)
	if err != nil {
		return err
	}

	repos, err := githubClient.ListRepositories()
	if err != nil {
		return err
	}

	return ctx.JSON(200, repos)
}
