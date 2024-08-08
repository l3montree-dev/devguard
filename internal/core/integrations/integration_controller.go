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
)

type integrationController struct {
}

func NewIntegrationController() *integrationController {
	return &integrationController{}
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
	if err := thirdPartyIntegration.FinishInstallation(ctx); err != nil {
		slog.Error("could not finish installation", "err", err)
		return err
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
