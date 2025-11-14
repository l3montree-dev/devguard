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
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package integrations

import (
	"github.com/l3montree-dev/devguard/integrations/githubint"
	"github.com/l3montree-dev/devguard/integrations/gitlabint"
	"github.com/l3montree-dev/devguard/integrations/jiraint"
	"github.com/l3montree-dev/devguard/integrations/webhook"
	"github.com/l3montree-dev/devguard/shared"
	"go.uber.org/fx"
)

// Module provides all integration constructors
var Module = fx.Options(
	// GitHub Integration
	fx.Provide(githubint.NewGithubIntegration),

	// GitLab Integration
	fx.Provide(gitlabint.NewGitLabOauth2Integrations),
	fx.Provide(gitlabint.NewGitlabClientFactory),
	fx.Provide(gitlabint.NewGitlabIntegration),

	// Jira Integration
	fx.Provide(jiraint.NewJiraIntegration),

	// Webhook Integration
	fx.Provide(webhook.NewWebhookIntegration),

	// Aggregated Third Party Integration
	fx.Provide(fx.Annotate(
		NewThirdPartyIntegrations,
		fx.As(new(shared.IntegrationAggregate)),
	)),
)
