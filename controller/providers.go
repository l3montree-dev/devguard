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

package controller

import (
	"os"

	"go.uber.org/fx"

	"github.com/l3montree-dev/devguard/internal/accesscontrol"
	"github.com/l3montree-dev/devguard/internal/auth"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/artifact"
	"github.com/l3montree-dev/devguard/internal/core/asset"
	"github.com/l3montree-dev/devguard/internal/core/assetversion"
	"github.com/l3montree-dev/devguard/internal/core/attestation"
	"github.com/l3montree-dev/devguard/internal/core/compliance"
	"github.com/l3montree-dev/devguard/internal/core/component"
	"github.com/l3montree-dev/devguard/internal/core/csaf"
	"github.com/l3montree-dev/devguard/internal/core/events"
	"github.com/l3montree-dev/devguard/internal/core/integrations"
	"github.com/l3montree-dev/devguard/internal/core/integrations/githubint"
	"github.com/l3montree-dev/devguard/internal/core/integrations/gitlabint"
	"github.com/l3montree-dev/devguard/internal/core/integrations/jiraint"
	"github.com/l3montree-dev/devguard/internal/core/integrations/webhook"
	"github.com/l3montree-dev/devguard/internal/core/intoto"
	"github.com/l3montree-dev/devguard/internal/core/org"
	"github.com/l3montree-dev/devguard/internal/core/pat"
	"github.com/l3montree-dev/devguard/internal/core/project"
	"github.com/l3montree-dev/devguard/internal/core/release"
	"github.com/l3montree-dev/devguard/internal/core/statistics"
	"github.com/l3montree-dev/devguard/internal/core/vuln"
	"github.com/l3montree-dev/devguard/internal/core/vulndb"
	"github.com/l3montree-dev/devguard/internal/core/vulndb/scan"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/pubsub"
)

// RepositoryModule provides all repository constructors
var RepositoryModule = fx.Options(
	fx.Provide(repositories.NewPATRepository),
	fx.Provide(repositories.NewAssetRepository),
	fx.Provide(repositories.NewArtifactRiskHistoryRepository),
	fx.Provide(repositories.NewAssetVersionRepository),
	fx.Provide(repositories.NewStatisticsRepository),
	fx.Provide(repositories.NewReleaseRepository),
	fx.Provide(repositories.NewProjectRepository),
	fx.Provide(repositories.NewComponentRepository),
	fx.Provide(repositories.NewVulnEventRepository),
	fx.Provide(repositories.NewOrgRepository),
	fx.Provide(repositories.NewCVERepository),
	fx.Provide(repositories.NewDependencyVulnRepository),
	fx.Provide(repositories.NewFirstPartyVulnerabilityRepository),
	fx.Provide(repositories.NewInTotoLinkRepository),
	fx.Provide(repositories.NewSupplyChainRepository),
	fx.Provide(repositories.NewAttestationRepository),
	fx.Provide(repositories.NewPolicyRepository),
	fx.Provide(repositories.NewLicenseRiskRepository),
	fx.Provide(repositories.NewWebhookRepository),
	fx.Provide(repositories.NewArtifactRepository),
	fx.Provide(repositories.NewInvitationRepository),
	fx.Provide(repositories.NewExternalUserRepository),
	fx.Provide(repositories.NewComponentProjectRepository),
	fx.Provide(repositories.NewGitLabIntegrationRepository),
)

// AuthModule provides authentication-related dependencies
var AuthModule = fx.Options(
	fx.Provide(func() core.AdminClient {
		ory := auth.GetOryAPIClient(os.Getenv("ORY_KRATOS_PUBLIC"))
		return core.NewAdminClient(ory)
	}),
	fx.Provide(func(db core.DB, broker pubsub.Broker) (core.RBACProvider, error) {
		return accesscontrol.NewCasbinRBACProvider(db, broker)
	}),
)

// IntegrationModule provides third-party integration dependencies
var IntegrationModule = fx.Options(
	fx.Provide(webhook.NewWebhookIntegration),
	fx.Provide(jiraint.NewJiraIntegration),
	fx.Provide(githubint.NewGithubIntegration),
	fx.Provide(gitlabint.NewGitLabOauth2Integrations),
	fx.Provide(gitlabint.NewGitlabClientFactory),
	fx.Provide(gitlabint.NewGitlabIntegration),
	fx.Provide(integrations.NewThirdPartyIntegrations),
)

// ControllerModule provides all HTTP controller constructors
var ControllerModule = fx.Options(
	fx.Provide(artifact.NewController),
	fx.Provide(vuln.NewHTTPController),
	fx.Provide(events.NewVulnEventController),
	fx.Provide(compliance.NewPolicyController),
	fx.Provide(pat.NewHTTPController),
	fx.Provide(org.NewHTTPController),
	fx.Provide(project.NewHTTPController),
	fx.Provide(asset.NewHTTPController),
	fx.Provide(scan.NewHTTPController),
	fx.Provide(assetversion.NewAssetVersionController),
	fx.Provide(attestation.NewAttestationController),
	fx.Provide(intoto.NewHTTPController),
	fx.Provide(component.NewHTTPController),
	fx.Provide(compliance.NewHTTPController),
	fx.Provide(statistics.NewHTTPController),
	fx.Provide(vuln.NewFirstPartyVulnController),
	fx.Provide(vuln.NewLicenseRiskController),
	fx.Provide(release.NewReleaseController),
	fx.Provide(vulndb.NewHTTPController),
	fx.Provide(csaf.NewCSAFController),
	fx.Provide(integrations.NewIntegrationController),
)
