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

package repositories

import (
	"github.com/l3montree-dev/devguard/shared"
	"go.uber.org/fx"
)

// Module provides all repository constructors as their interfaces
var Module = fx.Options(
	fx.Provide(fx.Annotate(NewPATRepository, fx.As(new(shared.PersonalAccessTokenRepository)))),
	fx.Provide(fx.Annotate(NewAssetRepository, fx.As(new(shared.AssetRepository)))),
	fx.Provide(fx.Annotate(NewArtifactRiskHistoryRepository, fx.As(new(shared.ArtifactRiskHistoryRepository)))),
	fx.Provide(fx.Annotate(NewAssetVersionRepository, fx.As(new(shared.AssetVersionRepository)))),
	fx.Provide(fx.Annotate(NewStatisticsRepository, fx.As(new(shared.StatisticsRepository)))),
	fx.Provide(fx.Annotate(NewReleaseRepository, fx.As(new(shared.ReleaseRepository)))),
	fx.Provide(fx.Annotate(NewProjectRepository, fx.As(new(shared.ProjectRepository)))),
	fx.Provide(fx.Annotate(NewComponentRepository, fx.As(new(shared.ComponentRepository)))),
	fx.Provide(fx.Annotate(NewVulnEventRepository, fx.As(new(shared.VulnEventRepository)))),
	fx.Provide(fx.Annotate(NewOrgRepository, fx.As(new(shared.OrganizationRepository)))),
	fx.Provide(fx.Annotate(NewCVERepository, fx.As(new(shared.CveRepository)))),
	fx.Provide(fx.Annotate(NewCWERepository, fx.As(new(shared.CweRepository)))),
	fx.Provide(fx.Annotate(NewExploitRepository, fx.As(new(shared.ExploitRepository)))),
	fx.Provide(fx.Annotate(NewAffectedComponentRepository, fx.As(new(shared.AffectedComponentRepository)))),
	fx.Provide(fx.Annotate(NewDependencyVulnRepository, fx.As(new(shared.DependencyVulnRepository)))),
	fx.Provide(fx.Annotate(NewFirstPartyVulnerabilityRepository, fx.As(new(shared.FirstPartyVulnRepository)))),
	fx.Provide(fx.Annotate(NewInTotoLinkRepository, fx.As(new(shared.InTotoLinkRepository)))),
	fx.Provide(fx.Annotate(NewSupplyChainRepository, fx.As(new(shared.SupplyChainRepository)))),
	fx.Provide(fx.Annotate(NewAttestationRepository, fx.As(new(shared.AttestationRepository)))),
	fx.Provide(fx.Annotate(NewPolicyRepository, fx.As(new(shared.PolicyRepository)))),
	fx.Provide(fx.Annotate(NewLicenseRiskRepository, fx.As(new(shared.LicenseRiskRepository)))),
	fx.Provide(fx.Annotate(NewWebhookRepository, fx.As(new(shared.WebhookIntegrationRepository)))),
	fx.Provide(fx.Annotate(NewArtifactRepository, fx.As(new(shared.ArtifactRepository)))),
	fx.Provide(fx.Annotate(NewInvitationRepository, fx.As(new(shared.InvitationRepository)))),
	fx.Provide(fx.Annotate(NewExternalUserRepository, fx.As(new(shared.ExternalUserRepository)))),
	fx.Provide(fx.Annotate(NewComponentProjectRepository, fx.As(new(shared.ComponentProjectRepository)))),
	fx.Provide(fx.Annotate(NewGitLabIntegrationRepository, fx.As(new(shared.GitlabIntegrationRepository)))),
	fx.Provide(fx.Annotate(NewGitlabOauth2TokenRepository, fx.As(new(shared.GitLabOauth2TokenRepository)))),
	fx.Provide(fx.Annotate(NewAggregatedVulnRepository, fx.As(new(shared.VulnRepository)))),
)
