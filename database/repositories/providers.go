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
	"go.uber.org/fx"
)

// Module provides all repository constructors
var Module = fx.Options(
	fx.Provide(NewPATRepository),
	fx.Provide(NewAssetRepository),
	fx.Provide(NewArtifactRiskHistoryRepository),
	fx.Provide(NewAssetVersionRepository),
	fx.Provide(NewStatisticsRepository),
	fx.Provide(NewReleaseRepository),
	fx.Provide(NewProjectRepository),
	fx.Provide(NewComponentRepository),
	fx.Provide(NewVulnEventRepository),
	fx.Provide(NewOrgRepository),
	fx.Provide(NewCVERepository),
	fx.Provide(NewDependencyVulnRepository),
	fx.Provide(NewFirstPartyVulnerabilityRepository),
	fx.Provide(NewInTotoLinkRepository),
	fx.Provide(NewSupplyChainRepository),
	fx.Provide(NewAttestationRepository),
	fx.Provide(NewPolicyRepository),
	fx.Provide(NewLicenseRiskRepository),
	fx.Provide(NewWebhookRepository),
	fx.Provide(NewArtifactRepository),
	fx.Provide(NewInvitationRepository),
	fx.Provide(NewExternalUserRepository),
	fx.Provide(NewComponentProjectRepository),
	fx.Provide(NewGitLabIntegrationRepository),
)
