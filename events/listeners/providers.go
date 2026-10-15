// Copyright (C) 2025 l3montree GmbH
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

package listeners

import (
	"slices"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/l3montree-dev/devguard/events"
	"github.com/l3montree-dev/devguard/shared"
	"go.opentelemetry.io/otel"
	"go.uber.org/fx"
)

var daemonTracer = otel.Tracer("devguard.daemon")

type DebugOptions struct {
	LimitToAssetVersionSlug string
	// LimitToStages, when non-empty, skips all pipeline stages not in the list.
	// Valid values match the stage method names: "SyncTickets",
	// "ResolveDifferencesInTicketState", "SyncUpstream",
	// "CollectStats", "RecalculateRiskForVulnerabilities",
	// "DeleteOldAssetVersions", "ResolveFixedVersions".
	LimitToStages []string
	// DryRun skips all database writes. External system mutations are separately
	// intercepted by the dryRunIntegration wrapper.
	DryRun bool
}

// DaemonRunner encapsulates daemon dependencies and lifecycle
type DaemonRunner struct {
	db                              shared.DB
	broker                          events.Broker
	configService                   shared.ConfigService
	rbacProvider                    shared.RBACProvider
	integrationAggregate            shared.IntegrationAggregate
	assetVersionService             shared.AssetVersionService
	assetVersionRepository          shared.AssetVersionRepository
	assetRepository                 shared.AssetRepository
	projectRepository               shared.ProjectRepository
	orgRepository                   shared.OrganizationRepository
	componentService                shared.ComponentService
	dependencyVulnService           shared.DependencyVulnService
	dependencyVulnRepository        shared.DependencyVulnRepository
	componentProjectRepository      shared.ComponentProjectRepository
	statisticsService               shared.StatisticsService
	artifactRepository              shared.ArtifactRepository
	cveRepository                   shared.CveRepository
	scanService                     shared.ScanService
	vulnDBImportService             shared.VulnDBService
	vexRuleRepository               shared.VEXRuleRepository
	vexRuleRecommendationRepository shared.VEXRuleRecommendationRepository
	trustedEntityRepository         shared.TrustedEntityRepository
	upstreamVEXRuleRepository       shared.UpstreamVEXRuleRepository
	externalReferenceRepository     shared.ExternalReferenceRepository
	sbomRepository                  shared.SBOMRepository
	externalEntityProviderService   shared.ExternalEntityProviderService
	firstPartyVulnService           shared.FirstPartyVulnService
	pgxpool                         *pgxpool.Pool

	debugOptions         DebugOptions
	fixedVersionResolver shared.FixedVersionResolver
}

func (runner *DaemonRunner) SetDebugOptions(options DebugOptions) {
	runner.debugOptions = options
}

// stageEnabled returns false when LimitToStage is set and does not match stageName,
// meaning the stage should be skipped and its input passed through unchanged.
func (runner *DaemonRunner) stageEnabled(stageName string) bool {
	if len(runner.debugOptions.LimitToStages) == 0 {
		return true
	}
	return slices.Contains(runner.debugOptions.LimitToStages, stageName)
}

func (runner *DaemonRunner) DebugMode() bool {
	return runner.debugOptions.LimitToAssetVersionSlug != ""
}

// NewDaemonRunner creates a new daemon runner with injected dependencies
func NewDaemonRunner(
	db shared.DB,
	broker events.Broker,
	configService shared.ConfigService,
	rbacProvider shared.RBACProvider,
	integrationAggregate shared.IntegrationAggregate,
	assetVersionService shared.AssetVersionService,
	assetVersionRepository shared.AssetVersionRepository,
	assetRepository shared.AssetRepository,
	projectRepository shared.ProjectRepository,
	orgRepository shared.OrganizationRepository,
	componentService shared.ComponentService,
	dependencyVulnService shared.DependencyVulnService,
	dependencyVulnRepository shared.DependencyVulnRepository,
	componentProjectRepository shared.ComponentProjectRepository,
	statisticsService shared.StatisticsService,
	artifactRepository shared.ArtifactRepository,
	cveRepository shared.CveRepository,
	scanService shared.ScanService,
	vulnDBImportService shared.VulnDBService,
	vexRuleRepository shared.VEXRuleRepository,
	vexRuleRecommendationRepository shared.VEXRuleRecommendationRepository,
	trustedEntityRepository shared.TrustedEntityRepository,
	externalReferenceRepository shared.ExternalReferenceRepository,
	sbomRepository shared.SBOMRepository,
	fixedVersionResolver shared.FixedVersionResolver,
	upstreamVEXRuleRepository shared.UpstreamVEXRuleRepository,
	externalEntityProviderService shared.ExternalEntityProviderService,
	firstPartyVulnService shared.FirstPartyVulnService,
	pool *pgxpool.Pool,
) *DaemonRunner {
	return &DaemonRunner{
		db:                              db,
		broker:                          broker,
		configService:                   configService,
		rbacProvider:                    rbacProvider,
		integrationAggregate:            integrationAggregate,
		assetVersionService:             assetVersionService,
		assetVersionRepository:          assetVersionRepository,
		assetRepository:                 assetRepository,
		projectRepository:               projectRepository,
		orgRepository:                   orgRepository,
		componentService:                componentService,
		dependencyVulnService:           dependencyVulnService,
		dependencyVulnRepository:        dependencyVulnRepository,
		componentProjectRepository:      componentProjectRepository,
		statisticsService:               statisticsService,
		artifactRepository:              artifactRepository,
		cveRepository:                   cveRepository,
		scanService:                     scanService,
		vulnDBImportService:             vulnDBImportService,
		vexRuleRepository:               vexRuleRepository,
		vexRuleRecommendationRepository: vexRuleRecommendationRepository,
		trustedEntityRepository:         trustedEntityRepository,
		externalReferenceRepository:     externalReferenceRepository,
		sbomRepository:                  sbomRepository,
		fixedVersionResolver:            fixedVersionResolver,
		upstreamVEXRuleRepository:       upstreamVEXRuleRepository,
		externalEntityProviderService:   externalEntityProviderService,
		firstPartyVulnService:           firstPartyVulnService,
		pgxpool:                         pool,
	}
}

var _ shared.DaemonRunner = (*DaemonRunner)(nil)

var Module = fx.Module("daemons",
	fx.Provide(fx.Annotate(NewDaemonRunner, fx.As(new(shared.DaemonRunner)))),
)
