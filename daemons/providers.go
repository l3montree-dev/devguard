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

package daemons

import (
	"github.com/l3montree-dev/devguard/controllers"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"go.uber.org/fx"
)

// DaemonRunner encapsulates daemon dependencies and lifecycle
type DaemonRunner struct {
	db                           shared.DB
	broker                       shared.Broker
	configService                services.ConfigService
	rbacProvider                 shared.RBACProvider
	integrationAggregate         shared.IntegrationAggregate
	scanController               *controllers.ScanController
	assetVersionService          shared.AssetVersionService
	assetVersionRepository       shared.AssetVersionRepository
	assetRepository              shared.AssetRepository
	projectRepository            shared.ProjectRepository
	orgRepository                shared.OrganizationRepository
	artifactService              shared.ArtifactService
	componentRepository          shared.ComponentRepository
	componentService             shared.ComponentService
	dependencyVulnService        shared.DependencyVulnService
	dependencyVulnRepository     shared.DependencyVulnRepository
	componentProjectRepository   shared.ComponentProjectRepository
	vulnEventRepository          shared.VulnEventRepository
	statisticsService            shared.StatisticsService
	artifactRepository           shared.ArtifactRepository
	cveRepository                shared.CveRepository
	cweRepository                shared.CweRepository
	exploitsRepository           shared.ExploitRepository
	affectedComponentsRepository shared.AffectedComponentRepository
}

// NewDaemonRunner creates a new daemon runner with injected dependencies
func NewDaemonRunner(
	db shared.DB,
	broker shared.Broker,
	configService services.ConfigService,
	rbacProvider shared.RBACProvider,
	integrationAggregate shared.IntegrationAggregate,
	scanController *controllers.ScanController,
	assetVersionService shared.AssetVersionService,
	assetVersionRepository shared.AssetVersionRepository,
	assetRepository shared.AssetRepository,
	projectRepository shared.ProjectRepository,
	orgRepository shared.OrganizationRepository,
	artifactService shared.ArtifactService,
	componentRepository shared.ComponentRepository,
	componentService shared.ComponentService,
	dependencyVulnService shared.DependencyVulnService,
	dependencyVulnRepository shared.DependencyVulnRepository,
	componentProjectRepository shared.ComponentProjectRepository,
	vulnEventRepository shared.VulnEventRepository,
	statisticsService shared.StatisticsService,
	artifactRepository shared.ArtifactRepository,
	cveRepository shared.CveRepository,
	cweRepository shared.CweRepository,
	exploitsRepository shared.ExploitRepository,
	affectedComponentsRepository shared.AffectedComponentRepository,
) *DaemonRunner {
	return &DaemonRunner{
		db:                           db,
		broker:                       broker,
		configService:                configService,
		rbacProvider:                 rbacProvider,
		integrationAggregate:         integrationAggregate,
		scanController:               scanController,
		assetVersionService:          assetVersionService,
		assetVersionRepository:       assetVersionRepository,
		assetRepository:              assetRepository,
		projectRepository:            projectRepository,
		orgRepository:                orgRepository,
		artifactService:              artifactService,
		componentRepository:          componentRepository,
		componentService:             componentService,
		dependencyVulnService:        dependencyVulnService,
		dependencyVulnRepository:     dependencyVulnRepository,
		componentProjectRepository:   componentProjectRepository,
		vulnEventRepository:          vulnEventRepository,
		statisticsService:            statisticsService,
		artifactRepository:           artifactRepository,
		cveRepository:                cveRepository,
		cweRepository:                cweRepository,
		exploitsRepository:           exploitsRepository,
		affectedComponentsRepository: affectedComponentsRepository,
	}
}

// Start initiates all background daemons
func (dr *DaemonRunner) Start() {
	Start(
		dr.db,
		dr.broker,
		dr.configService,
		dr.rbacProvider,
		dr.integrationAggregate,
		dr.scanController,
		dr.assetVersionService,
		dr.assetVersionRepository,
		dr.assetRepository,
		dr.projectRepository,
		dr.orgRepository,
		dr.artifactService,
		dr.componentRepository,
		dr.componentService,
		dr.dependencyVulnService,
		dr.dependencyVulnRepository,
		dr.componentProjectRepository,
		dr.vulnEventRepository,
		dr.statisticsService,
		dr.artifactRepository,
		dr.cveRepository,
		dr.cweRepository,
		dr.exploitsRepository,
		dr.affectedComponentsRepository,
	)
}

var Module = fx.Module("daemons",
	fx.Provide(NewDaemonRunner),
	fx.Invoke(func(dr *DaemonRunner) {
		dr.Start()
	}),
)
