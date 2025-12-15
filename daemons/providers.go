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
	"log/slog"
	"time"

	"github.com/l3montree-dev/devguard/database"
	"github.com/l3montree-dev/devguard/shared"
	"go.uber.org/fx"
)

// DaemonRunner encapsulates daemon dependencies and lifecycle
type DaemonRunner struct {
	db                           shared.DB
	broker                       database.Broker
	configService                shared.ConfigService
	rbacProvider                 shared.RBACProvider
	integrationAggregate         shared.IntegrationAggregate
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
	scanService                  shared.ScanService
	leaderElector                shared.LeaderElector
}

// NewDaemonRunner creates a new daemon runner with injected dependencies
func NewDaemonRunner(
	db shared.DB,
	broker database.Broker,
	configService shared.ConfigService,
	rbacProvider shared.RBACProvider,
	integrationAggregate shared.IntegrationAggregate,
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
	scanService shared.ScanService,
	leaderElector shared.LeaderElector,
) DaemonRunner {
	return DaemonRunner{
		db:                           db,
		broker:                       broker,
		configService:                configService,
		rbacProvider:                 rbacProvider,
		integrationAggregate:         integrationAggregate,
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
		scanService:                  scanService,
		leaderElector:                leaderElector,
	}
}

// Start initiates all background daemons
func (runner DaemonRunner) Start() {
	go func() {
		runner.tick()
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			runner.tick()
		}
	}()
}

func (runner DaemonRunner) tick() {
	if runner.leaderElector.IsLeader() {
		slog.Info("this instance is the leader - running background jobs")
		runner.runDaemons()
		runner.RunAssetPipeline(false)
	} else {
		slog.Info("not the leader - skipping background jobs")
	}
}

var _ shared.DaemonRunner = DaemonRunner{}

var Module = fx.Module("daemons",
	fx.Provide(fx.Annotate(NewDaemonRunner, fx.As(new(shared.DaemonRunner)))),
)
