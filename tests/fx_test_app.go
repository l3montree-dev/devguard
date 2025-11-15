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

package tests

import (
	"github.com/l3montree-dev/devguard/accesscontrol"
	"github.com/l3montree-dev/devguard/controllers"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"go.uber.org/fx"
)

// TestApp provides access to all services and controllers via FX
type TestApp struct {
	fx.In

	// Services
	LicenseRiskService    shared.LicenseRiskService
	StatisticsService     shared.StatisticsService
	ComponentService      shared.ComponentService
	FirstPartyVulnService shared.FirstPartyVulnService
	DependencyVulnService shared.DependencyVulnService
	ArtifactService       shared.ArtifactService
	AssetVersionService   shared.AssetVersionService
	ScanService           shared.ScanService

	// Controllers
	AssetVersionController *controllers.AssetVersionController
	ScanController         *controllers.ScanController

	// Repositories
	AssetRepository          shared.AssetRepository
	AssetVersionRepository   shared.AssetVersionRepository
	ComponentRepository      shared.ComponentRepository
	DependencyVulnRepository shared.DependencyVulnRepository
	CveRepository            shared.CveRepository
}

// NewTestApp creates a test application with all dependencies wired via FX
// It uses the same FX modules as production for consistency
func NewTestApp(db shared.DB) (*TestApp, error) {
	var app TestApp

	fxApp := fx.New(
		// Provide the database
		fx.Provide(func() shared.DB { return db }),

		// Use the same modules as production
		repositories.Module,
		services.ServiceModule,
		controllers.ControllerModule,
		accesscontrol.AccessControlModule,

		// Populate the TestApp struct
		fx.Populate(&app),

		// Don't start the application (no servers, etc)
		fx.NopLogger,
	)

	if err := fxApp.Err(); err != nil {
		return nil, err
	}

	return &app, nil
}
