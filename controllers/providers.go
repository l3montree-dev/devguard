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

package controllers

import (
	"go.uber.org/fx"
)

// ControllerModule provides all HTTP controller constructors
var ControllerModule = fx.Options(
	// Asset Management
	fx.Provide(NewAssetController),
	fx.Provide(NewAssetVersionController),
	fx.Provide(NewArtifactController),
	fx.Provide(NewComponentController),

	// Vulnerability Management
	fx.Provide(NewDependencyVulnController),
	fx.Provide(NewFirstPartyVulnController),
	fx.Provide(NewVulnEventController),
	fx.Provide(NewLicenseRiskController),

	// Organization & Project Management
	fx.Provide(NewOrganizationController),
	fx.Provide(NewProjectController),

	// Security & Compliance
	fx.Provide(NewCSAFController),
	fx.Provide(NewComplianceController),
	fx.Provide(NewAttestationController),
	fx.Provide(NewInToToController),
	fx.Provide(NewPolicyController),

	// Integrations
	fx.Provide(NewIntegrationController),
	fx.Provide(NewVulnDBController),
	fx.Provide(NewWebhookController),

	// Release & Statistics
	fx.Provide(NewReleaseController),
	fx.Provide(NewStatisticsController),

	// Authentication & Access
	fx.Provide(NewPatController),
	fx.Provide(NewScanController),
)
