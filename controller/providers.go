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
	"go.uber.org/fx"

	"github.com/l3montree-dev/devguard/internal/core/artifact"
	"github.com/l3montree-dev/devguard/internal/core/asset"
	"github.com/l3montree-dev/devguard/internal/core/assetversion"
	"github.com/l3montree-dev/devguard/internal/core/attestation"
	"github.com/l3montree-dev/devguard/internal/core/compliance"
	"github.com/l3montree-dev/devguard/internal/core/component"
	"github.com/l3montree-dev/devguard/internal/core/csaf"
	"github.com/l3montree-dev/devguard/internal/core/events"
	"github.com/l3montree-dev/devguard/internal/core/integrations"
	"github.com/l3montree-dev/devguard/internal/core/intoto"
	"github.com/l3montree-dev/devguard/internal/core/org"
	"github.com/l3montree-dev/devguard/internal/core/pat"
	"github.com/l3montree-dev/devguard/internal/core/project"
	"github.com/l3montree-dev/devguard/internal/core/release"
	"github.com/l3montree-dev/devguard/internal/core/statistics"
	"github.com/l3montree-dev/devguard/internal/core/vuln"
	"github.com/l3montree-dev/devguard/internal/core/vulndb"
	"github.com/l3montree-dev/devguard/internal/core/vulndb/scan"
)

// Module provides all HTTP controller constructors
var Module = fx.Options(
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
