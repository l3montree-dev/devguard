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

// BOLA (Broken Object-Level Authorization) integration tests.
//
// Each test proves that an authenticated user from tenant B cannot read a
// record that belongs to tenant A, even when they supply a valid UUID for
// that record via tenant B's route prefix.
//
// Attack pattern being tested:
//   GET /api/v1/organizations/<orgB>/.../dependency-vulns/<vulnID from orgA>/
//
// The route-level RBAC authorises the orgB carrier path.  Without the
// tenant-scoping fix the DB query would return orgA's record.  With the fix,
// the query appends AND asset_id = <assetB.ID> which yields no rows → 404.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/controllers"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTenant creates an org/project/asset/assetVersion with a unique slug
// suffix so multiple tenants can coexist in the same test database.
func createTenant(f *TestFixture, suffix string) (models.Org, models.Project, models.Asset, models.AssetVersion) {
	org := f.CreateOrg("org-" + suffix)
	project := f.CreateProject(org.ID, "project-"+suffix)
	asset := f.CreateAsset(project.ID, "asset-"+suffix)
	assetVersion := f.CreateAssetVersion(asset.ID, "main", true)
	return org, project, asset, assetVersion
}

// bolaCtx builds a shared.Context that looks like it came from tenant B's
// authenticated request but carries vulnID from tenant A.
// It propagates tenant B's IDs into both the Echo context (for controllers) and
// the plain context.Context (for GormRepository.Read / autoTenantScope).
func bolaCtx(t *testing.T, paramName, vulnID string, orgB models.Org, projB models.Project, assetB models.Asset, assetVersionB models.AssetVersion) shared.Context {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	ctx := NewContext(req, rec)

	// Authenticate as tenant B
	session := mocks.NewAuthSession(t)
	session.On("GetUserID").Return(uuid.New().String()).Maybe()
	shared.SetSession(ctx, session)
	shared.SetOrg(ctx, orgB)
	shared.SetProject(ctx, projB)
	shared.SetAsset(ctx, assetB)
	shared.SetAssetVersion(ctx, assetVersionB)

	rbac := mocks.NewAccessControl(t)
	shared.SetRBAC(ctx, rbac)

	// Propagate tenant B's IDs into the plain context.Context so that
	// GormRepository.Read() / autoTenantScope picks them up.
	tenantIDs := models.OwnershipScope{
		AssetID:   assetB.ID,
		ProjectID: projB.ID,
		OrgID:     orgB.ID,
	}
	ctx.SetRequest(ctx.Request().WithContext(shared.WithOwnershipScope(ctx.Request().Context(), tenantIDs)))

	// But supply the UUID from tenant A
	ctx.SetParamNames(paramName)
	ctx.SetParamValues(vulnID)

	return ctx
}

// TestBOLADependencyVulnCrossAssetReadBlocked proves that reading a
// DependencyVuln by UUID is scoped to the asset in the request context.
// An attacker authenticated as orgB cannot retrieve a vuln belonging to orgA.
func TestBOLADependencyVulnCrossAssetReadBlocked(t *testing.T) {
	t.Parallel()
	WithTestAppOptions(t, "../initdb.sql", TestAppOptions{SuppressLogs: true}, func(f *TestFixture) {
		// Tenant A: owns the vulnerability
		_, _, assetA, assetVersionA := createTenant(f, "depvuln-read-a")

		cve := models.CVE{CVE: "CVE-2025-BOLA-1"}
		require.NoError(t, f.DB.Create(&cve).Error)

		vulnA := models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				State:            dtos.VulnStateOpen,
				AssetVersionName: assetVersionA.Name,
				AssetID:          assetA.ID,
			},
			CVEID:         cve.CVE,
			ComponentPurl: "pkg:npm/left-pad@1.0.0",
		}
		require.NoError(t, f.DB.Create(&vulnA).Error)

		// Tenant B: the attacker
		orgB, projB, assetB, assetVersionB := createTenant(f, "depvuln-read-b")
		_ = orgB

		ctx := bolaCtx(t, "dependencyVulnID", vulnA.ID.String(), orgB, projB, assetB, assetVersionB)

		err := f.App.DependencyVulnController.Read(ctx)
		require.Error(t, err, "expected an error when reading another tenant's DependencyVuln")

		httpErr, ok := err.(*echo.HTTPError)
		require.True(t, ok, "expected an echo.HTTPError")
		assert.Equal(t, http.StatusNotFound, httpErr.Code,
			"cross-tenant DependencyVuln read must return 404, not 200")
	})
}

// TestBOLAFirstPartyVulnCrossAssetReadBlocked proves that reading a
// FirstPartyVuln by UUID is scoped to the asset in the request context.
func TestBOLAFirstPartyVulnCrossAssetReadBlocked(t *testing.T) {
	t.Parallel()
	WithTestAppOptions(t, "../initdb.sql", TestAppOptions{SuppressLogs: true}, func(f *TestFixture) {
		// Tenant A: owns the vulnerability
		_, _, assetA, assetVersionA := createTenant(f, "fpvuln-read-a")

		vulnA := models.FirstPartyVuln{
			Vulnerability: models.Vulnerability{
				State:            dtos.VulnStateOpen,
				AssetVersionName: assetVersionA.Name,
				AssetID:          assetA.ID,
			},
			RuleID: "test-rule-bola",
		}
		require.NoError(t, f.DB.Create(&vulnA).Error)

		// Tenant B: the attacker
		orgB, projB, assetB, assetVersionB := createTenant(f, "fpvuln-read-b")

		ctx := bolaCtx(t, "firstPartyVulnID", vulnA.ID.String(), orgB, projB, assetB, assetVersionB)

		err := f.App.FirstPartyVulnController.Read(ctx)
		require.Error(t, err, "expected an error when reading another tenant's FirstPartyVuln")

		httpErr, ok := err.(*echo.HTTPError)
		require.True(t, ok, "expected an echo.HTTPError")
		assert.Equal(t, http.StatusNotFound, httpErr.Code,
			"cross-tenant FirstPartyVuln read must return 404, not 200")
	})
}

// TestBOLALicenseRiskCrossAssetReadBlocked proves that reading a LicenseRisk
// by UUID is scoped to the asset in the request context.
func TestBOLALicenseRiskCrossAssetReadBlocked(t *testing.T) {
	t.Parallel()
	WithTestAppOptions(t, "../initdb.sql", TestAppOptions{SuppressLogs: true}, func(f *TestFixture) {
		// Tenant A: owns the license risk
		_, _, assetA, assetVersionA := createTenant(f, "licenserisk-a")

		component := models.Component{ID: "pkg:npm/proprietary-lib@1.0.0"}
		require.NoError(t, f.DB.Create(&component).Error)

		riskA := models.LicenseRisk{
			Vulnerability: models.Vulnerability{
				State:            dtos.VulnStateOpen,
				AssetVersionName: assetVersionA.Name,
				AssetID:          assetA.ID,
			},
			ComponentPurl: component.ID,
		}
		require.NoError(t, f.DB.Create(&riskA).Error)

		// Tenant B: the attacker
		orgB, projB, assetB, assetVersionB := createTenant(f, "licenserisk-b")

		ctx := bolaCtx(t, "licenseRiskID", riskA.ID.String(), orgB, projB, assetB, assetVersionB)

		licenseRiskController := controllers.NewLicenseRiskController(f.App.LicenseRiskRepository, f.App.LicenseRiskService)
		err := licenseRiskController.Read(ctx)
		require.Error(t, err, "expected an error when reading another tenant's LicenseRisk")

		httpErr, ok := err.(*echo.HTTPError)
		require.True(t, ok, "expected an echo.HTTPError")
		assert.Equal(t, http.StatusNotFound, httpErr.Code,
			"cross-tenant LicenseRisk read must return 404, not 200")
	})
}

// TestBOLADependencyVulnCreateEventCrossAssetBlocked proves that creating an
// event on a DependencyVuln from a different asset is blocked. CreateEvent
// calls repository.Read internally; the tenant scope must reject the record.
func TestBOLADependencyVulnCreateEventCrossAssetBlocked(t *testing.T) {
	t.Parallel()
	WithTestAppOptions(t, "../initdb.sql", TestAppOptions{SuppressLogs: true}, func(f *TestFixture) {
		// Tenant A: owns the vulnerability
		_, _, assetA, assetVersionA := createTenant(f, "event-a")

		cve := models.CVE{CVE: "CVE-2025-BOLA-EVENT-1"}
		require.NoError(t, f.DB.Create(&cve).Error)

		vulnA := models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				State:            dtos.VulnStateOpen,
				AssetVersionName: assetVersionA.Name,
				AssetID:          assetA.ID,
			},
			CVEID:         cve.CVE,
			ComponentPurl: "pkg:npm/left-pad@1.0.0",
		}
		require.NoError(t, f.DB.Create(&vulnA).Error)

		// Tenant B: the attacker
		orgB, projB, assetB, assetVersionB := createTenant(f, "event-b")

		body, _ := json.Marshal(map[string]string{"comment": "attacker comment", "statusType": "accepted"})
		req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		ctx := NewContext(req, rec)

		session := mocks.NewAuthSession(t)
		session.On("GetUserID").Return(uuid.New().String()).Maybe()
		shared.SetSession(ctx, session)
		shared.SetOrg(ctx, orgB)
		shared.SetProject(ctx, projB)
		shared.SetAsset(ctx, assetB)
		shared.SetAssetVersion(ctx, assetVersionB)
		integration := mocks.NewIntegrationAggregate(t)
		shared.SetThirdPartyIntegration(ctx, integration)
		rbac := mocks.NewAccessControl(t)
		rbac.On("GetAllMembersOfOrganization").Return(nil, nil).Maybe()
		shared.SetRBAC(ctx, rbac)
		adminClient := mocks.NewAdminClient(t)
		shared.SetAuthAdminClient(ctx, adminClient)
		// Propagate tenant B's IDs into plain context.Context for autoTenantScope.
		tenantIDs := models.OwnershipScope{AssetID: assetB.ID, ProjectID: projB.ID, OrgID: orgB.ID}
		ctx.SetRequest(ctx.Request().WithContext(shared.WithOwnershipScope(ctx.Request().Context(), tenantIDs)))
		ctx.SetParamNames("dependencyVulnID")
		ctx.SetParamValues(vulnA.ID.String())

		err := f.App.DependencyVulnController.CreateEvent(ctx)
		require.Error(t, err, "CreateEvent on another tenant's vuln must fail")
		httpErr, ok := err.(*echo.HTTPError)
		require.True(t, ok)
		assert.Equal(t, http.StatusNotFound, httpErr.Code)
	})
}

// TestBOLAReleaseReadCrossProjectBlocked proves that reading a Release by UUID
// is blocked when the release belongs to a different project.
func TestBOLAReleaseReadCrossProjectBlocked(t *testing.T) {
	t.Parallel()
	WithTestAppOptions(t, "../initdb.sql", TestAppOptions{SuppressLogs: true}, func(f *TestFixture) {
		// Tenant A: owns the release
		_, projA, _, _ := createTenant(f, "release-read-a")

		releaseA := models.Release{
			Name:      "v1.0.0",
			ProjectID: projA.ID,
		}
		require.NoError(t, f.DB.Create(&releaseA).Error)

		// Tenant B: the attacker
		orgB, projB, assetB, assetVersionB := createTenant(f, "release-read-b")

		releaseController := controllers.NewReleaseController(
			f.App.ReleaseService,
			f.App.AssetVersionService,
			f.App.AssetVersionRepository,
			f.App.DependencyVulnRepository,
			f.App.AssetRepository,
			f.App.CSAFService,
		)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := NewContext(req, rec)

		session := mocks.NewAuthSession(t)
		session.On("GetUserID").Return(uuid.New().String()).Maybe()
		shared.SetSession(ctx, session)
		shared.SetOrg(ctx, orgB)
		shared.SetProject(ctx, projB)
		shared.SetAsset(ctx, assetB)
		shared.SetAssetVersion(ctx, assetVersionB)
		scope := models.OwnershipScope{AssetID: assetB.ID, ProjectID: projB.ID, OrgID: orgB.ID}
		ctx.SetRequest(ctx.Request().WithContext(shared.WithOwnershipScope(ctx.Request().Context(), scope)))
		ctx.SetParamNames("releaseID")
		ctx.SetParamValues(releaseA.ID.String())

		err := releaseController.Read(ctx)
		require.Error(t, err, "reading a release from a different project must fail")
		httpErr, ok := err.(*echo.HTTPError)
		require.True(t, ok)
		assert.Equal(t, http.StatusNotFound, httpErr.Code,
			"cross-project release read must return 404 — if this fails, release_repository.ReadRecursive needs tenant scoping")
	})
}

// TestBOLAReleaseRepositoryReadRecursiveCrossProject directly tests the
// repository layer: ReadRecursive must not return a release that belongs to a
// different project than the one in the request context.
func TestBOLAReleaseRepositoryReadRecursiveCrossProject(t *testing.T) {
	t.Parallel()
	WithTestAppOptions(t, "../initdb.sql", TestAppOptions{SuppressLogs: true}, func(f *TestFixture) {
		// Tenant A: owns the release
		_, projA, _, _ := createTenant(f, "release-repo-a")

		releaseA := models.Release{
			Name:      "v1.0.0",
			ProjectID: projA.ID,
		}
		require.NoError(t, f.DB.Create(&releaseA).Error)

		// Tenant B: the attacker — their projectID goes into the context
		_, projB, _, _ := createTenant(f, "release-repo-b")

		// Build a context carrying tenant B's project ID
		ctx := shared.WithOwnershipScope(context.Background(), models.OwnershipScope{
			ProjectID: projB.ID,
		})

		_, err := f.App.ReleaseService.ReadRecursive(ctx, releaseA.ID)
		assert.Error(t, err,
			"ReadRecursive must return an error when the release belongs to a different project — "+
				"if this passes unexpectedly, the raw CTE in release_repository needs a WHERE project_id = ? clause")
	})
}

// TestBOLASameAssetReadStillWorks proves that the tenant scope does NOT
// block legitimate reads — a vuln is readable when the request context
// matches the asset the vuln belongs to.
func TestBOLASameAssetReadStillWorks(t *testing.T) {
	t.Parallel()
	WithTestAppOptions(t, "../initdb.sql", TestAppOptions{SuppressLogs: true}, func(f *TestFixture) {
		org, proj, asset, assetVersion := createTenant(f, "legit")

		cve := models.CVE{CVE: "CVE-2025-LEGIT-1"}
		require.NoError(t, f.DB.Create(&cve).Error)

		vuln := models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				State:            dtos.VulnStateOpen,
				AssetVersionName: assetVersion.Name,
				AssetID:          asset.ID,
			},
			CVEID:         cve.CVE,
			ComponentPurl: "pkg:npm/lodash@4.0.0",
		}
		require.NoError(t, f.DB.Create(&vuln).Error)

		// Legitimate request: same tenant
		ctx := bolaCtx(t, "dependencyVulnID", vuln.ID.String(), org, proj, asset, assetVersion)

		err := f.App.DependencyVulnController.Read(ctx)
		assert.NoError(t, err, "reading a vuln from the correct tenant context must succeed")
	})
}
