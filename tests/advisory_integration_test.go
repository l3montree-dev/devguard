// Copyright (C) 2026 l3montree GmbH
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
	"bytes"
	"fmt"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

// TestAdvisoryUpdateDoesNotDuplicateAffectedPackages covers
// https://github.com/l3montree-dev/devguard/issues/2779: repeatedly saving a
// draft advisory must not duplicate its affected packages. The frontend
// echoes back the affected package's server-assigned id on every PATCH, so
// the test does the same.
func TestAdvisoryUpdateDoesNotDuplicateAffectedPackages(t *testing.T) {
	t.Parallel()
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		controller := f.App.AdvisoryController
		app := echo.New()
		org, project, asset, _ := f.CreateOrgProjectAssetAndVersion()

		setupContext := func(ctx shared.Context) {
			authSession := NewUserSession(t, "abc")
			shared.SetAsset(ctx, asset)
			shared.SetProject(ctx, project)
			shared.SetOrg(ctx, org)
			shared.SetSession(ctx, authSession)
		}

		createBody := `{
			"title": "Test 3",
			"description": "Test 3",
			"severity": "None",
			"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
			"affectedPackages": [
				{
					"ecosystem": "cargo",
					"packageName": "pkg:csaf-validator",
					"semverStart": "0.5.0",
					"semverEnd": "0.5.2"
				}
			],
			"visibility": "draft"
		}`

		// Create the draft advisory with a single affected package.
		createReq := httptest.NewRequest("POST", "/advisory/", bytes.NewBufferString(createBody))
		createReq.Header.Set("Content-Type", "application/json")
		createRecorder := httptest.NewRecorder()
		createCtx := app.NewContext(createReq, createRecorder)
		setupContext(createCtx)
		assert.Nil(t, controller.Create(createCtx))
		assert.Equal(t, 200, createRecorder.Code)

		var advisories []models.Advisory
		assert.Nil(t, f.DB.Preload("AffectedPackages").Where("asset_id = ?", asset.ID).Find(&advisories).Error)
		assert.Len(t, advisories, 1)
		advisoryID := advisories[0].ID
		assert.Len(t, advisories[0].AffectedPackages, 1)
		packageID := advisories[0].AffectedPackages[0].ID

		// Re-save the draft the way the frontend does: same affected package,
		// with its server-assigned id echoed back.
		patchBody := fmt.Sprintf(`{
			"title": "Test 3",
			"description": "Test 3",
			"severity": "None",
			"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
			"affectedPackages": [
				{
					"id": "%s",
					"ecosystem": "cargo",
					"packageName": "pkg:csaf-validator",
					"semverStart": "0.5.0",
					"semverEnd": "0.5.2"
				}
			],
			"visibility": "draft"
		}`, packageID)

		patchOnce := func() {
			req := httptest.NewRequest("PATCH", "/advisory/"+strconv.FormatInt(advisoryID, 10)+"/", bytes.NewBufferString(patchBody))
			req.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()
			ctx := app.NewContext(req, recorder)
			ctx.SetParamNames("id")
			ctx.SetParamValues(strconv.FormatInt(advisoryID, 10))
			setupContext(ctx)
			assert.Nil(t, controller.Update(ctx))
			assert.Equal(t, 200, recorder.Code)
		}

		patchOnce()

		var advisory models.Advisory
		assert.Nil(t, f.DB.Preload("AffectedPackages").First(&advisory, "id = ?", advisoryID).Error)
		assert.Len(t, advisory.AffectedPackages, 1, "affected packages must not be duplicated after re-saving the draft once")
		assert.Equal(t, packageID, advisory.AffectedPackages[0].ID, "the existing affected package must be updated in place, not replaced")

		// Saving again must still not duplicate anything.
		patchOnce()
		assert.Nil(t, f.DB.Preload("AffectedPackages").First(&advisory, "id = ?", advisoryID).Error)
		assert.Len(t, advisory.AffectedPackages, 1, "affected packages must not be duplicated after re-saving the draft a second time")
		assert.Equal(t, packageID, advisory.AffectedPackages[0].ID)
	})
}

// TestAdvisoryUpdateRemovesDroppedAffectedPackage covers the adjacent bug
// found while investigating #2779: dropping an affected package from the
// PATCH body (the user removed it in the UI) must actually delete it,
// not just leave its join row and row in affected_packages behind.
func TestAdvisoryUpdateRemovesDroppedAffectedPackage(t *testing.T) {
	t.Parallel()
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		controller := f.App.AdvisoryController
		app := echo.New()
		org, project, asset, _ := f.CreateOrgProjectAssetAndVersion()

		setupContext := func(ctx shared.Context) {
			authSession := NewUserSession(t, "abc")
			shared.SetAsset(ctx, asset)
			shared.SetProject(ctx, project)
			shared.SetOrg(ctx, org)
			shared.SetSession(ctx, authSession)
		}

		createBody := `{
			"title": "Test 3",
			"description": "Test 3",
			"severity": "None",
			"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
			"affectedPackages": [
				{"ecosystem": "cargo", "packageName": "pkg:csaf-validator-a", "semverStart": "0.5.0", "semverEnd": "0.5.2"},
				{"ecosystem": "cargo", "packageName": "pkg:csaf-validator-b", "semverStart": "1.0.0", "semverEnd": "1.0.2"}
			],
			"visibility": "draft"
		}`

		createReq := httptest.NewRequest("POST", "/advisory/", bytes.NewBufferString(createBody))
		createReq.Header.Set("Content-Type", "application/json")
		createRecorder := httptest.NewRecorder()
		createCtx := app.NewContext(createReq, createRecorder)
		setupContext(createCtx)
		assert.Nil(t, controller.Create(createCtx))
		assert.Equal(t, 200, createRecorder.Code)

		var advisories []models.Advisory
		assert.Nil(t, f.DB.Preload("AffectedPackages").Where("asset_id = ?", asset.ID).Find(&advisories).Error)
		assert.Len(t, advisories, 1)
		assert.Len(t, advisories[0].AffectedPackages, 2)
		advisoryID := advisories[0].ID

		var keptID string
		for _, p := range advisories[0].AffectedPackages {
			if p.PackageName == "pkg:csaf-validator-a" {
				keptID = p.ID.String()
			}
		}
		assert.NotEmpty(t, keptID, "should have found the package to keep")

		// PATCH with only the "a" package (echoing its id) - "b" was removed by the user.
		patchBody := fmt.Sprintf(`{
			"title": "Test 3",
			"description": "Test 3",
			"severity": "None",
			"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
			"affectedPackages": [
				{"id": "%s", "ecosystem": "cargo", "packageName": "pkg:csaf-validator-a", "semverStart": "0.5.0", "semverEnd": "0.5.2"}
			],
			"visibility": "draft"
		}`, keptID)

		req := httptest.NewRequest("PATCH", "/advisory/"+strconv.FormatInt(advisoryID, 10)+"/", bytes.NewBufferString(patchBody))
		req.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		ctx := app.NewContext(req, recorder)
		ctx.SetParamNames("id")
		ctx.SetParamValues(strconv.FormatInt(advisoryID, 10))
		setupContext(ctx)
		assert.Nil(t, controller.Update(ctx))
		assert.Equal(t, 200, recorder.Code)

		var advisory models.Advisory
		assert.Nil(t, f.DB.Preload("AffectedPackages").First(&advisory, "id = ?", advisoryID).Error)
		assert.Len(t, advisory.AffectedPackages, 1, "the removed affected package must not still be associated with the advisory")
		assert.Equal(t, "pkg:csaf-validator-a", advisory.AffectedPackages[0].PackageName)

		var orphanCount int64
		assert.Nil(t, f.DB.Table("affected_packages").Where("package_name = ?", "pkg:csaf-validator-b").Count(&orphanCount).Error)
		assert.Equal(t, int64(0), orphanCount, "the removed affected package row itself must be deleted, not just unlinked")
	})
}
