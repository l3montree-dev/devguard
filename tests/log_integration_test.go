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
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm/logger"
)

func TestLogService_StoreCaptureException(t *testing.T) {
	t.Parallel()
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		org, project, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()

		t.Run("writes a log row with the exact ids and message passed in", func(t *testing.T) {
			err := f.App.LogService.StoreCaptureException(context.Background(), nil, org.ID, project.ID, asset.ID, assetVersion.Name, "something went wrong")
			assert.Nil(t, err)

			var stored models.Log
			err = f.DB.Where("org_id = ? AND asset_id = ?", org.ID, asset.ID).First(&stored).Error
			assert.Nil(t, err)

			assert.Equal(t, org.ID, stored.OrgID)
			assert.Equal(t, project.ID, stored.ProjectID)
			assert.Equal(t, asset.ID, stored.AssetID)
			assert.Equal(t, assetVersion.Name, stored.AssetVersionName)
			assert.Equal(t, "something went wrong", stored.Message)
			assert.Equal(t, logger.Error, stored.LogLevel)
			assert.NotEqual(t, uuid.Nil, stored.ID)
			assert.False(t, stored.CreatedAt.IsZero())
		})

		t.Run("cascades project and org ids from the asset when only assetID is given", func(t *testing.T) {
			err := f.App.LogService.StoreCaptureException(context.Background(), nil, uuid.Nil, uuid.Nil, asset.ID, "", "cascaded from asset")
			assert.Nil(t, err)

			var stored models.Log
			err = f.DB.Where("message = ?", "cascaded from asset").First(&stored).Error
			assert.Nil(t, err)

			assert.Equal(t, org.ID, stored.OrgID)
			assert.Equal(t, project.ID, stored.ProjectID)
			assert.Equal(t, asset.ID, stored.AssetID)
		})

		t.Run("cascades org id from the project when only projectID is given", func(t *testing.T) {
			err := f.App.LogService.StoreCaptureException(context.Background(), nil, uuid.Nil, project.ID, uuid.Nil, "", "cascaded from project")
			assert.Nil(t, err)

			var stored models.Log
			err = f.DB.Where("message = ?", "cascaded from project").First(&stored).Error
			assert.Nil(t, err)

			assert.Equal(t, org.ID, stored.OrgID)
			assert.Equal(t, project.ID, stored.ProjectID)
			assert.Equal(t, uuid.Nil, stored.AssetID)
		})
	})
}

func TestLogService_StoreRecoverPanic(t *testing.T) {
	t.Parallel()
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		org, project, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()

		err := f.App.LogService.StoreRecoverPanic(context.Background(), nil, org.ID, project.ID, asset.ID, assetVersion.Name, "panic message")
		assert.Nil(t, err)

		var stored models.Log
		err = f.DB.Where("message = ?", "panic message").First(&stored).Error
		assert.Nil(t, err)
		assert.Equal(t, logger.Error, stored.LogLevel)
	})
}

func TestLogService_ListPaged(t *testing.T) {
	t.Parallel()
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		org, project, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()

		otherOrg := f.CreateOrg("other-org")
		otherProject := f.CreateProject(otherOrg.ID, "other-project")
		otherAsset := f.CreateAsset(otherProject.ID, "other-asset")
		otherAssetVersion := f.CreateAssetVersion(otherAsset.ID, "main", true)

		assert.Nil(t, f.App.LogService.StoreCaptureException(context.Background(), nil, org.ID, project.ID, asset.ID, assetVersion.Name, "first"))
		assert.Nil(t, f.App.LogService.StoreCaptureException(context.Background(), nil, org.ID, project.ID, asset.ID, assetVersion.Name, "second"))
		// belongs to a different org/asset - must not leak into the results below
		assert.Nil(t, f.App.LogService.StoreCaptureException(context.Background(), nil, otherOrg.ID, otherProject.ID, otherAsset.ID, otherAssetVersion.Name, "unrelated"))

		pageInfo := shared.PageInfo{Page: 1, PageSize: 10}
		paged, err := f.App.LogRepository.ListPaged(context.Background(), nil, org.ID, project.ID, asset.ID, pageInfo)
		assert.Nil(t, err)

		assert.Equal(t, int64(2), paged.Total)
		assert.Len(t, paged.Data, 2)
		for _, l := range paged.Data {
			assert.Equal(t, org.ID, l.OrgID)
			assert.Equal(t, project.ID, l.ProjectID)
			assert.Equal(t, asset.ID, l.AssetID)
		}
	})
}
