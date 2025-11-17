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
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/stretchr/testify/require"
)

// TestFixture provides a complete test environment with database and FX app
type TestFixture struct {
	T   *testing.T
	App *TestApp
	DB  shared.DB
}

// NewTestFixture creates a complete test environment with database container and FX app
func NewTestFixture(t *testing.T, sqlInitFile string) *TestFixture {
	t.Helper()

	// Initialize database container
	db, terminate := InitDatabaseContainer(sqlInitFile)

	// Create FX test app
	app, fxApp := NewTestAppWithT(t, db, &TestAppOptions{
		SuppressLogs: true,
	})

	fixture := &TestFixture{
		T:   t,
		App: app,
		DB:  db,
	}

	// Register cleanup - this will be called in LIFO order
	t.Cleanup(func() {

		// Stop FX app first (with timeout)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = fxApp.Stop(ctx)
		// Then terminate database
		terminate()
	})

	return fixture
}

// CreateOrgProjectAssetAndVersion creates a full test hierarchy using FX services
func (f *TestFixture) CreateOrgProjectAssetAndVersion() (models.Org, models.Project, models.Asset, models.AssetVersion) {
	f.T.Helper()

	org, project, asset, assetVersion := CreateOrgProjectAndAssetAssetVersion(f.DB)
	return org, project, asset, assetVersion
}

// CreateOrg creates a test organization
func (f *TestFixture) CreateOrg(name string) models.Org {
	f.T.Helper()

	org := models.Org{
		Name:        name,
		Description: "Test Organization",
	}
	err := f.DB.Create(&org).Error
	require.NoError(f.T, err)
	return org
}

// CreateProject creates a test project
func (f *TestFixture) CreateProject(orgID uuid.UUID, name string) models.Project {
	f.T.Helper()

	project := models.Project{
		Name:           name,
		OrganizationID: orgID,
	}
	err := f.DB.Create(&project).Error
	require.NoError(f.T, err)
	return project
}

// CreateAsset creates a test asset
func (f *TestFixture) CreateAsset(projectID uuid.UUID, name string) models.Asset {
	f.T.Helper()

	asset := models.Asset{
		Name:      name,
		ProjectID: projectID,
	}
	err := f.DB.Create(&asset).Error
	require.NoError(f.T, err)
	return asset
}

// CreateAssetVersion creates a test asset version
func (f *TestFixture) CreateAssetVersion(assetID uuid.UUID, name string, isDefault bool) models.AssetVersion {
	f.T.Helper()

	assetVersion := models.AssetVersion{
		Name:          name,
		AssetID:       assetID,
		DefaultBranch: isDefault,
		Slug:          name,
		Type:          "branch",
	}
	err := f.DB.Create(&assetVersion).Error
	require.NoError(f.T, err)
	return assetVersion
}

// WithTestApp provides a callback-based pattern for tests
func WithTestApp(t *testing.T, sqlInitFile string, testFn func(*TestFixture)) {
	t.Helper()
	fixture := NewTestFixture(t, sqlInitFile)
	testFn(fixture)
}
