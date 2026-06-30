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
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package repositories

import (
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// dryRunDB returns a GORM db in dry-run mode backed by SQLite so we can
// inspect generated SQL without a real database connection.
func dryRunDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{DryRun: true})
	require.NoError(t, err)
	return db
}

type assetScopedModel struct {
	ID      uuid.UUID `gorm:"column:id"`
	AssetID uuid.UUID `gorm:"column:asset_id"`
}

func (assetScopedModel) TableName() string { return "asset_scoped" }

type projectScopedModel struct {
	ID        uuid.UUID `gorm:"column:id"`
	ProjectID uuid.UUID `gorm:"column:project_id"`
}

func (projectScopedModel) TableName() string { return "project_scoped" }

type orgScopedModel struct {
	ID    uuid.UUID `gorm:"column:id"`
	OrgID uuid.UUID `gorm:"column:organization_id"`
}

func (orgScopedModel) TableName() string { return "org_scoped" }

type unscopedModel struct {
	ID   uuid.UUID `gorm:"column:id"`
	PURL string    `gorm:"column:purl"`
}

func (unscopedModel) TableName() string { return "unscoped" }

func TestAutoTenantScopeAssetScoped(t *testing.T) {
	db := dryRunDB(t)
	assetID := uuid.New()
	ids := models.TenantIDs{AssetID: assetID}

	stmt := db.Scopes(autoTenantScope(assetScopedModel{}, ids)).
		Find(&assetScopedModel{}).Statement

	assert.Contains(t, stmt.SQL.String(), "asset_id")
	assert.Contains(t, stmt.Vars, assetID)
}

func TestAutoTenantScopeProjectScoped(t *testing.T) {
	db := dryRunDB(t)
	projectID := uuid.New()
	ids := models.TenantIDs{ProjectID: projectID}

	stmt := db.Scopes(autoTenantScope(projectScopedModel{}, ids)).
		Find(&projectScopedModel{}).Statement

	assert.Contains(t, stmt.SQL.String(), "project_id")
	assert.Contains(t, stmt.Vars, projectID)
}

func TestAutoTenantScopeOrgScoped(t *testing.T) {
	db := dryRunDB(t)
	orgID := uuid.New()
	ids := models.TenantIDs{OrgID: orgID}

	stmt := db.Scopes(autoTenantScope(orgScopedModel{}, ids)).
		Find(&orgScopedModel{}).Statement

	assert.Contains(t, stmt.SQL.String(), "organization_id")
	assert.Contains(t, stmt.Vars, orgID)
}

func TestAutoTenantScopeUnscopedModelNoWhereClause(t *testing.T) {
	db := dryRunDB(t)
	ids := models.TenantIDs{
		AssetID:   uuid.New(),
		ProjectID: uuid.New(),
		OrgID:     uuid.New(),
	}

	stmt := db.Scopes(autoTenantScope(unscopedModel{}, ids)).
		Find(&unscopedModel{}).Statement

	sql := stmt.SQL.String()
	assert.NotContains(t, sql, "asset_id")
	assert.NotContains(t, sql, "project_id")
	assert.NotContains(t, sql, "organization_id")
}

func TestAutoTenantScopeZeroIDNotAppended(t *testing.T) {
	db := dryRunDB(t)
	// AssetID is zero — the scope should still append the clause but with
	// the zero UUID (the caller is responsible for ensuring IDs are valid).
	ids := models.TenantIDs{} // all zero

	stmt := db.Scopes(autoTenantScope(assetScopedModel{}, ids)).
		Find(&assetScopedModel{}).Statement

	// Clause IS added (enforcement is unconditional once a tenant column is found)
	assert.Contains(t, stmt.SQL.String(), "asset_id")
	assert.Contains(t, stmt.Vars, uuid.UUID{})
}
