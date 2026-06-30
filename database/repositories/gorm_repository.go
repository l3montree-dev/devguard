// Copyright (C) 2023 Tim Bastin, l3montree GmbH
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

package repositories

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"

	"github.com/google/uuid"
	"github.com/in-toto/go-witness/log"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type GormRepository[ID comparable, T utils.Tabler] struct {
	db *gorm.DB
}

func newGormRepository[ID comparable, T utils.Tabler](db *gorm.DB) *GormRepository[ID, T] {
	return &GormRepository[ID, T]{
		db: db,
	}
}

func (g *GormRepository[ID, T]) All(ctx context.Context, tx *gorm.DB) ([]T, error) {
	var ts []T
	err := g.GetDB(ctx, tx).Find(&ts).Error
	return ts, err
}

func (g *GormRepository[ID, T]) DeleteBatch(ctx context.Context, tx *gorm.DB, m []T) error {
	err := g.GetDB(ctx, tx).Delete(m).Error
	if err != nil {
		return err
	}
	return nil
}

func (g *GormRepository[ID, T]) Save(ctx context.Context, tx *gorm.DB, t *T) error {
	return g.GetDB(ctx, tx).Save(t).Error
}

func (g *GormRepository[ID, T]) Upsert(ctx context.Context, tx *gorm.DB, t *[]*T, conflictingColumns []clause.Column, updateOnly []string) error {
	if len(*t) == 0 {
		return nil
	}
	db := g.GetDB(ctx, tx)
	if len(conflictingColumns) == 0 {
		if len(updateOnly) > 0 {
			return db.Clauses(clause.OnConflict{DoUpdates: clause.AssignmentColumns(updateOnly)}).Create(t).Error
		}
		return db.Clauses(clause.OnConflict{UpdateAll: true}).Create(t).Error
	}

	if len(updateOnly) > 0 {
		return db.Clauses(clause.OnConflict{
			DoUpdates: clause.AssignmentColumns(updateOnly),
			Columns:   conflictingColumns,
		}).Create(t).Error
	}

	return db.Clauses(clause.OnConflict{UpdateAll: true, Columns: conflictingColumns}).Create(t).Error
}

// it does not save any associations, so it is the caller's responsibility to save them separately if needed
func (g *GormRepository[ID, T]) SaveBatchBestEffort(
	ctx context.Context,
	tx *gorm.DB,
	ts []T,
) error {
	if len(ts) == 0 {
		return nil
	}

	db := g.GetDB(ctx, tx)
	sp := fmt.Sprintf("sp%s", strings.ReplaceAll(uuid.NewString(), "-", ""))
	if err := db.SavePoint(sp).Error; err != nil {
		return err
	}

	err := db.Omit(clause.Associations).Save(ts).Error
	if err == nil {
		return nil
	}

	// Roll back to savepoint so the transaction is still usable for retries.
	if rbErr := db.RollbackTo(sp).Error; rbErr != nil {
		// Preserve both the original save error and the rollback error for diagnostics.
		return fmt.Errorf("failed to rollback to savepoint after SaveBatchBestEffort error: %w (rollback error: %v)", err, rbErr)
	}

	// Base case: single row
	if len(ts) == 1 {
		if isIgnorableUpsertError(err) {
			log.Warn("dropping row during best-effort upsert", "row", ts[0], "err", err)
			return nil
		}
		return err
	}

	// Split and retry
	half := len(ts) / 2
	if err := g.SaveBatchBestEffort(ctx, tx, ts[:half]); err != nil {
		return err
	}
	return g.SaveBatchBestEffort(ctx, tx, ts[half:])
}

func (g *GormRepository[ID, T]) SaveBatch(ctx context.Context, tx *gorm.DB, ts []T) error {
	if len(ts) == 0 {
		return nil
	}

	err := g.GetDB(ctx, tx).Save(ts).Error
	// check if "extended protocol limited to 65535 parameters" error
	if err != nil && err.Error() == "extended protocol limited to 65535 parameters" {
		// split the batch in half and try again
		half := len(ts) / 2
		err = g.SaveBatch(ctx, tx, ts[:half])
		if err != nil {
			return err
		}
		err = g.SaveBatch(ctx, tx, ts[half:])
	}
	return err
}

func (g *GormRepository[ID, T]) Transaction(ctx context.Context, f func(tx *gorm.DB) error) error {
	tx := g.GetDB(ctx, nil).Begin()
	defer tx.Rollback()
	err := f(tx)
	if err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit().Error
}

func (g *GormRepository[ID, T]) Begin(ctx context.Context) *gorm.DB {
	return g.GetDB(ctx, nil).Begin()
}

func (g *GormRepository[ID, T]) GetDB(ctx context.Context, tx *gorm.DB) *gorm.DB {
	if tx != nil {
		return tx
	}
	return g.db.WithContext(ctx)
}

func (g *GormRepository[ID, T]) Create(ctx context.Context, tx *gorm.DB, t *T) error {
	return g.GetDB(ctx, tx).Create(t).Error
}

func (g *GormRepository[ID, T]) CreateBatch(ctx context.Context, tx *gorm.DB, ts []T) error {
	if len(ts) == 0 {
		return nil
	}
	return g.GetDB(ctx, tx).Clauses(clause.OnConflict{DoNothing: true}).Create(ts).Error
}

func (g *GormRepository[ID, T]) Read(ctx context.Context, tx *gorm.DB, id ID) (T, error) {
	var t T
	db := g.GetDB(ctx, tx).Where("id = ?", id)
	if ids, ok := shared.TenantIDsFromCtx(ctx); ok {
		db = db.Scopes(autoTenantScope(t, ids))
	}
	err := db.First(&t).Error
	return t, err
}

// withTenantScope applies autoTenantScope to db when tenant IDs are present in
// ctx. Use this in custom Read() overrides that need Preload chains but must
// still enforce the tenant boundary.
func withTenantScope(ctx context.Context, db *gorm.DB, model any) *gorm.DB {
	if ids, ok := shared.TenantIDsFromCtx(ctx); ok {
		return db.Scopes(autoTenantScope(model, ids))
	}
	return db
}

// autoTenantScope inspects the GORM struct tags and field names of model
// (including embedded structs) to detect a tenant column (asset_id,
// project_id, organization_id) and returns a scope that filters by the
// corresponding ID from ids. Models without any tenant column (e.g.
// Component, CVE) are returned unscoped.
//
// Column detection uses two strategies:
//  1. Explicit gorm:"column:asset_id" tag
//  2. Go field name AssetID / ProjectID / OrganizationID (GORM default naming)
//
// reflect.VisibleFields is used so embedded struct fields are included.
func autoTenantScope(model any, ids models.TenantIDs) func(*gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		t := reflect.TypeOf(model)
		if t.Kind() == reflect.Pointer {
			t = t.Elem()
		}
		for _, f := range reflect.VisibleFields(t) {
			tag := f.Tag.Get("gorm")
			name := f.Name
			switch {
			case strings.Contains(tag, "column:asset_id") || name == "AssetID":
				return db.Where("asset_id = ?", ids.AssetID)
			case strings.Contains(tag, "column:project_id") || name == "ProjectID":
				return db.Where("project_id = ?", ids.ProjectID)
			case strings.Contains(tag, "column:organization_id") || name == "OrganizationID":
				return db.Where("organization_id = ?", ids.OrgID)
			}
		}
		return db
	}
}

func (g *GormRepository[ID, T]) Delete(ctx context.Context, tx *gorm.DB, id ID) error {
	var t T
	return g.GetDB(ctx, tx).Delete(&t, id).Error
}

func (g *GormRepository[ID, T]) List(ctx context.Context, tx *gorm.DB, ids []ID) ([]T, error) {
	if len(ids) == 0 {
		return []T{}, nil
	}
	var ts []T

	err := g.GetDB(ctx, tx).Find(&ts, ids).Error
	if err != nil {
		return ts, err
	}
	return ts, nil
}

func (g *GormRepository[ID, T]) Activate(ctx context.Context, tx *gorm.DB, id ID) error {
	var t T
	return g.GetDB(ctx, tx).Model(&t).Unscoped().Where("id = ?", id).Update("deleted_at", nil).Error
}

func (g *GormRepository[ID, T]) CleanupOrphanedRecords(ctx context.Context) error {
	if err := g.GetDB(ctx, nil).Exec(CleanupOrphanedRecordsSQL).Error; err != nil {
		slog.Error("Failed to clean up orphaned records after deleting artifact", "err", err)
		return err
	}
	return nil
}

func isIgnorableUpsertError(err error) bool {
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok {
		switch pgErr.Code {
		case "23503": // FK violation
			return true
		case "23505": // unique violation (optional)
			return true
		}
	}

	return false
}

var CleanupOrphanedRecordsSQL = `
DELETE FROM dependency_vulns dv
WHERE NOT EXISTS (SELECT artifact_dependency_vulns.dependency_vuln_id FROM artifact_dependency_vulns WHERE artifact_dependency_vulns.dependency_vuln_id = dv.id);

DELETE FROM license_risks lr
WHERE NOT EXISTS (SELECT artifact_license_risks.license_risk_id FROM artifact_license_risks WHERE artifact_license_risks.license_risk_id = lr.id);

-- Clean up artifact root nodes (component_id = 'ROOT', dependency_id LIKE 'artifact:%')
-- where the artifact no longer exists
DELETE FROM component_dependencies cd
WHERE cd.component_id = 'ROOT'
AND cd.dependency_id LIKE 'artifact:%'
AND NOT EXISTS (
    SELECT 1 FROM artifacts a
    WHERE 'artifact:' || a.artifact_name = cd.dependency_id
    AND a.asset_version_name = cd.asset_version_name
    AND a.asset_id = cd.asset_id
);

-- Clean up component_dependencies that point to non-existent artifacts
DELETE FROM component_dependencies cd
WHERE cd.component_id LIKE 'artifact:%'
AND NOT EXISTS (
    SELECT 1 FROM artifacts a
    WHERE 'artifact:' || a.artifact_name = cd.component_id
    AND a.asset_version_name = cd.asset_version_name
    AND a.asset_id = cd.asset_id
);

DELETE FROM vuln_events ve WHERE ve.dependency_vuln_id IS NOT NULL AND NOT EXISTS (
    SELECT dependency_vulns.id FROM dependency_vulns WHERE dependency_vulns.id = ve.dependency_vuln_id
);

DELETE FROM vuln_events ve WHERE ve.first_party_vuln_id IS NOT NULL AND NOT EXISTS(
	SELECT first_party_vulnerabilities.id FROM first_party_vulnerabilities WHERE first_party_vulnerabilities.id = ve.first_party_vuln_id
);

DELETE FROM vuln_events ve WHERE ve.license_risk_id IS NOT NULL AND NOT EXISTS(
	SELECT license_risks.id FROM license_risks WHERE license_risks.id = ve.license_risk_id
);
`
