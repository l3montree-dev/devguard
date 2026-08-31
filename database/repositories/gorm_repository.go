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
	"iter"
	"log/slog"
	"reflect"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/l3montree-dev/devguard/database"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type GormRepository[ID comparable, T utils.Tabler] struct {
	db              *gorm.DB
	createBatchSize int
}

func newGormRepository[ID comparable, T utils.Tabler](db *gorm.DB) *GormRepository[ID, T] {
	batchSize, err := database.CalcBatchSize(db, new(T))
	if err != nil {
		panic(fmt.Errorf("error calculating batch size: %w", err))
	}
	return &GormRepository[ID, T]{
		db:              db,
		createBatchSize: batchSize,
	}
}

func (g *GormRepository[ID, T]) InBatches(ctx context.Context, tx *gorm.DB, batchSize int) iter.Seq2[[]T, error] {
	return func(yield func([]T, error) bool) {
		db := g.GetDB(ctx, tx)

		stmt := &gorm.Statement{DB: db}
		if err := stmt.Parse(new(T)); err != nil {
			yield(nil, fmt.Errorf("failed to parse schema for batched query: %w", err))
			return
		}
		if len(stmt.Schema.PrimaryFields) != 1 {
			yield(nil, fmt.Errorf("InBatches requires exactly one primary key column, got %d", len(stmt.Schema.PrimaryFields)))
			return
		}
		pkField := stmt.Schema.PrimaryFields[0]

		var lastID any
		hasLastID := false

		for {
			var res = []T{}
			query := db.Order(pkField.DBName)
			if hasLastID {
				query = query.Where(fmt.Sprintf("%s > ?", pkField.DBName), lastID)
			}
			if batchSize > 0 {
				query = query.Limit(batchSize)
			}
			if err := query.Find(&res).Error; err != nil {
				yield(nil, err)
				return
			}

			if len(res) == 0 {
				return
			}

			if !yield(res, nil) {
				return
			}

			// batchSize <= 0 means "no limit" (GORM treats Limit(-1) as unlimited) -
			// the query above already returned everything there is, so stop instead
			// of issuing a second, pointless round trip.
			if batchSize <= 0 || len(res) < batchSize {
				return
			}

			lastID = reflect.ValueOf(res[len(res)-1]).FieldByName(pkField.Name).Interface()
			hasLastID = true
		}
	}
}

func (g *GormRepository[ID, T]) All(ctx context.Context, tx *gorm.DB) ([]T, error) {
	var ts []T
	err := g.GetDB(ctx, tx).Find(&ts).Error
	return ts, err
}

func (g *GormRepository[ID, T]) DeleteBatch(ctx context.Context, tx *gorm.DB, entries []T) error {
	return g.executeOperationInBatch(ctx, tx, entries, func(db *gorm.DB, batch []T) *gorm.DB {
		return db.Delete(batch)
	})
}

// the receiver is passed in instead of being bound by the caller so every batch runs on a
// fresh session - a closure is needed because gorm's finishers differ in shape (Delete is
// variadic, Save is often chained behind Omit), so no single method expression fits them all
func (g *GormRepository[ID, T]) executeOperationInBatch(ctx context.Context, tx *gorm.DB, entries []T, operation func(db *gorm.DB, batch []T) *gorm.DB) error {
	for start := 0; start < len(entries); start += g.createBatchSize {
		end := min(start+g.createBatchSize, len(entries))
		if err := operation(g.GetDB(ctx, tx), entries[start:end]).Error; err != nil {
			return fmt.Errorf("could not execute batch %d - %d: %w", start, end, err)
		}
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

func (g *GormRepository[ID, T]) SaveBatch(ctx context.Context, tx *gorm.DB, ts []T) error {
	return g.executeOperationInBatch(ctx, tx, ts, func(db *gorm.DB, batch []T) *gorm.DB {
		return db.Omit(clause.Associations).Save(batch)
	})
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
		return tx.Session(&gorm.Session{CreateBatchSize: g.createBatchSize})
	}
	return g.db.Session(&gorm.Session{Context: ctx, CreateBatchSize: g.createBatchSize})
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
	if ids, ok := shared.OwnershipScopeFromCtx(ctx); ok {
		db = db.Scopes(autoOwnershipScope(t, ids))
	}
	err := db.First(&t).Error
	return t, err
}

// withOwnershipScope applies autoOwnershipScope to db when tenant IDs are present in
// ctx. Use this in custom Read() overrides that need Preload chains but must
// still enforce the tenant boundary.
func withOwnershipScope(ctx context.Context, db *gorm.DB, model any) *gorm.DB {
	if ids, ok := shared.OwnershipScopeFromCtx(ctx); ok {
		return db.Scopes(autoOwnershipScope(model, ids))
	}
	return db
}

func gormColumnName(tag string) string {
	for _, part := range strings.Split(tag, ";") {
		part = strings.TrimSpace(part)
		if after, ok := strings.CutPrefix(part, "column:"); ok {
			return after
		}
	}
	return ""
}

// autoOwnershipScope inspects the GORM struct tags and field names of model (including embedded
// structs) to detect tenant columns (asset_id, project_id, organization_id/org_id) and ANDs a
// filter for every one found - not just the first, since some models (e.g. WebhookIntegration)
// have more than one (GHSA-gxhm-8569-26mq). A *pointer* tenant field (nullable column, e.g.
// WebhookIntegration.ProjectID) is only constrained when ids carries a value for it, so a
// broader-scoped request doesn't wrongly exclude rows whose optional tenant column is NULL; a
// non-pointer field is always constrained, preserving the old fail-closed behavior.
func autoOwnershipScope(model any, ids models.OwnershipScope) func(*gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		t := reflect.TypeOf(model)
		if t.Kind() == reflect.Pointer {
			t = t.Elem()
		}
		for _, f := range reflect.VisibleFields(t) {
			tag := f.Tag.Get("gorm")
			name := f.Name
			col := gormColumnName(tag)
			nullable := f.Type.Kind() == reflect.Pointer
			switch {
			case col == "asset_id" || name == "AssetID":
				if !nullable || ids.AssetID != uuid.Nil {
					db = db.Where("asset_id = ?", ids.AssetID)
				}
			case col == "project_id" || name == "ProjectID":
				if !nullable || ids.ProjectID != uuid.Nil {
					db = db.Where("project_id = ?", ids.ProjectID)
				}
			case col == "organization_id" || col == "org_id" || name == "OrganizationID" || name == "OrgID":
				orgColumn := col
				if orgColumn == "" {
					orgColumn = "organization_id"
				}
				if !nullable || ids.OrgID != uuid.Nil {
					db = db.Where(orgColumn+" = ?", ids.OrgID)
				}
			}
		}
		return db
	}
}

func (g *GormRepository[ID, T]) Delete(ctx context.Context, tx *gorm.DB, id ID) error {
	var t T
	db := g.GetDB(ctx, tx).Where("id = ?", id)
	if ids, ok := shared.OwnershipScopeFromCtx(ctx); ok {
		db = db.Scopes(autoOwnershipScope(t, ids))
	}
	res := db.Delete(&t)
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
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
	return g.GetDB(ctx, tx).Model(&t).Unscoped().Where("id = ?", id).Update("deleted_at", nil).Error // nosemgrep: bola-repository-update-missing-tenant-scope
}

func (g *GormRepository[ID, T]) CleanupOrphanedRecords(ctx context.Context) error {
	if err := g.GetDB(ctx, nil).Exec(CleanupOrphanedRecordsSQL).Error; err != nil {
		slog.Error("Failed to clean up orphaned records after deleting artifact", "err", err)
		return err
	}
	return nil
}

// delete if unused
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
