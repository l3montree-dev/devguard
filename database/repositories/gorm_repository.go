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
	"strings"

	"github.com/google/uuid"
	"github.com/in-toto/go-witness/log"
	"github.com/jackc/pgx/v5/pgconn"
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
	err := g.GetDB(ctx, tx).First(&t, "id = ?", id).Error
	return t, err
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
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23503": // FK violation
			return true
		case "23505": // unique violation (optional)
			return true
		}
	}

	return false
}
