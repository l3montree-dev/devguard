// Copyright (C) 2023 Tim Bastin, l3montree UG (haftungsbeschränkt)
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
	"github.com/l3montree-dev/devguard/internal/common"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type GormRepository[ID comparable, T common.Tabler] struct {
	db *gorm.DB
}

func newGormRepository[ID comparable, T common.Tabler](db *gorm.DB) *GormRepository[ID, T] {
	return &GormRepository[ID, T]{
		db: db,
	}
}

func (g *GormRepository[ID, T]) All() ([]T, error) {
	var ts []T
	err := g.db.Find(&ts).Error
	return ts, err
}

func (g *GormRepository[ID, T]) DeleteBatch(tx *gorm.DB, m []T) error {
	err := g.GetDB(tx).Delete(m).Error
	if err != nil {
		return err
	}
	return nil
}

func (g *GormRepository[ID, T]) Save(tx *gorm.DB, t *T) error {
	return g.GetDB(tx).Save(t).Error
}

func (g *GormRepository[ID, T]) Upsert(t *[]*T, conflictingColumns *[]clause.Column) error {
	if len(*t) == 0 {
		return nil
	}
	if conflictingColumns == nil {
		return g.db.Clauses(clause.OnConflict{UpdateAll: true}).Create(t).Error
	}

	return g.db.Clauses(clause.OnConflict{UpdateAll: true, Columns: *conflictingColumns}).Create(t).Error
}

func (g *GormRepository[ID, T]) SaveBatch(tx *gorm.DB, ts []T) error {
	if len(ts) == 0 {
		return nil
	}

	err := g.GetDB(tx).Save(ts).Error
	// check if "extended protocol limited to 65535 parameters" error
	if err != nil && err.Error() == "extended protocol limited to 65535 parameters" {
		// split the batch in half and try again
		half := len(ts) / 2
		err = g.SaveBatch(tx, ts[:half])
		if err != nil {
			return err
		}
		err = g.SaveBatch(tx, ts[half:])
	}
	return err
}

func (g *GormRepository[ID, T]) Transaction(f func(tx *gorm.DB) error) error {
	tx := g.db.Begin()
	err := f(tx)
	if err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit().Error
}

func (g *GormRepository[ID, T]) Begin() *gorm.DB {
	return g.db.Begin()
}

func (g *GormRepository[ID, T]) GetDB(tx *gorm.DB) *gorm.DB {
	if tx != nil {
		return tx
	}

	return g.db
}

func (g *GormRepository[ID, T]) Create(tx *gorm.DB, t *T) error {
	return g.GetDB(tx).Create(t).Error
}

func (g *GormRepository[ID, T]) CreateBatch(tx *gorm.DB, ts []T) error {
	if len(ts) == 0 {
		return nil
	}
	return g.GetDB(tx).Clauses(clause.OnConflict{DoNothing: true}).Create(ts).Error
}

func (g *GormRepository[ID, T]) Read(id ID) (T, error) {
	var t T
	err := g.db.First(&t, "id = ?", id).Error

	return t, err
}

func (g *GormRepository[ID, T]) Delete(tx *gorm.DB, id ID) error {
	var t T
	return g.GetDB(tx).Delete(&t, id).Error
}

func (g *GormRepository[ID, T]) List(ids []ID) ([]T, error) {
	if len(ids) == 0 {
		return []T{}, nil
	}
	var ts []T

	err := g.db.Find(&ts, ids).Error
	if err != nil {
		return ts, err
	}
	return ts, nil
}

func (g *GormRepository[ID, T]) Activate(tx *gorm.DB, id ID) error {
	var t T
	return g.GetDB(tx).Model(&t).Unscoped().Where("id = ?", id).Update("deleted_at", nil).Error
}
