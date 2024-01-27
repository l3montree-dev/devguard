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

package database

import (
	"gorm.io/gorm"
)

type Tabler interface {
	TableName() string
}

type Repository[ID any, T Tabler, Tx any] interface {
	Create(tx Tx, t *T) error
	CreateBatch(tx Tx, ts []T) error
	Read(id ID) (T, error)
	Update(tx Tx, t *T) error
	UpdateBatch(tx Tx, ts []T) error
	Delete(tx Tx, id ID) error
	List(ids []ID) ([]T, error)
	Transaction(func(tx Tx) error) error
	GetDB(tx Tx) Tx

	Save(tx Tx, t *T) error
	SaveBatch(tx Tx, ts []T) error
}

type GormRepository[ID comparable, T Tabler] struct {
	db *gorm.DB
}

func NewGormRepository[ID comparable, T Tabler](db *gorm.DB) Repository[ID, T, *gorm.DB] {
	return &GormRepository[ID, T]{
		db: db,
	}
}

func (g *GormRepository[ID, T]) Save(tx *gorm.DB, t *T) error {
	return g.GetDB(tx).Save(t).Error
}

func (g *GormRepository[ID, T]) SaveBatch(tx *gorm.DB, ts []T) error {
	return g.GetDB(tx).Save(ts).Error
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
	return g.GetDB(tx).Create(ts).Error
}

func (g *GormRepository[ID, T]) Read(id ID) (T, error) {
	var t T
	err := g.db.First(&t, id).Error

	return t, err
}

func (g *GormRepository[ID, T]) Update(tx *gorm.DB, t *T) error {
	return g.GetDB(tx).Save(t).Error
}

func (g *GormRepository[ID, T]) UpdateBatch(tx *gorm.DB, ts []T) error {
	return g.GetDB(tx).Save(ts).Error
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
