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
	"gorm.io/gorm"
)

type Repository[ID any, T any] interface {
	Create(t *T) error
	Read(id ID) (T, error)
	Update(t *T) error
	Delete(id ID) error
	List(ids []ID) ([]T, error)
}

type GormRepository[ID comparable, T any] struct {
	db *gorm.DB
}

func NewGormRepository[ID comparable, T any](db *gorm.DB) Repository[ID, T] {
	return &GormRepository[ID, T]{
		db: db,
	}
}

func (g *GormRepository[ID, T]) Create(t *T) error {
	return g.db.Create(t).Error
}

func (g *GormRepository[ID, T]) Read(id ID) (T, error) {
	var t T
	err := g.db.First(&t, id).Error
	return t, err
}

func (g *GormRepository[ID, T]) Update(t *T) error {
	return g.db.Save(t).Error
}

func (g *GormRepository[ID, T]) Delete(id ID) error {
	return g.db.Delete(id).Error
}

func (g *GormRepository[ID, T]) List(ids []ID) ([]T, error) {
	var ts []T
	err := g.db.Find(&ts, ids).Error
	if err != nil {
		return ts, err
	}
	return ts, nil
}
