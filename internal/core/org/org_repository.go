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

package org

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/database"
)

type gormRepository struct {
	db core.DB
	database.Repository[uuid.UUID, Model, core.DB]
}

type repository interface {
	database.Repository[uuid.UUID, Model, core.DB]
	// ReadBySlug reads an organization by its slug
	ReadBySlug(slug string) (Model, error)
}

func NewGormRepository(db core.DB) *gormRepository {
	return &gormRepository{
		db:         db,
		Repository: database.NewGormRepository[uuid.UUID, Model](db),
	}
}

func (g *gormRepository) ReadBySlug(slug string) (Model, error) {
	var t Model
	err := g.db.Where("slug = ?", slug).First(&t).Error
	return t, err
}
