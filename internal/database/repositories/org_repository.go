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
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type orgRepository struct {
	db core.DB
	Repository[uuid.UUID, models.Org, core.DB]
}

func NewOrgRepository(db core.DB) *orgRepository {
	if err := db.AutoMigrate(&models.Org{}); err != nil {
		panic(err)
	}
	return &orgRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.Org](db),
	}
}

func (g *orgRepository) ReadBySlug(slug string) (models.Org, error) {
	var t models.Org
	err := g.db.Where("slug = ?", slug).First(&t).Error
	return t, err
}
