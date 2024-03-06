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

package pat

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/database"
)

type gormPatRepository struct {
	database.Repository[uuid.UUID, Model, core.DB]
	db core.DB
}

type repository interface {
	database.Repository[uuid.UUID, Model, core.DB]
	ReadByToken(token string) (Model, error)
	ListByUserID(userId string) ([]Model, error)
	GetUserIDByToken(token string) (string, error)
}

func NewGormRepository(db core.DB) *gormPatRepository {
	return &gormPatRepository{
		db:         db,
		Repository: database.NewGormRepository[uuid.UUID, Model](db),
	}
}

func (g *gormPatRepository) ReadByToken(token string) (Model, error) {
	var t Model
	// make sure to hash the token before querying
	err := g.db.First(&t, "token = ?", t.HashToken(token)).Error
	return t, err
}

func (g *gormPatRepository) ListByUserID(userId string) ([]Model, error) {
	var pats []Model
	err := g.db.Where("user_id = ?", userId).Find(&pats).Error
	return pats, err
}

func (g *gormPatRepository) GetUserIDByToken(token string) (string, error) {
	var t Model
	err := g.db.First(&t, "token = ?", t.HashToken(token)).Error
	return t.UserID.String(), err
}
