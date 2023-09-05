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
	"github.com/l3montree-dev/flawfix/internal/models"
	"gorm.io/gorm"
)

type GormPatRepository struct {
	db *gorm.DB
}

func NewGormPatRepository(db *gorm.DB) *GormPatRepository {
	return &GormPatRepository{
		db: db,
	}
}

func (g *GormPatRepository) Create(t *models.PersonalAccessToken) error {
	return g.db.Create(t).Error
}

func (g *GormPatRepository) Read(id uuid.UUID) (models.PersonalAccessToken, error) {
	var t models.PersonalAccessToken
	err := g.db.First(&t, id).Error
	return t, err
}

func (g *GormPatRepository) ReadByToken(token string) (models.PersonalAccessToken, error) {
	var t models.PersonalAccessToken
	// make sure to hash the token before querying
	err := g.db.First(&t, "token = ?", t.HashToken(token)).Error
	return t, err
}

func (g *GormPatRepository) Delete(tokenId uuid.UUID) error {
	pat := models.PersonalAccessToken{}
	return g.db.Delete(&pat, "id = ?", tokenId.String()).Error
}

func (g *GormPatRepository) List(userId string) ([]models.PersonalAccessToken, error) {
	var pats []models.PersonalAccessToken
	err := g.db.Where("user_id = ?", userId).Find(&pats).Error
	return pats, err
}
