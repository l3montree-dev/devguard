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
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
)

type gormPatRepository struct {
	utils.Repository[uuid.UUID, models.PAT, *gorm.DB]
	db *gorm.DB
}

func NewPATRepository(db *gorm.DB) *gormPatRepository {
	return &gormPatRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.PAT](db),
	}
}

func (g *gormPatRepository) MarkAsLastUsedNow(fingerprint string) error {
	return g.db.Model(&models.PAT{}).Where("fingerprint = ?", fingerprint).Update("last_used_at", time.Now()).Error
}

func (g *gormPatRepository) DeleteByFingerprint(fingerprint string) error {
	return g.db.Where("fingerprint = ?", fingerprint).Delete(&models.PAT{}).Error
}

func (g *gormPatRepository) ReadByToken(token string) (models.PAT, error) {
	var t models.PAT
	// make sure to hash the token before querying
	err := g.db.First(&t, "token = ?", t.HashToken(token)).Error
	return t, err
}

func (g *gormPatRepository) ListByUserID(userID string) ([]models.PAT, error) {
	var pats []models.PAT
	err := g.db.Where("user_id = ?", userID).Find(&pats).Error
	return pats, err
}

func (g *gormPatRepository) GetUserIDByToken(token string) (string, error) {
	var t models.PAT
	err := g.db.First(&t, "token = ?", t.HashToken(token)).Error
	return t.UserID.String(), err
}

func (g *gormPatRepository) GetByFingerprint(fingerprint string) (models.PAT, error) {
	var t models.PAT
	err := g.db.First(&t, "fingerprint = ?", fingerprint).Error
	return t, err
}

func (g *gormPatRepository) FindByUserIDs(userIDs []uuid.UUID) ([]models.PAT, error) {
	var pats []models.PAT
	err := g.db.Where("user_id IN (?)", userIDs).Find(&pats).Error
	return pats, err
}
