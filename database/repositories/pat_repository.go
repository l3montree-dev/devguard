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
	"fmt"
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

// overwrite internal save function with a custom one to guarantee expiry date checks on each operation
func (g *gormPatRepository) Save(ctx context.Context, tx *gorm.DB, pat *models.PAT) error {
	if pat == nil {
		return fmt.Errorf("no token provided")
	}
	if pat.ExpiryDate == nil || pat.ExpiryDate.Before(time.Now()) {
		return fmt.Errorf("could not save PAT, token is expired!")
	}
	return g.Repository.Save(ctx, tx, pat)
}

func (g *gormPatRepository) MarkAsLastUsedNow(ctx context.Context, tx *gorm.DB, fingerprint string) error {
	return g.GetDB(ctx, tx).Model(&models.PAT{}).Where("fingerprint = ?", fingerprint).Update("last_used_at", time.Now()).Error
}

func (g *gormPatRepository) DeleteByFingerprint(ctx context.Context, tx *gorm.DB, fingerprint string) error {
	return g.GetDB(ctx, tx).Where("fingerprint = ?", fingerprint).Delete(&models.PAT{}).Error
}

func (g *gormPatRepository) ReadByToken(ctx context.Context, tx *gorm.DB, token string) (models.PAT, error) {
	var t models.PAT
	// make sure to hash the token before querying
	err := g.GetDB(ctx, tx).First(&t, "token = ?", t.HashToken(token)).Error
	if err != nil {
		return t, err
	}
	if t.ExpiryDate == nil || t.ExpiryDate.Before(time.Now()) {
		return t, fmt.Errorf("PAT is expired!")
	}
	return t, nil
}

func (g *gormPatRepository) ListByUserID(ctx context.Context, tx *gorm.DB, userID string) ([]models.PAT, error) {
	var pats []models.PAT
	err := g.GetDB(ctx, tx).Where("user_id = ?", userID).Find(&pats).Error
	return pats, err
}

func (g *gormPatRepository) GetUserIDByToken(ctx context.Context, tx *gorm.DB, token string) (string, error) {
	var t models.PAT
	err := g.GetDB(ctx, tx).First(&t, "token = ?", t.HashToken(token)).Error
	if t.ExpiryDate == nil || t.ExpiryDate.Before(time.Now()) {
		return "", fmt.Errorf("PAT is expired!")
	}
	return t.UserID.String(), err
}

func (g *gormPatRepository) GetByFingerprint(ctx context.Context, tx *gorm.DB, fingerprint string) (models.PAT, error) {
	var t models.PAT
	err := g.GetDB(ctx, tx).First(&t, "fingerprint = ?", fingerprint).Error
	return t, err
}

func (g *gormPatRepository) FindByUserIDs(ctx context.Context, tx *gorm.DB, userIDs []uuid.UUID) ([]models.PAT, error) {
	var pats []models.PAT
	err := g.GetDB(ctx, tx).Where("user_id IN (?)", userIDs).Find(&pats).Error
	return pats, err
}
