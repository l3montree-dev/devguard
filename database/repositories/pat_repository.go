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

// ReadUnscoped/DeleteUnscoped are deliberately unscoped by tenant - the "Unscoped"
// name signals that ownership must be verified by the caller before acting on the
// result. Every call site (controllers/pat_controller.go's Delete/DeleteByOrg/
// DeleteByProject/DeleteByAsset) does exactly that: ReadUnscoped fetches the PAT,
// the controller checks pat.UserID/OrgID/ProjectID/AssetID against the caller's
// verified scope and 403s on mismatch, and only then calls DeleteUnscoped with the
// same, already-verified id.
func (g *gormPatRepository) ReadUnscoped(ctx context.Context, tx *gorm.DB, id uuid.UUID) (models.PAT, error) {
	var t models.PAT
	err := g.GetDB(ctx, tx).First(&t, "id = ?", id).Error // nosemgrep: bola-raw-gorm-first-bypasses-tenant-scope -- ownership verified by every caller before use, see comment above
	return t, err
}

func (g *gormPatRepository) DeleteUnscoped(ctx context.Context, tx *gorm.DB, id uuid.UUID) error {
	res := g.GetDB(ctx, tx).Where("id = ?", id).Delete(&models.PAT{}) // nosemgrep: bola-repository-delete-missing-tenant-scope -- ownership verified by every caller before use, see comment above
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// MarkAsLastUsedNowByID scopes by id only: id is the PAT's own ID, resolved from a token the
// caller already presented and that was matched by fingerprint (proof of possession), not from
// a raw user-suppliable path param.
func (g *gormPatRepository) MarkAsLastUsedNowByID(ctx context.Context, tx *gorm.DB, id uuid.UUID) error {
	return g.GetDB(ctx, tx).Model(&models.PAT{}).Where("id = ?", id).Update("last_used_at", time.Now()).Error // nosemgrep: bola-repository-update-missing-tenant-scope
}

func (g *gormPatRepository) DeleteByFingerprint(ctx context.Context, tx *gorm.DB, fingerprint string) error {
	return g.GetDB(ctx, tx).Where("fingerprint = ?", fingerprint).Delete(&models.PAT{}).Error
}

func (g *gormPatRepository) ListByUserID(ctx context.Context, tx *gorm.DB, userID string) ([]models.PAT, error) {
	var pats []models.PAT
	err := g.GetDB(ctx, tx).Where("user_id = ?", userID).Find(&pats).Error
	return pats, err
}

func (g *gormPatRepository) ListByOrgID(ctx context.Context, tx *gorm.DB, orgID uuid.UUID) ([]models.PAT, error) {
	var pats []models.PAT
	err := g.GetDB(ctx, tx).Where("org_id = ?", orgID).Find(&pats).Error
	return pats, err
}

func (g *gormPatRepository) ListByProjectID(ctx context.Context, tx *gorm.DB, projectID uuid.UUID) ([]models.PAT, error) {
	var pats []models.PAT
	err := g.GetDB(ctx, tx).Where("project_id = ?", projectID).Find(&pats).Error
	return pats, err
}

func (g *gormPatRepository) ListByAssetID(ctx context.Context, tx *gorm.DB, assetID uuid.UUID) ([]models.PAT, error) {
	var pats []models.PAT
	err := g.GetDB(ctx, tx).Where("asset_id = ?", assetID).Find(&pats).Error
	return pats, err
}

// checks if a valid token exists for the fingerprint, this excludes any expired tokens
func (g *gormPatRepository) GetByFingerprint(ctx context.Context, tx *gorm.DB, fingerprint string) (models.PAT, error) {
	var t models.PAT
	err := g.GetDB(ctx, tx).First(&t, "fingerprint = ?", fingerprint).Error
	return t, err
}

func (g *gormPatRepository) GetByBearerTokenHash(ctx context.Context, tx *gorm.DB, tokenHash string) (models.PAT, error) {
	var t models.PAT
	err := g.GetDB(ctx, tx).First(&t, "bearer_token_hash = ?", tokenHash).Error
	return t, err
}

func (g *gormPatRepository) FindByUserIDs(ctx context.Context, tx *gorm.DB, userIDs []uuid.UUID) ([]models.PAT, error) {
	var pats []models.PAT
	err := g.GetDB(ctx, tx).Where("user_id IN (?)", userIDs).Find(&pats).Error
	return pats, err
}