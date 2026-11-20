// Copyright (C) 2026 l3montree GmbH
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
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package repositories

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
)

type secretRepository struct {
	db *gorm.DB
	utils.Repository[uuid.UUID, models.Secret, *gorm.DB]
	encryptionService shared.DBEncryptionService
}

func NewSecretRepository(db *gorm.DB, encryptionService shared.DBEncryptionService) *secretRepository {
	return &secretRepository{db: db,
		Repository: newGormRepository[uuid.UUID, models.Secret](db), encryptionService: encryptionService}
}

func (r *secretRepository) encryptSecretInPlace(ctx context.Context, secret models.Secret) (models.Secret, error) {
	if secret.Value == "" {
		return secret, nil
	}

	encryptedSecret, err := r.encryptionService.EncryptAndWrapData(secret.Value)
	if err != nil {
		return secret, fmt.Errorf("could not encrypt secret before saving to db: %w", err)
	}
	secret.Value = encryptedSecret

	return secret, nil
}

func (r *secretRepository) decryptSecretInPlace(ctx context.Context, secret *models.Secret) error {
	if secret.Value == "" {
		return nil
	}

	decryptedSecret, err := r.encryptionService.MaybeDecryptData(secret.Value)
	if err != nil {
		return fmt.Errorf("could not decrypt secret: %w", err)
	}
	secret.Value = decryptedSecret

	return nil
}

func (r *secretRepository) Save(ctx context.Context, tx *gorm.DB, secret *models.Secret) error {
	encrypted, err := r.encryptSecretInPlace(ctx, *secret)
	if err != nil {
		return err
	}

	originalSecret := secret.Value
	secret.Value = encrypted.Value
	defer func() { secret.Value = originalSecret }()

	return r.Repository.Save(ctx, tx, secret)
}

func (r *secretRepository) FindVisible(ctx context.Context, tx *gorm.DB, orgID uuid.UUID, projectID, assetID *uuid.UUID) ([]models.Secret, error) {
	var secrets []models.Secret

	query := r.GetDB(ctx, tx).Where("org_id = ?", orgID)
	if projectID != nil {
		query = query.Or(`project_id IN (
			WITH RECURSIVE ancestors AS (
				SELECT id, parent_id FROM projects WHERE id = ?
				UNION ALL
				SELECT p.id, p.parent_id FROM projects p JOIN ancestors a ON p.id = a.parent_id
			) SELECT id FROM ancestors
		)`, *projectID)
	}
	if assetID != nil {
		query = query.Or("asset_id = ?", *assetID)
	}

	if err := query.Find(&secrets).Error; err != nil {
		return nil, err
	}

	for i := range secrets {
		if err := r.decryptSecretInPlace(ctx, &secrets[i]); err != nil {
			return nil, err
		}
	}

	return secrets, nil
}

func (r *secretRepository) DeleteOwned(ctx context.Context, tx *gorm.DB, id, orgID uuid.UUID, projectID, assetID *uuid.UUID) error {
	query := r.GetDB(ctx, tx).Where("id = ?", id)
	switch {
	case assetID != nil:
		query = query.Where("asset_id = ?", *assetID)
	case projectID != nil:
		query = query.Where("project_id = ?", *projectID)
	default:
		query = query.Where("org_id = ?", orgID)
	}

	result := query.Delete(&models.Secret{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}
