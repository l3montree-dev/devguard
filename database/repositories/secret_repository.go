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
