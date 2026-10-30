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

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
)

type dependencyProxySecretRepository struct {
	db *gorm.DB
	utils.Repository[uuid.UUID, models.DependencyProxySecret, *gorm.DB]
	encryptionService shared.DBEncryptionService
}

func NewDependencyProxyRepository(db *gorm.DB, encryptionService shared.DBEncryptionService) *dependencyProxySecretRepository {
	return &dependencyProxySecretRepository{db: db, Repository: newGormRepository[uuid.UUID, models.DependencyProxySecret](db), encryptionService: encryptionService}
}

func (r *dependencyProxySecretRepository) GetOrCreateByOrgID(ctx context.Context, tx *gorm.DB, orgID uuid.UUID) (models.DependencyProxySecret, error) {
	var proxy models.DependencyProxySecret
	err := r.db.WithContext(ctx).Where("org_id = ?", orgID).First(&proxy).Error
	//check if not exists, then create a new one
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			newProxy := models.DependencyProxySecret{
				OrgID: &orgID,
			}

			err = r.Create(ctx, tx, &newProxy)
			return newProxy, err
		}
		return proxy, err
	}
	return proxy, err
}

func (r *dependencyProxySecretRepository) GetOrCreateByProjectID(ctx context.Context, tx *gorm.DB, projectID uuid.UUID) (models.DependencyProxySecret, error) {
	var proxy models.DependencyProxySecret
	err := r.db.WithContext(ctx).Where("project_id = ?", projectID).First(&proxy).Error
	//check if not exists, then create a new one
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			newProxy := models.DependencyProxySecret{
				ProjectID: &projectID,
			}
			err = r.Create(ctx, tx, &newProxy)
			return newProxy, err
		}
		return proxy, err
	}
	return proxy, err
}

func (r *dependencyProxySecretRepository) GetOrCreateByAssetID(ctx context.Context, tx *gorm.DB, assetID uuid.UUID) (models.DependencyProxySecret, error) {
	var proxy models.DependencyProxySecret
	err := r.db.WithContext(ctx).Where("asset_id = ?", assetID).First(&proxy).Error
	//check if not exists, then create a new one
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			newProxy := models.DependencyProxySecret{
				AssetID: &assetID,
			}
			err = r.Create(ctx, tx, &newProxy)
			return newProxy, err
		}
		return proxy, err
	}
	return proxy, err
}

func (r *dependencyProxySecretRepository) UpdateSecret(ctx context.Context, tx *gorm.DB, proxy models.DependencyProxySecret) (models.DependencyProxySecret, error) {
	exec := func(db *gorm.DB) error {
		newSecret := uuid.New()
		if err := db.Model(&models.DependencyProxySecret{}).Where("secret = ?", proxy.Secret).Update("secret", newSecret).Error; err != nil {
			return err
		}
		proxy.Secret = newSecret
		return nil
	}
	var err error
	if tx != nil {
		err = exec(tx.WithContext(ctx))
	} else {
		err = r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			return exec(tx)
		})
	}
	if err != nil {
		return proxy, err
	}

	return proxy, nil
}

func (r *dependencyProxySecretRepository) GetBySecret(ctx context.Context, tx *gorm.DB, secret uuid.UUID) (models.DependencyProxySecret, error) {

	var proxy models.DependencyProxySecret

	if err := r.db.WithContext(ctx).Where("secret = ?", secret).First(&proxy).Error; err != nil {
		return proxy, err
	}

	return proxy, nil
}

func (r *dependencyProxySecretRepository) GetDebSigningKey(ctx context.Context, tx *gorm.DB, secret uuid.UUID) (string, string, bool, error) {
	var proxy models.DependencyProxySecret
	if err := r.GetDB(ctx, tx).First(&proxy, "secret = ?", secret).Error; err != nil {
		return "", "", false, err
	}

	if proxy.DebSigningPrivateKey == nil || proxy.DebSigningPublicKey == nil {
		return "", "", false, nil
	}

	privKey, err := r.encryptionService.MaybeDecryptData(*proxy.DebSigningPrivateKey)
	if err != nil {
		return "", "", false, err
	}

	return privKey, *proxy.DebSigningPublicKey, true, nil
}

func (r *dependencyProxySecretRepository) UpdateDebSigningKey(ctx context.Context, tx *gorm.DB, secret uuid.UUID, privateKey, publicKey string) error {
	encryptedText, err := r.encryptionService.EncryptAndWrapData(privateKey)
	if err != nil {
		return err
	}

	res := r.GetDB(ctx, tx).Model(&models.DependencyProxySecret{}).
		Where("secret = ?", secret).
		Updates(map[string]any{"deb_signing_private_key": encryptedText, "deb_signing_public_key": publicKey})
	return res.Error
}
