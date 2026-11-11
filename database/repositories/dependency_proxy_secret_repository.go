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

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
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

var _ shared.DependencyProxySecretRepository = (*dependencyProxySecretRepository)(nil)

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

			err = r.createWithSigningKey(ctx, tx, &newProxy)
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
			err = r.createWithSigningKey(ctx, tx, &newProxy)
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
			err = r.createWithSigningKey(ctx, tx, &newProxy)
			return newProxy, err
		}
		return proxy, err
	}
	return proxy, err
}

func (r *dependencyProxySecretRepository) UpdateSecret(ctx context.Context, tx *gorm.DB, proxy models.DependencyProxySecret) (models.DependencyProxySecret, error) {
	exec := func(db *gorm.DB) error {
		newSecret := uuid.New()
		encryptedPrivateKey, publicKey, err := generateEncryptedSigningKey(r.encryptionService)
		if err != nil {
			return err
		}
		if err := db.Model(&models.DependencyProxySecret{}).Where("secret = ?", proxy.Secret).Updates(map[string]any{
			"secret":              newSecret,
			"signing_private_key": encryptedPrivateKey,
			"signing_public_key":  publicKey,
		}).Error; err != nil {
			return err
		}
		proxy.Secret = newSecret
		proxy.SigningPrivateKey = &encryptedPrivateKey
		proxy.SigningPublicKey = &publicKey
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

func generateSigningKey() (string, string, error) {
	key, err := crypto.PGPWithProfile(profile.RFC4880()).KeyGeneration().AddUserId("DevGuard Dependency Proxy", "noreply@devguard.org").New().GenerateKey()
	if err != nil {
		return "", "", err
	}

	privKey, err := key.Armor()
	if err != nil {
		return "", "", err
	}

	pubKey, err := key.GetArmoredPublicKey()
	if err != nil {
		return "", "", err
	}

	return privKey, pubKey, nil
}

func generateEncryptedSigningKey(encryptionService shared.DBEncryptionService) (string, string, error) {
	privateKey, publicKey, err := generateSigningKey()
	if err != nil {
		return "", "", err
	}

	encryptedPrivateKey, err := encryptionService.EncryptAndWrapData(privateKey)
	if err != nil {
		return "", "", err
	}

	return encryptedPrivateKey, publicKey, nil
}

func (r *dependencyProxySecretRepository) createWithSigningKey(ctx context.Context, tx *gorm.DB, proxy *models.DependencyProxySecret) error {
	encryptedPrivateKey, publicKey, err := generateEncryptedSigningKey(r.encryptionService)
	if err != nil {
		return err
	}

	proxy.SigningPrivateKey = &encryptedPrivateKey
	proxy.SigningPublicKey = &publicKey
	return r.Create(ctx, tx, proxy)
}

func (r *dependencyProxySecretRepository) BackfillSigningKeys(ctx context.Context, tx *gorm.DB) (int, error) {
	var proxies []models.DependencyProxySecret
	if err := r.GetDB(ctx, tx).Where("signing_private_key IS NULL OR signing_public_key IS NULL").Find(&proxies).Error; err != nil {
		return 0, err
	}

	updated := 0
	for _, proxy := range proxies {
		encryptedPrivateKey, publicKey, err := generateEncryptedSigningKey(r.encryptionService)
		if err != nil {
			return updated, err
		}
		// the IS NULL guard keeps concurrent backfills from overwriting each other's keys
		res := r.GetDB(ctx, tx).Model(&models.DependencyProxySecret{}).
			Where("secret = ? AND (signing_private_key IS NULL OR signing_public_key IS NULL)", proxy.Secret).
			Updates(map[string]any{"signing_private_key": encryptedPrivateKey, "signing_public_key": publicKey})
		if res.Error != nil {
			return updated, res.Error
		}
		updated += int(res.RowsAffected)
	}
	return updated, nil
}

func (r *dependencyProxySecretRepository) GetSigningKey(ctx context.Context, tx *gorm.DB, secret uuid.UUID) (string, string, error) {
	var proxy models.DependencyProxySecret
	if err := r.GetDB(ctx, tx).First(&proxy, "secret = ?", secret).Error; err != nil {
		return "", "", err
	}

	if proxy.SigningPrivateKey == nil || proxy.SigningPublicKey == nil {
		return "", "", fmt.Errorf("dependency proxy secret has no signing key")
	}

	privKey, err := r.encryptionService.MaybeDecryptData(*proxy.SigningPrivateKey)
	if err != nil {
		return "", "", err
	}

	return privKey, *proxy.SigningPublicKey, nil
}
