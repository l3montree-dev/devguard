// Copyright (C) 2024 Tim Bastin, l3montree GmbH
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
	"gorm.io/gorm/clause"
)

type gitlabIntegrationRepository struct {
	db *gorm.DB
	utils.Repository[uuid.UUID, models.GitLabIntegration, *gorm.DB]
	encryptionService shared.DBEncryptionService
}

func NewGitLabIntegrationRepository(db *gorm.DB, encryptionService shared.DBEncryptionService) *gitlabIntegrationRepository {
	return &gitlabIntegrationRepository{
		db:                db,
		Repository:        newGormRepository[uuid.UUID, models.GitLabIntegration](db),
		encryptionService: encryptionService,
	}
}

// overwrite save function with a custom one using the encryption logic, to make sure all callers encrypt before save
func (r *gitlabIntegrationRepository) Save(ctx context.Context, tx *gorm.DB, integration *models.GitLabIntegration) error {
	originalAccessToken := integration.AccessToken
	encryptedAccessToken, err := r.encryptionService.EncryptAndWrapData(originalAccessToken)
	if err != nil {
		return fmt.Errorf("could not encrypt access token before saving to db: %w", err)
	}
	integration.AccessToken = encryptedAccessToken
	defer func() { integration.AccessToken = originalAccessToken }()

	return r.Repository.Save(ctx, tx, integration)
}

func (r *gitlabIntegrationRepository) Read(ctx context.Context, tx *gorm.DB, id uuid.UUID) (models.GitLabIntegration, error) {
	integration, err := r.Repository.Read(ctx, tx, id)
	if err != nil {
		return integration, err
	}

	decryptedAccessToken, err := r.encryptionService.MaybeDecryptData(integration.AccessToken)
	if err != nil {
		return integration, fmt.Errorf("could not decrypt fetched access token: %w", err)
	}
	integration.AccessToken = decryptedAccessToken

	return integration, nil
}

func (r *gitlabIntegrationRepository) FindByOrganizationID(ctx context.Context, tx *gorm.DB, orgID uuid.UUID) ([]models.GitLabIntegration, error) {
	var integrations []models.GitLabIntegration
	if err := r.GetDB(ctx, tx).Find(&integrations, "org_id = ?", orgID).Error; err != nil {
		return nil, err
	}

	for i := range integrations {
		decryptedAccessToken, err := r.encryptionService.MaybeDecryptData(integrations[i].AccessToken)
		if err != nil {
			return nil, fmt.Errorf("could not decrypt fetched access token: %w", err)
		}
		integrations[i].AccessToken = decryptedAccessToken
	}

	return integrations, nil
}

type gitlabOauth2TokenRepository struct {
	db                *gorm.DB
	encryptionService shared.DBEncryptionService
}

func NewGitlabOauth2TokenRepository(db *gorm.DB, encryptionService shared.DBEncryptionService) *gitlabOauth2TokenRepository {
	return &gitlabOauth2TokenRepository{
		db:                db,
		encryptionService: encryptionService,
	}
}

func (r *gitlabOauth2TokenRepository) GetDB(ctx context.Context, tx *gorm.DB) *gorm.DB {
	if tx != nil {
		return tx
	}
	return r.db.WithContext(ctx)
}

func (r *gitlabOauth2TokenRepository) Save(ctx context.Context, tx *gorm.DB, token ...*models.GitLabOauth2Token) error {
	for _, t := range token {
		restore, err := r.encryptTokenInPlace(ctx, t)
		if err != nil {
			return err
		}
		defer restore()
	}

	if err := r.GetDB(ctx, tx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "user_id"}, {Name: "provider_id"}},
		UpdateAll: true,
	}).Create(token).Error; err != nil {
		return err
	}
	return nil
}

func (r *gitlabOauth2TokenRepository) Upsert(ctx context.Context, tx *gorm.DB, token *models.GitLabOauth2Token) error {
	restore, err := r.encryptTokenInPlace(ctx, token)
	if err != nil {
		return err
	}
	defer restore()

	if err := r.GetDB(ctx, tx).Clauses(clause.OnConflict{
		UpdateAll: true,
	}).Create(token).Error; err != nil {
		return err
	}
	return nil
}

func (r *gitlabOauth2TokenRepository) FindByUserIDAndProviderID(ctx context.Context, tx *gorm.DB, userID string, providerID string) (*models.GitLabOauth2Token, error) {
	var token models.GitLabOauth2Token
	if err := r.GetDB(ctx, tx).Where("user_id = ? AND provider_id = ?", userID, providerID).First(&token).Error; err != nil {
		return nil, err
	}

	if err := r.decryptTokenInPlace(ctx, &token); err != nil {
		return nil, err
	}

	return &token, nil
}

func (r *gitlabOauth2TokenRepository) FindByUserID(ctx context.Context, tx *gorm.DB, userID string) ([]models.GitLabOauth2Token, error) {
	var tokens []models.GitLabOauth2Token
	if err := r.GetDB(ctx, tx).Where("user_id = ?", userID).Find(&tokens).Error; err != nil {
		return nil, err
	}

	for i := range tokens {
		if err := r.decryptTokenInPlace(ctx, &tokens[i]); err != nil {
			return nil, err
		}
	}

	return tokens, nil
}

func (r *gitlabOauth2TokenRepository) Delete(ctx context.Context, tx *gorm.DB, tokens []models.GitLabOauth2Token) error {
	if err := r.GetDB(ctx, tx).Delete(tokens).Error; err != nil {
		return err
	}
	return nil
}

func (r *gitlabOauth2TokenRepository) DeleteByUserIDAndProviderID(ctx context.Context, tx *gorm.DB, userID string, providerID string) error {
	return r.GetDB(ctx, tx).Where("user_id = ? AND provider_id = ?", userID, providerID).Delete(&models.GitLabOauth2Token{}).Error
}

func (r *gitlabOauth2TokenRepository) CreateIfNotExists(ctx context.Context, tx *gorm.DB, tokens []*models.GitLabOauth2Token) error {
	for _, t := range tokens {
		restore, err := r.encryptTokenInPlace(ctx, t)
		if err != nil {
			return err
		}
		defer restore()
	}

	return r.GetDB(ctx, tx).Clauses(clause.OnConflict{
		DoNothing: true,
		Columns: []clause.Column{
			{
				Name: "provider_id",
			},
			{
				Name: "user_id",
			},
		},
	}).Create(tokens).Error
}

// encryptTokenInPlace encrypts the token's sensitive fields in place and returns a func to restore the plaintext.
func (r *gitlabOauth2TokenRepository) encryptTokenInPlace(ctx context.Context, token *models.GitLabOauth2Token) (func(), error) {
	encryptedAccessToken, err := r.encryptionService.EncryptAndWrapData(token.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("could not encrypt access token before saving to db: %w", err)
	}
	encryptedRefreshToken, err := r.encryptionService.EncryptAndWrapData(token.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("could not encrypt refresh token before saving to db: %w", err)
	}

	originalAccessToken := token.AccessToken
	originalRefreshToken := token.RefreshToken
	token.AccessToken = encryptedAccessToken
	token.RefreshToken = encryptedRefreshToken

	return func() {
		token.AccessToken = originalAccessToken
		token.RefreshToken = originalRefreshToken
	}, nil
}

// decryptTokenInPlace decrypts the sensitive fields of a fetched token
func (r *gitlabOauth2TokenRepository) decryptTokenInPlace(ctx context.Context, token *models.GitLabOauth2Token) error {
	decryptedAccessToken, err := r.encryptionService.MaybeDecryptData(token.AccessToken)
	if err != nil {
		return fmt.Errorf("could not decrypt fetched access token: %w", err)
	}
	decryptedRefreshToken, err := r.encryptionService.MaybeDecryptData(token.RefreshToken)
	if err != nil {
		return fmt.Errorf("could not decrypt fetched refresh token: %w", err)
	}

	token.AccessToken = decryptedAccessToken
	token.RefreshToken = decryptedRefreshToken
	return nil
}
