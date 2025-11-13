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
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/common"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"gorm.io/gorm/clause"
)

type gitlabIntegrationRepository struct {
	db shared.DB
	common.Repository[uuid.UUID, models.GitLabIntegration, shared.DB]
}

func NewGitLabIntegrationRepository(db shared.DB) *gitlabIntegrationRepository {
	return &gitlabIntegrationRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.GitLabIntegration](db),
	}
}

func (r *gitlabIntegrationRepository) FindByOrganizationID(orgID uuid.UUID) ([]models.GitLabIntegration, error) {
	var integrations []models.GitLabIntegration
	if err := r.db.Find(&integrations, "orgID = ?", orgID).Error; err != nil {
		return nil, err
	}
	return integrations, nil
}

type gitlabOauth2TokenRepository struct {
	db shared.DB
}

func NewGitlabOauth2TokenRepository(db shared.DB) *gitlabOauth2TokenRepository {
	return &gitlabOauth2TokenRepository{
		db: db,
	}
}

func (r *gitlabOauth2TokenRepository) Save(tx shared.DB, token ...*models.GitLabOauth2Token) error {
	if err := r.db.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "user_id"}, {Name: "provider_id"}},
		UpdateAll: true,
	}).Create(token).Error; err != nil {
		return err
	}
	return nil
}

func (r *gitlabOauth2TokenRepository) Upsert(tx shared.DB, token *models.GitLabOauth2Token) error {
	if err := r.db.Clauses(clause.OnConflict{
		UpdateAll: true,
	}).Create(token).Error; err != nil {
		return err
	}
	return nil
}

func (r *gitlabOauth2TokenRepository) FindByUserIDAndProviderID(userID string, providerID string) (*models.GitLabOauth2Token, error) {
	var token models.GitLabOauth2Token
	if err := r.db.Where("user_id = ? AND provider_id = ?", userID, providerID).First(&token).Error; err != nil {
		return nil, err
	}
	return &token, nil
}

func (r *gitlabOauth2TokenRepository) FindByUserID(userID string) ([]models.GitLabOauth2Token, error) {
	var tokens []models.GitLabOauth2Token
	if err := r.db.Where("user_id = ?", userID).Find(&tokens).Error; err != nil {
		return nil, err
	}
	return tokens, nil
}

func (r *gitlabOauth2TokenRepository) Delete(tx shared.DB, tokens []models.GitLabOauth2Token) error {
	if err := r.db.Delete(tokens).Error; err != nil {
		return err
	}
	return nil
}

func (r *gitlabOauth2TokenRepository) DeleteByUserIDAndProviderID(userID string, providerID string) error {
	return r.db.Where("user_id = ? AND provider_id = ?", userID, providerID).Delete(&models.GitLabOauth2Token{}).Error
}

func (r *gitlabOauth2TokenRepository) CreateIfNotExists(tokens []*models.GitLabOauth2Token) error {
	return r.db.Clauses(clause.OnConflict{
		DoNothing: true,
		Columns: []clause.Column{
			clause.Column{
				Name: "provider_id",
			},
			clause.Column{
				Name: "user_id",
			},
		},
	}).Create(tokens).Error
}
