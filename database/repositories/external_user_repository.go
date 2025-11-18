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
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
)

type externalUserRepository struct {
	db *gorm.DB
	utils.Repository[int, models.ExternalUser, *gorm.DB]
}

func NewExternalUserRepository(db *gorm.DB) *externalUserRepository {
	return &externalUserRepository{
		db:         db,
		Repository: newGormRepository[int, models.ExternalUser](db),
	}
}

func (r *externalUserRepository) FindByOrgID(tx *gorm.DB, orgID uuid.UUID) ([]models.ExternalUser, error) {
	var users []models.ExternalUser
	if err := r.GetDB(tx).Raw("SELECT gh.* FROM external_users gh WHERE EXISTS(SELECT 1 from external_user_orgs where external_user_id = gh.id AND org_id = ?)", orgID).Scan(&users).Error; err != nil {
		return nil, err
	}
	return users, nil
}
