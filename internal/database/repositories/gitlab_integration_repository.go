// Copyright (C) 2024 Tim Bastin, l3montree UG (haftungsbeschränkt)
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
	"os"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type gitlabIntegrationRepository struct {
	db core.DB
	common.Repository[uuid.UUID, models.GitLabIntegration, core.DB]
}

func NewGitLabIntegrationRepository(db core.DB) *gitlabIntegrationRepository {
	if os.Getenv("DISABLE_AUTOMIGRATE") != "true" {
		if err := db.AutoMigrate(&models.GitLabIntegration{}); err != nil {
			panic(err)
		}
	}
	return &gitlabIntegrationRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.GitLabIntegration](db),
	}
}

func (r *gitlabIntegrationRepository) FindByOrganizationId(orgId uuid.UUID) ([]models.GitLabIntegration, error) {
	var integrations []models.GitLabIntegration
	if err := r.db.Find(&integrations, "org_id = ?", orgId).Error; err != nil {
		return nil, err
	}
	return integrations, nil
}
