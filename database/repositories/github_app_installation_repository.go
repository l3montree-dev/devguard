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
)

type githubAppInstallationRepository struct {
	db shared.DB
	common.Repository[int, models.GithubAppInstallation, shared.DB]
}

func NewGithubAppInstallationRepository(db shared.DB) *githubAppInstallationRepository {
	return &githubAppInstallationRepository{
		db:         db,
		Repository: newGormRepository[int, models.GithubAppInstallation](db),
	}
}

func (r *githubAppInstallationRepository) FindByOrganizationID(orgID uuid.UUID) ([]models.GithubAppInstallation, error) {
	var installations []models.GithubAppInstallation
	if err := r.db.Find(&installations, "orgID = ?", orgID).Error; err != nil {
		return nil, err
	}
	return installations, nil
}

func (r *githubAppInstallationRepository) Read(id int) (models.GithubAppInstallation, error) {
	var installation models.GithubAppInstallation
	if err := r.db.First(&installation, "installation_id = ?", id).Error; err != nil {
		return models.GithubAppInstallation{}, err
	}
	return installation, nil
}
