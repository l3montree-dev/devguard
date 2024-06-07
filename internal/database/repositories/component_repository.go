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
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/database"
	"github.com/l3montree-dev/flawfix/internal/database/models"
	"gorm.io/gorm"
)

type componentRepository struct {
	Repository[string, models.Component, database.DB]
	db *gorm.DB
}

func NewComponentRepository(db database.DB) *componentRepository {
	if err := db.AutoMigrate(&models.Component{}, &models.AssetComponent{}); err != nil {
		panic(err)
	}

	return &componentRepository{
		Repository: newGormRepository[string, models.Component](db),
		db:         db,
	}
}

func (c *componentRepository) UpdateSemverEnd(tx database.DB, assetID uuid.UUID, componentPurlOrCpe []string, version string) error {
	return c.GetDB(tx).Model(&models.AssetComponent{}).Where("asset_id = ? AND component_purl_or_cpe IN ?", assetID.String(), componentPurlOrCpe).Update("semver_end", version).Error
}

func (c *componentRepository) CreateAssetComponents(tx database.DB, components []models.AssetComponent) error {
	if len(components) == 0 {
		return nil
	}
	return c.GetDB(tx).Create(&components).Error
}

func (c *componentRepository) LoadAssetComponents(tx database.DB, asset models.Asset) ([]models.AssetComponent, error) {
	var components []models.AssetComponent
	err := c.GetDB(tx).Where("asset_id = ?", asset.ID).Find(&components).Error
	return components, err
}
