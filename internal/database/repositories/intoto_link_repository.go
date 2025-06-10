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
	"os"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"gorm.io/gorm"
)

type inTotoLinkRepository struct {
	db core.DB
	common.Repository[uuid.UUID, models.InTotoLink, core.DB]
}

func NewInTotoLinkRepository(db core.DB) *inTotoLinkRepository {
	if os.Getenv("DISABLE_AUTOMIGRATE") != "true" {
		if err := db.AutoMigrate(&models.InTotoLink{}); err != nil {
			panic(err)
		}
	}

	return &inTotoLinkRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.InTotoLink](db),
	}
}

func (g *inTotoLinkRepository) FindByAssetAndSupplyChainId(assetID uuid.UUID, supplyChainId string) ([]models.InTotoLink, error) {
	var t []models.InTotoLink
	// only require it to start with the supply chain id
	err := g.db.Model(models.InTotoLink{}).Where("asset_id = ? AND supply_chain_id LIKE ?", assetID, supplyChainId+"%").Find(&t).Error
	return t, err
}

func (g *inTotoLinkRepository) FindBySupplyChainID(supplyChainID string) ([]models.InTotoLink, error) {
	var t []models.InTotoLink

	err := g.db.Model(&models.InTotoLink{}).
		Where("LEFT(supply_chain_id, 8) = ?", supplyChainID).
		Find(&t).Error

	return t, err
}

func (g *inTotoLinkRepository) Save(tx core.DB, model *models.InTotoLink) error {
	return g.db.Session(&gorm.Session{
		FullSaveAssociations: false,
	}).Save(model).Error
}
