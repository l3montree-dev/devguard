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
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
package repositories

import (
	"log/slog"

	"github.com/l3montree-dev/devguard/common"
	"github.com/l3montree-dev/devguard/database/models"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

type affectedCmpRepository struct {
	db *gorm.DB
	common.Repository[string, models.AffectedComponent, *gorm.DB]
}

func (g *affectedCmpRepository) Save(tx *gorm.DB, affectedComponents *models.AffectedComponent) error {
	return g.GetDB(tx).Clauses(
		clause.OnConflict{
			UpdateAll: true,
		},
	).Save(affectedComponents).Error
}

func NewAffectedComponentRepository(db *gorm.DB) *affectedCmpRepository {
	return &affectedCmpRepository{
		db:         db,
		Repository: newGormRepository[string, models.AffectedComponent](db),
	}
}

func (g *affectedCmpRepository) DeleteAll(tx *gorm.DB, ecosystem string) error {
	return g.GetDB(tx).Where("ecosystem = ?", ecosystem).Delete(&models.AffectedComponent{}).Error
}

func (g *affectedCmpRepository) GetAllAffectedComponentsID() ([]string, error) {
	var affectedComponents []string
	err := g.db.Model(&models.AffectedComponent{}).
		Pluck("id", &affectedComponents).
		Error
	return affectedComponents, err
}

func (g *affectedCmpRepository) createInBatches(tx *gorm.DB, pkgs []models.AffectedComponent, batchSize int) error {
	err := g.GetDB(tx).Session(
		&gorm.Session{
			Logger: logger.Default.LogMode(logger.Silent),
		}).Clauses(
		clause.OnConflict{
			DoNothing: true,
		},
	).CreateInBatches(&pkgs, batchSize).Error
	// check if we got a protocol error since we are inserting more than 65535 parameters
	if err != nil && err.Error() == "extended protocol limited to 65535 parameters; extended protocol limited to 65535 parameters" {
		newBatchSize := batchSize / 2
		if newBatchSize < 1 {
			// we can't reduce the batch size anymore
			// lets try to save the CVEs one by one
			// this will be slow but it will work
			for _, pkg := range pkgs {
				tmpPkg := pkg
				if err := g.GetDB(tx).Session(
					&gorm.Session{
						// Logger: logger.Default.LogMode(logger.Silent),
					}).Clauses(
					clause.OnConflict{
						DoNothing: true,
					},
				).Create(&tmpPkg).Error; err != nil {
					// log, that we werent able to save the CVE
					slog.Error("unable to save affected packages", "cve", pkg.CVE, "err", err)
				}
			}
			return nil
		}
		slog.Warn("protocol error, trying to reduce batch size", "newBatchSize", newBatchSize, "oldBatchSize", batchSize, "err", err)
		return g.createInBatches(tx, pkgs, newBatchSize)
	}
	return err
}

func (g *affectedCmpRepository) SaveBatch(tx *gorm.DB, affectedPkgs []models.AffectedComponent) error {
	return g.createInBatches(tx, affectedPkgs, 1000)
}
