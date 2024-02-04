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
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
package vulndb

import (
	"log/slog"

	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/database"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

type affectedPkgGormRepository struct {
	database.Repository[string, AffectedPackage, core.DB]
}

func newAffectedPkgGormRepository(db core.DB) affectedPkgGormRepository {
	err := db.AutoMigrate(&AffectedPackage{})
	if err != nil {
		panic(err)
	}

	return affectedPkgGormRepository{
		Repository: database.NewGormRepository[string, AffectedPackage](db),
	}
}

func (g *affectedPkgGormRepository) createInBatches(tx core.DB, pkgs []AffectedPackage, batchSize int) error {
	err := g.GetDB(tx).Session(
		&gorm.Session{
			Logger: logger.Default.LogMode(logger.Silent),
		}).Clauses(
		clause.OnConflict{
			UpdateAll: true,
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
						UpdateAll: true,
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

func (g *affectedPkgGormRepository) SaveBatch(tx core.DB, affectedPkgs []AffectedPackage) error {
	return g.createInBatches(tx, affectedPkgs, 1000)
}
