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
	"context"
	"log/slog"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/utils"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

type affectedCmpRepository struct {
	db *gorm.DB
	utils.Repository[string, models.AffectedComponent, *gorm.DB]
}

func (g *affectedCmpRepository) Save(ctx context.Context, tx *gorm.DB, affectedComponents *models.AffectedComponent) error {
	return g.GetDB(ctx, tx).Clauses(
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

func (g *affectedCmpRepository) createInBatches(ctx context.Context, tx *gorm.DB, pkgs []models.AffectedComponent, batchSize int) error {
	err := g.GetDB(ctx, tx).Session(
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
				if err := g.GetDB(ctx, tx).Session(
					&gorm.Session{
						// Logger: logger.Default.LogMode(logger.Silent),
					}).Clauses(
					clause.OnConflict{
						DoNothing: true,
					},
				).Create(pkg).Error; err != nil {
					// log, that we werent able to save the CVE
					slog.Error("unable to save affected packages", "cve", pkg.CVE, "err", err)
				}
			}
			return nil
		}
		slog.Warn("protocol error, trying to reduce batch size", "newBatchSize", newBatchSize, "oldBatchSize", batchSize, "err", err)
		return g.createInBatches(ctx, tx, pkgs, newBatchSize)
	}
	return err
}

func (g *affectedCmpRepository) SaveBatch(ctx context.Context, tx *gorm.DB, affectedPkgs []models.AffectedComponent) error {
	return g.createInBatches(ctx, tx, affectedPkgs, 1000)
}

func (g *affectedCmpRepository) CreateAffectedComponentsUsingUnnest(ctx context.Context, tx *gorm.DB, components []models.AffectedComponent) error {
	if len(components) == 0 {
		return nil
	}

	// convert values of entries into arrays of values
	ids := make([]int64, len(components))

	purls := make([]string, len(components))
	ecosystems := make([]string, len(components))

	versions := make([]*string, len(components))
	semversIntroduced := make([]*string, len(components))
	semversFixed := make([]*string, len(components))
	versionsIntroduced := make([]*string, len(components))
	versionsFixed := make([]*string, len(components))

	for i := range components {
		// non nil-able
		ids[i] = components[i].CalculateHashFast()

		purls[i] = components[i].PurlWithoutVersion
		ecosystems[i] = components[i].Ecosystem

		versions[i] = components[i].Version
		semversIntroduced[i] = components[i].SemverIntroduced
		semversFixed[i] = components[i].SemverFixed
		versionsIntroduced[i] = components[i].VersionIntroduced
		versionsFixed[i] = components[i].VersionFixed
	}

	query := `
        INSERT INTO affected_components (id,purl,ecosystem,version,semver_introduced,semver_fixed,version_introduced,version_fixed)
        SELECT
            unnest($1::text[]),

            unnest($2::text[]),
            unnest($3::text[]),

            unnest($4::text[]),
            unnest($5::text[])::semver,
            unnest($6::text[])::semver,
            unnest($7::text[]),
			unnest($8::text[])
			ON CONFLICT (id) DO NOTHING`

	return g.GetDB(ctx, tx).Session(&gorm.Session{Logger: logger.Default.LogMode(logger.Silent)}).Exec(query, ids, purls, ecosystems, versions, semversIntroduced, semversFixed, versionsIntroduced, versionsFixed).Error
}
