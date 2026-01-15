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
	"encoding/json"
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

// DeleteAll deletes all affected components whose ecosystem name starts with the provided string.
// This uses a prefix match (SQL LIKE 'ecosystem%') to handle versioned ecosystems,
func (g *affectedCmpRepository) DeleteAll(tx *gorm.DB, ecosystem string) error {
	return g.GetDB(tx).Where("ecosystem LIKE ?", ecosystem+"%").Delete(&models.AffectedComponent{}).Error
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
				if err := g.GetDB(tx).Session(
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
		return g.createInBatches(tx, pkgs, newBatchSize)
	}
	return err
}

func (g *affectedCmpRepository) SaveBatch(tx *gorm.DB, affectedPkgs []models.AffectedComponent) error {
	return g.createInBatches(tx, affectedPkgs, 1000)
}

func (g *affectedCmpRepository) CreateAffectedComponentsUsingUnnest(tx *gorm.DB, components []models.AffectedComponent) error {
	if len(components) == 0 {
		return nil
	}

	// convert values of entries into arrays of values
	ids := make([]string, len(components))
	sources := make([]string, len(components))
	purls := make([]string, len(components))
	ecosystems := make([]string, len(components))
	schemes := make([]string, len(components))
	types := make([]string, len(components))
	names := make([]string, len(components))

	// nil-able
	namespaces := make([]string, len(components))
	qualifiers := make([]string, len(components))
	subpaths := make([]string, len(components))
	versions := make([]string, len(components))
	semversIntroduced := make([]string, len(components))
	semversFixed := make([]string, len(components))
	versionsIntroduced := make([]string, len(components))
	versionsFixed := make([]string, len(components))

	for i := range components {
		// non nil-able
		ids[i] = components[i].CalculateHash()
		sources[i] = components[i].Source
		purls[i] = components[i].PurlWithoutVersion
		ecosystems[i] = components[i].Ecosystem
		schemes[i] = components[i].Scheme
		types[i] = components[i].Type
		names[i] = components[i].Name

		// nil-able
		namespaces[i] = utils.SafeDereference(components[i].Namespace)
		if components[i].Qualifiers != nil {
			b, _ := json.Marshal(components[i].Qualifiers)
			qualifiers[i] = string(b)
		} else {
			qualifiers[i] = "{}"
		}
		subpaths[i] = utils.SafeDereference(components[i].Subpath)
		versions[i] = utils.SafeDereference(components[i].Version)
		semversIntroduced[i] = utils.SafeDereference(components[i].SemverIntroduced)
		semversFixed[i] = utils.SafeDereference(components[i].SemverFixed)
		versionsIntroduced[i] = utils.SafeDereference(components[i].VersionIntroduced)
		versionsFixed[i] = utils.SafeDereference(components[i].VersionFixed)
	}

	query := `
        INSERT INTO affected_components (id,source,purl,ecosystem,scheme,type,name,namespace,qualifiers,subpath,version,semver_introduced,semver_fixed,version_introduced,version_fixed)
        SELECT
            unnest($1::text[]),
            unnest($2::text[]),
            unnest($3::text[]),
            unnest($4::text[]),
            unnest($5::text[]),
            unnest($6::text[]),
            unnest($7::text[]),
            unnest($8::text[]),
            unnest($9::text[])::jsonb,
            unnest($10::text[]),
            unnest($11::text[]),
            NULLIF(unnest($12::text[]), '')::semver,
            NULLIF(unnest($13::text[]), '')::semver,
            unnest($14::text[]),
			unnest($15::text[])
			ON CONFLICT (id) DO NOTHING`

	return g.GetDB(tx).Session(&gorm.Session{Logger: logger.Default.LogMode(logger.Silent)}).Exec(query, ids, sources, purls, ecosystems, schemes, types, names, namespaces, qualifiers, subpaths, versions, semversIntroduced, semversFixed, versionsIntroduced, versionsFixed).Error
}
