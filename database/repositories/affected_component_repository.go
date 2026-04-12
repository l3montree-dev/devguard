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
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
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

// DeleteAll deletes all affected components whose ecosystem name starts with the provided string.
// This uses a prefix match (SQL LIKE 'ecosystem%') to handle versioned ecosystems,
func (g *affectedCmpRepository) DeleteAll(ctx context.Context, tx *gorm.DB, ecosystem string) error {
	return g.GetDB(ctx, tx).Where("ecosystem LIKE ?", ecosystem+"%").Delete(&models.AffectedComponent{}).Error
}

func (g *affectedCmpRepository) GetAllAffectedComponentsID(ctx context.Context, tx *gorm.DB) ([]string, error) {
	var affectedComponents []string
	err := g.GetDB(ctx, tx).Model(&models.AffectedComponent{}).
		Pluck("id", &affectedComponents).
		Error
	return affectedComponents, err
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
	ids := make([]string, len(components))
	sources := make([]string, len(components))
	purls := make([]string, len(components))
	ecosystems := make([]string, len(components))
	schemes := make([]string, len(components))
	types := make([]string, len(components))
	names := make([]string, len(components))

	// nil-able
	namespaces := make([]*string, len(components))
	qualifiers := make([]*string, len(components))
	subpaths := make([]*string, len(components))
	versions := make([]*string, len(components))
	semversIntroduced := make([]*string, len(components))
	semversFixed := make([]*string, len(components))
	versionsIntroduced := make([]*string, len(components))
	versionsFixed := make([]*string, len(components))

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
		namespaces[i] = components[i].Namespace
		if components[i].Qualifiers != nil {
			b, _ := json.Marshal(components[i].Qualifiers)
			s := string(b)
			qualifiers[i] = &s
		} else {
			t := "{}"
			qualifiers[i] = &t
		}
		subpaths[i] = components[i].Subpath
		versions[i] = components[i].Version
		semversIntroduced[i] = components[i].SemverIntroduced
		semversFixed[i] = components[i].SemverFixed
		versionsIntroduced[i] = components[i].VersionIntroduced
		versionsFixed[i] = components[i].VersionFixed
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
            unnest($12::text[])::semver,
            unnest($13::text[])::semver,
            unnest($14::text[]),
			unnest($15::text[])
			ON CONFLICT (id) DO NOTHING`

	return g.GetDB(ctx, tx).Session(&gorm.Session{Logger: logger.Default.LogMode(logger.Silent)}).Exec(query, ids, sources, purls, ecosystems, schemes, types, names, namespaces, qualifiers, subpaths, versions, semversIntroduced, semversFixed, versionsIntroduced, versionsFixed).Error
}

// InsertAffectedComponentsUsingCOPY bulk-inserts affected components via PostgreSQL COPY on the
// caller-provided pgx transaction. Assumes the slice is already deduplicated by id, so no
// ON CONFLICT handling is needed. The caller owns the tx lifecycle (begin/commit/rollback).
func (g *affectedCmpRepository) InsertAffectedComponentsUsingCOPY(ctx context.Context, tx pgx.Tx, affectedComponents []models.AffectedComponent) error {
	if len(affectedComponents) == 0 {
		return nil
	}

	// Staging table with plain text columns. pgx has no built-in codec for the custom
	// semver type, so we stage as text and cast during the INSERT ... SELECT.
	if _, err := tx.Exec(ctx, `
		CREATE TEMP TABLE affected_components_stage (
			id                 text,
			source             text,
			purl               text,
			ecosystem          text,
			scheme             text,
			type               text,
			name               text,
			namespace          text,
			qualifiers         jsonb,
			subpath            text,
			version            text,
			semver_introduced  text,
			semver_fixed       text,
			version_introduced text,
			version_fixed      text
		) ON COMMIT DROP
	`); err != nil {
		return fmt.Errorf("create staging table: %w", err)
	}

	copied, err := tx.CopyFrom(
		ctx,
		pgx.Identifier{"affected_components_stage"},
		[]string{
			"id", "source", "purl", "ecosystem", "scheme", "type", "name",
			"namespace", "qualifiers", "subpath", "version",
			"semver_introduced", "semver_fixed",
			"version_introduced", "version_fixed",
		},
		pgx.CopyFromSlice(len(affectedComponents), func(i int) ([]any, error) {
			c := &affectedComponents[i]

			qualifiers := "{}"
			if c.Qualifiers != nil {
				b, err := json.Marshal(c.Qualifiers)
				if err != nil {
					return nil, fmt.Errorf("marshal qualifiers: %w", err)
				}
				qualifiers = string(b)
			}

			return []any{
				c.CalculateHash(),
				c.Source,
				c.PurlWithoutVersion,
				c.Ecosystem,
				c.Scheme,
				c.Type,
				c.Name,
				c.Namespace,
				qualifiers,
				c.Subpath,
				c.Version,
				c.SemverIntroduced,
				c.SemverFixed,
				c.VersionIntroduced,
				c.VersionFixed,
			}, nil
		}),
	)
	if err != nil {
		return fmt.Errorf("copy into staging: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO affected_components (
			id, source, purl, ecosystem, scheme, type, name,
			namespace, qualifiers, subpath, version,
			semver_introduced, semver_fixed,
			version_introduced, version_fixed
		)
		SELECT
			id, source, purl, ecosystem, scheme, type, name,
			namespace, qualifiers, subpath, version,
			semver_introduced::semver, semver_fixed::semver,
			version_introduced, version_fixed
		FROM affected_components_stage
	`); err != nil {
		return fmt.Errorf("insert from staging: %w", err)
	}

	slog.Info("copied affected_components", "rows", copied)
	return nil
}

// InsertCVEAffectedComponentsUsingCOPY bulk-inserts pivot rows linking cves <-> affected_components via COPY
// on the caller-provided pgx transaction. Takes two parallel slices to stay schema-agnostic. Assumes the
// caller has already deduplicated the rows. The caller owns the tx lifecycle.
//
// The referenced cves must be visible (committed or in the same tx) when this runs, otherwise the FK
// check against cve_affected_component.cvecve will fail.
func (g *affectedCmpRepository) InsertCVEAffectedComponentsUsingCOPY(ctx context.Context, tx pgx.Tx, cveIDs []string, affectedComponentIDs []string) error {
	if len(cveIDs) == 0 {
		return nil
	}
	if len(cveIDs) != len(affectedComponentIDs) {
		return fmt.Errorf("cveIDs and affectedComponentIDs must be the same length (%d vs %d)", len(cveIDs), len(affectedComponentIDs))
	}

	// Pivot is text-only and caller guarantees dedup, so COPY straight into the target table.
	copied, err := tx.CopyFrom(
		ctx,
		pgx.Identifier{"cve_affected_component"},
		[]string{"cvecve", "affected_component_id"},
		pgx.CopyFromSlice(len(cveIDs), func(i int) ([]any, error) {
			return []any{cveIDs[i], affectedComponentIDs[i]}, nil
		}),
	)
	if err != nil {
		return fmt.Errorf("copy into cve_affected_component: %w", err)
	}

	slog.Info("copied cve_affected_component", "rows", copied)
	return nil
}
