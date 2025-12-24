// Copyright (C) 2025 l3montree GmbH
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
	"strings"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/normalize"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

type MaliciousPackageRepository struct {
	db *gorm.DB
}

func NewMaliciousPackageRepository(db *gorm.DB) *MaliciousPackageRepository {
	return &MaliciousPackageRepository{
		db: db,
	}
}

func (r *MaliciousPackageRepository) GetDB() *gorm.DB {
	return r.db
}

// GetMaliciousAffectedComponents finds malicious packages for a given purl (similar to GetAffectedComponents)
func (r *MaliciousPackageRepository) GetMaliciousAffectedComponents(purl, version string) ([]models.MaliciousAffectedComponent, error) {
	ctx, err := normalize.ParsePurlForMatching(purl, version)
	if err != nil {
		return []models.MaliciousAffectedComponent{}, nil
	}

	if ctx == nil {
		return []models.MaliciousAffectedComponent{}, nil
	}

	var components []models.MaliciousAffectedComponent

	// Build query using shared helper functions
	query := r.db.Model(&models.MaliciousAffectedComponent{}).Where("purl = ?", ctx.SearchPurl)
	query = BuildQualifierQuery(query, ctx.Qualifiers, ctx.Namespace)

	// Align version matching behavior with PurlComparer:
	// - If VersionIsValid is not nil, perform an exact version match.
	// - Otherwise, fall back to semver range matching.
	if ctx.VersionIsValid != nil {
		query = query.Where("version = ?", ctx.TargetVersion)
	} else {
		query = BuildVersionRangeQuery(query, ctx.TargetVersion, ctx.NormalizedVersion)
	}
	err = query.Preload("MaliciousPackage").Find(&components).Error
	return components, err
}

func (r *MaliciousPackageRepository) UpsertPackages(packages []models.MaliciousPackage) error {
	if len(packages) == 0 {
		return nil
	}

	// Use ON CONFLICT to update if exists, insert if not
	err := r.db.Session(
		&gorm.Session{
			Logger: logger.Discard,
		},
	).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		UpdateAll: true,
	}).Create(&packages).Error

	// If duplicate key error (cannot affect row a second time), split batch and retry
	if err != nil && (strings.Contains(err.Error(), "cannot affect row a second time") ||
		strings.Contains(err.Error(), "extended protocol limited to 65535 parameters")) {
		// Split the batch in half and try again
		half := len(packages) / 2
		if half == 0 {
			// Can't split further, skip this problematic entry
			return nil
		}
		err = r.UpsertPackages(packages[:half])
		if err != nil {
			return err
		}
		err = r.UpsertPackages(packages[half:])
	}

	return err
}

func (r *MaliciousPackageRepository) UpsertAffectedComponents(components []models.MaliciousAffectedComponent) error {
	if len(components) == 0 {
		return nil
	}

	// Use ON CONFLICT to update if exists, insert if not
	err := r.db.Session(
		&gorm.Session{
			Logger: logger.Discard,
		},
	).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		UpdateAll: true,
	}).Create(&components).Error

	// If duplicate key error (cannot affect row a second time), split batch and retry
	if err != nil && (strings.Contains(err.Error(), "cannot affect row a second time") ||
		strings.Contains(err.Error(), "extended protocol limited to 65535 parameters")) {
		// Split the batch in half and try again
		half := len(components) / 2
		if half == 0 {
			// Can't split further, skip this problematic entry
			return nil
		}
		err = r.UpsertAffectedComponents(components[:half])
		if err != nil {
			return err
		}
		err = r.UpsertAffectedComponents(components[half:])
	}

	return err
}

func (r *MaliciousPackageRepository) DeleteAll() error {
	// Delete affected components first (foreign key constraint)
	if err := r.db.Exec("TRUNCATE TABLE malicious_affected_components CASCADE").Error; err != nil {
		return err
	}
	return r.db.Exec("TRUNCATE TABLE malicious_packages CASCADE").Error
}

func (r *MaliciousPackageRepository) Count() (int64, error) {
	var count int64
	err := r.db.Model(&models.MaliciousPackage{}).Count(&count).Error
	return count, err
}

func (r *MaliciousPackageRepository) CountByEcosystem() (map[string]int64, error) {
	type Result struct {
		Ecosystem string
		Count     int64
	}

	var results []Result
	err := r.db.Model(&models.MaliciousAffectedComponent{}).
		Select("ecosystem, COUNT(DISTINCT malicious_package_id) as count").
		Group("ecosystem").
		Scan(&results).Error

	if err != nil {
		return nil, err
	}

	counts := make(map[string]int64)
	for _, r := range results {
		counts[strings.ToLower(r.Ecosystem)] += r.Count
	}

	return counts, nil
}

// BatchUpsert handles large batches by splitting them into chunks
func (r *MaliciousPackageRepository) BatchUpsertPackages(packages []models.MaliciousPackage, batchSize int) error {
	if len(packages) == 0 {
		return nil
	}

	for i := 0; i < len(packages); i += batchSize {
		end := i + batchSize
		if end > len(packages) {
			end = len(packages)
		}

		batch := packages[i:end]
		if err := r.UpsertPackages(batch); err != nil {
			return err
		}
	}

	return nil
}

func (r *MaliciousPackageRepository) BatchUpsertAffectedComponents(components []models.MaliciousAffectedComponent, batchSize int) error {
	if len(components) == 0 {
		return nil
	}

	for i := 0; i < len(components); i += batchSize {
		end := min(i+batchSize, len(components))

		batch := components[i:end]
		if err := r.UpsertAffectedComponents(batch); err != nil {
			return err
		}
	}

	return nil
}
