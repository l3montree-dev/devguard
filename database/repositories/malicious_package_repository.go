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
	"context"
	"strings"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/package-url/packageurl-go"
	"gorm.io/gorm"
)

type MaliciousPackageRepository struct {
	db         *gorm.DB
	pkgRepo    *GormRepository[string, models.MaliciousPackage]
	compRepo   *GormRepository[string, models.MaliciousAffectedComponent]
}

func NewMaliciousPackageRepository(db *gorm.DB) *MaliciousPackageRepository {
	return &MaliciousPackageRepository{
		db:       db,
		pkgRepo:  newGormRepository[string, models.MaliciousPackage](db),
		compRepo: newGormRepository[string, models.MaliciousAffectedComponent](db),
	}
}

func (r *MaliciousPackageRepository) GetDB(ctx context.Context, tx *gorm.DB) *gorm.DB {
	if tx != nil {
		return tx
	}
	return r.db.WithContext(ctx)
}

// GetMaliciousAffectedComponents finds malicious packages for a given purl (similar to GetAffectedComponents)
func (r *MaliciousPackageRepository) GetMaliciousAffectedComponents(ctx context.Context, tx *gorm.DB, purl packageurl.PackageURL) ([]models.MaliciousAffectedComponent, error) {
	matchCtx := normalize.ParsePurlForMatching(purl)

	var components []models.MaliciousAffectedComponent

	// Build query using shared helper functions
	query := r.GetDB(ctx, tx).Model(&models.MaliciousAffectedComponent{}).Where("purl = ?", matchCtx.SearchPurl)
	query = BuildQualifierQuery(query, matchCtx.Qualifiers, matchCtx.Namespace)

	// Align version matching behavior with PurlComparer:
	// - If VersionIsValid is not nil, perform an exact version match.
	// - Otherwise, fall back to semver range matching.

	err := BuildQueryBasedOnMatchContext(query, matchCtx).Find(&components).Error
	return components, err
}

func (r *MaliciousPackageRepository) GetMaliciousPackageByID(ctx context.Context, tx *gorm.DB, id string) (models.MaliciousPackage, error) {
	var maliciousPackage models.MaliciousPackage
	err := r.GetDB(ctx, tx).Where("id = ?", id).First(&maliciousPackage).Error
	return maliciousPackage, err
}

func (r *MaliciousPackageRepository) UpsertPackages(ctx context.Context, tx *gorm.DB, packages []models.MaliciousPackage) error {
	return r.pkgRepo.SaveBatchBestEffort(ctx, tx, packages)
}

func (r *MaliciousPackageRepository) UpsertAffectedComponents(ctx context.Context, tx *gorm.DB, components []models.MaliciousAffectedComponent) error {
	return r.compRepo.SaveBatchBestEffort(ctx, tx, components)
}

func (r *MaliciousPackageRepository) DeleteAll(ctx context.Context, tx *gorm.DB) error {
	// Delete affected components first (foreign key constraint)
	if err := r.GetDB(ctx, tx).Exec("TRUNCATE TABLE malicious_affected_components CASCADE").Error; err != nil {
		return err
	}
	return r.GetDB(ctx, tx).Exec("TRUNCATE TABLE malicious_packages CASCADE").Error
}

func (r *MaliciousPackageRepository) Count(ctx context.Context, tx *gorm.DB) (int64, error) {
	var count int64
	err := r.GetDB(ctx, tx).Model(&models.MaliciousPackage{}).Count(&count).Error
	return count, err
}

func (r *MaliciousPackageRepository) CountByEcosystem(ctx context.Context, tx *gorm.DB) (map[string]int64, error) {
	type Result struct {
		Ecosystem string
		Count     int64
	}

	var results []Result
	err := r.GetDB(ctx, tx).Model(&models.MaliciousAffectedComponent{}).
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
func (r *MaliciousPackageRepository) BatchUpsertPackages(ctx context.Context, tx *gorm.DB, packages []models.MaliciousPackage, batchSize int) error {
	if len(packages) == 0 {
		return nil
	}

	for i := 0; i < len(packages); i += batchSize {
		end := i + batchSize
		if end > len(packages) {
			end = len(packages)
		}

		batch := packages[i:end]
		if err := r.UpsertPackages(ctx, tx, batch); err != nil {
			return err
		}
	}

	return nil
}

func (r *MaliciousPackageRepository) BatchUpsertAffectedComponents(ctx context.Context, tx *gorm.DB, components []models.MaliciousAffectedComponent, batchSize int) error {
	if len(components) == 0 {
		return nil
	}

	for i := 0; i < len(components); i += batchSize {
		end := min(i+batchSize, len(components))

		batch := components[i:end]
		if err := r.UpsertAffectedComponents(ctx, tx, batch); err != nil {
			return err
		}
	}

	return nil
}
