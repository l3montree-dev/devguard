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
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/package-url/packageurl-go"
	"gorm.io/gorm"
)

type MaliciousPackageRepository struct {
	db       *gorm.DB
	pkgRepo  *GormRepository[string, models.MaliciousPackage]
	compRepo *GormRepository[string, models.MaliciousAffectedComponent]
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
