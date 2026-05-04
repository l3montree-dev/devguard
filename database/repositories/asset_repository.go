// Copyright (C) 2023 Tim Bastin, l3montree GmbH
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
	"fmt"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/lib/pq"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type assetRepository struct {
	db *gorm.DB
	utils.Repository[uuid.UUID, models.Asset, *gorm.DB]
}

func NewAssetRepository(db *gorm.DB) *assetRepository {
	return &assetRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.Asset](db),
	}
}

func (repository *assetRepository) prepareUniqueSlugs(ctx context.Context, tx *gorm.DB, projectID uuid.UUID, assets []*models.Asset) error {
	if len(assets) == 0 {
		return nil
	}

	// Collect slug base patterns for LIKE search
	patterns := make([]string, 0, len(assets))

	for _, p := range assets {
		patterns = append(patterns, p.Slug+"%")
	}

	// Fetch existing slugs safely using ANY()
	var existing []*models.Asset
	err := repository.GetDB(ctx, tx).Model(&models.Asset{}).
		Where("project_id = ? AND slug LIKE ANY(?)", projectID, pq.Array(patterns)).Find(&existing).Error
	if err != nil {
		return err
	}

	// Inject unique slugs into the projects
	if err := injectUniqueSlugs(existing, assets); err != nil {
		return fmt.Errorf("failed to inject unique slugs: %w", err)
	}

	return nil
}

func (repository *assetRepository) Upsert(ctx context.Context, tx *gorm.DB, t *[]*models.Asset, conflictingColumns []clause.Column, updateOnly []string) error {
	if len(*t) == 0 {
		return nil
	}

	err := repository.prepareUniqueSlugs(ctx, tx, (*t)[0].ProjectID, *t)
	if err != nil {
		return fmt.Errorf("failed to prepare unique slugs: %w", err)
	}

	if len(conflictingColumns) == 0 {
		if len(updateOnly) > 0 {
			return repository.GetDB(ctx, tx).Clauses(clause.OnConflict{DoUpdates: clause.AssignmentColumns(updateOnly)}).Create(t).Error
		}
		return repository.GetDB(ctx, tx).Clauses(clause.OnConflict{UpdateAll: true}).Create(t).Error
	}

	if len(updateOnly) > 0 {
		return repository.GetDB(ctx, tx).Clauses(clause.OnConflict{
			DoUpdates: clause.AssignmentColumns(updateOnly),
			Columns:   conflictingColumns,
		}).Create(t).Error
	}

	return repository.GetDB(ctx, tx).Clauses(clause.OnConflict{UpdateAll: true, Columns: conflictingColumns}).Create(t).Error
}

func (repository *assetRepository) Create(ctx context.Context, tx *gorm.DB, asset *models.Asset) error {
	// get the next slug for the asset
	firstFreeSlug, err := repository.firstFreeSlug(ctx, tx, asset.ProjectID, asset.Slug)
	if err != nil {
		return fmt.Errorf("failed to get next slug: %w", err)
	}
	asset.Slug = firstFreeSlug

	if err := repository.GetDB(ctx, tx).Create(asset).Error; err != nil {
		return err
	}
	return nil
}

func (repository *assetRepository) Save(ctx context.Context, tx *gorm.DB, asset *models.Asset) error {
	if asset.ID == uuid.Nil {
		// get the next slug for the asset
		firstFreeSlug, err := repository.firstFreeSlug(ctx, tx, asset.ProjectID, asset.Slug)
		if err != nil {
			return fmt.Errorf("failed to get next slug: %w", err)
		}
		asset.Slug = firstFreeSlug
	}

	if err := repository.GetDB(ctx, tx).Save(asset).Error; err != nil {
		return err
	}
	return nil
}

func (repository *assetRepository) FindAssetByExternalProviderID(ctx context.Context, tx *gorm.DB, externalEntityProviderID string, externalEntityID string) (*models.Asset, error) {
	var asset models.Asset
	err := repository.GetDB(ctx, tx).Where("external_entity_provider_id = ? AND external_entity_id = ?", externalEntityProviderID, externalEntityID).First(&asset).Error
	return &asset, err
}

func (repository *assetRepository) GetFQNByID(ctx context.Context, tx *gorm.DB, id uuid.UUID) (string, error) {
	var fqn struct {
		FQN string `gorm:"column:fqn"`
	}
	// the fully qualified name (FQN) is the slug of the asset - including the project slug and the organization slug
	// using the fqn an asset is addressable through the API
	err := repository.GetDB(ctx, tx).Model(&models.Asset{}).
		Select("CONCAT(organizations.slug, '/', projects.slug, '/', assets.slug) AS fqn").
		Joins("JOIN projects ON assets.project_id = projects.id").
		Joins("JOIN organizations ON projects.organization_id = organizations.id").
		Where("assets.id = ?", id).
		First(&fqn).Error
	if err != nil {
		return "", err
	}
	return fqn.FQN, nil
}

func (repository *assetRepository) FindByName(ctx context.Context, tx *gorm.DB, name string) (models.Asset, error) {
	var app models.Asset
	err := repository.GetDB(ctx, tx).Where("name = ?", name).First(&app).Error
	if err != nil {
		return app, err
	}
	return app, nil
}

func (repository *assetRepository) GetAllowedAssetsByProjectID(ctx context.Context, tx *gorm.DB, allowedAssetIDs []string, projectID uuid.UUID) ([]models.Asset, error) {
	var apps []models.Asset
	q := repository.GetDB(ctx, tx).Where("project_id = ? AND id IN (?)", projectID, allowedAssetIDs).Or("project_id = ? AND is_public = true", projectID).Find(&apps)
	if q.Error != nil {
		return nil, q.Error
	}

	return apps, nil
}

func (repository *assetRepository) GetByProjectID(ctx context.Context, tx *gorm.DB, projectID uuid.UUID) ([]models.Asset, error) {
	var apps []models.Asset
	err := repository.GetDB(ctx, tx).Where("project_id = ?", projectID).Find(&apps).Error
	if err != nil {
		return nil, err
	}
	return apps, nil
}

func (repository *assetRepository) GetByOrgID(ctx context.Context, tx *gorm.DB, orgID uuid.UUID) ([]models.Asset, error) {
	var apps []models.Asset
	err := repository.GetDB(ctx, tx).Where("project_id IN (SELECT id from projects where organization_id = ?)", orgID).Preload("AssetVersions").Find(&apps).Error
	if err != nil {
		return nil, err
	}
	return apps, nil
}

func (repository *assetRepository) GetByProjectIDs(ctx context.Context, tx *gorm.DB, projectIDs []uuid.UUID) ([]models.Asset, error) {
	var apps []models.Asset
	err := repository.GetDB(ctx, tx).Where("project_id IN (?)", projectIDs).Find(&apps).Error
	if err != nil {
		return nil, err
	}
	return apps, nil
}

func (repository *assetRepository) ReadBySlug(ctx context.Context, tx *gorm.DB, projectID uuid.UUID, slug string) (models.Asset, error) {
	var t models.Asset
	err := repository.GetDB(ctx, tx).Where("slug = ? AND project_id = ?", slug, projectID).Preload("AssetVersions").First(&t).Error
	return t, err
}

func (repository *assetRepository) ReadBySlugUnscoped(ctx context.Context, tx *gorm.DB, projectID uuid.UUID, slug string) (models.Asset, error) {
	var asset models.Asset
	err := repository.GetDB(ctx, tx).Unscoped().Where("slug = ? AND project_id = ?", slug, projectID).First(&asset).Error
	return asset, err
}

func (repository *assetRepository) GetAssetIDBySlug(ctx context.Context, tx *gorm.DB, projectID uuid.UUID, slug string) (uuid.UUID, error) {
	app, err := repository.ReadBySlug(ctx, tx, projectID, slug)
	if err != nil {
		return uuid.UUID{}, err
	}
	return app.ID, nil
}

func (repository *assetRepository) Update(ctx context.Context, tx *gorm.DB, asset *models.Asset) error {
	return repository.GetDB(ctx, tx).Save(asset).Error
}

func (repository *assetRepository) GetAllAssetsFromDB(ctx context.Context, tx *gorm.DB) ([]models.Asset, error) {
	var assets []models.Asset
	err := repository.GetDB(ctx, tx).Preload("AssetVersions").Find(&assets).Error
	return assets, err
}

func (repository *assetRepository) GetAssetByAssetVersionID(ctx context.Context, tx *gorm.DB, assetVersionID uuid.UUID) (models.Asset, error) {
	var asset models.Asset
	err := repository.GetDB(ctx, tx).Model(&models.AssetVersion{}).
		Select("assets.*").
		Joins("JOIN assets ON assets.id = asset_versions.asset_id").
		Where("asset_versions.id = ?", assetVersionID).
		First(&asset).Error
	return asset, err
}

func (repository *assetRepository) Delete(ctx context.Context, tx *gorm.DB, id uuid.UUID) error {
	asset := models.Asset{Model: models.Model{ID: id}}
	return repository.GetDB(ctx, tx).Select("AssetVersions").Delete(&asset).Error
}

func (repository *assetRepository) ReadWithAssetVersions(ctx context.Context, tx *gorm.DB, assetID uuid.UUID) (models.Asset, error) {
	var asset models.Asset
	err := repository.GetDB(ctx, tx).Preload("AssetVersions").Where("id = ?", assetID).First(&asset).Error
	if err != nil {
		return models.Asset{}, err
	}
	return asset, nil
}

func (repository *assetRepository) firstFreeSlug(ctx context.Context, tx *gorm.DB, projectID uuid.UUID, assetSlug string) (string, error) {
	var slugs []string
	err := repository.GetDB(ctx, tx).Model(&models.Asset{}).
		Where("project_id = ? AND slug LIKE ?", projectID, assetSlug+"%").
		Pluck("slug", &slugs).Error
	if err != nil {
		return "", err
	}

	baseTaken := false
	existing := make(map[string]bool)
	for _, s := range slugs {
		existing[s] = true
		if s == assetSlug {
			baseTaken = true
		}
	}

	if !baseTaken {
		return assetSlug, nil
	}

	for i := 1; ; i++ {
		candidate := fmt.Sprintf("%s-%d", assetSlug, i)
		if !existing[candidate] {
			return candidate, nil
		}
	}
}

func (repository *assetRepository) GetAssetsWithVulnSharingEnabled(ctx context.Context, tx *gorm.DB, orgID uuid.UUID) ([]models.Asset, error) {
	var assets []models.Asset
	err := repository.GetDB(ctx, tx).Where("shares_information = true").Where(
		"EXISTS (SELECT 1 from projects where projects.id = assets.project_id AND projects.organization_id = ?)", orgID,
	).Preload("Project").Find(&assets).Error
	return assets, err
}
