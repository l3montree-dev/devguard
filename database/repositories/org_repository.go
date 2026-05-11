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
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
)

type orgRepository struct {
	db *gorm.DB
	utils.Repository[uuid.UUID, models.Org, *gorm.DB]
}

func NewOrgRepository(db *gorm.DB) *orgRepository {
	return &orgRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.Org](db),
	}
}

func (g *orgRepository) Create(ctx context.Context, tx *gorm.DB, org *models.Org) error {
	firstFreeSlug, err := g.firstFreeSlug(ctx, tx, org.Slug)
	if err != nil {
		return fmt.Errorf("could not generate next slug: %w", err)
	}
	org.Slug = firstFreeSlug

	return g.GetDB(ctx, tx).Create(org).Error
}

func (g *orgRepository) Save(ctx context.Context, tx *gorm.DB, org *models.Org) error {
	// if the slug is empty, generate a new one
	if org.ID == uuid.Nil {
		firstFreeSlug, err := g.firstFreeSlug(ctx, tx, org.Name)
		if err != nil {
			return fmt.Errorf("could not generate next slug: %w", err)
		}
		org.Slug = firstFreeSlug
	}

	return g.GetDB(ctx, tx).Save(org).Error
}

func (g *orgRepository) ReadBySlug(ctx context.Context, tx *gorm.DB, slug string) (models.Org, error) {
	var t models.Org
	err := g.GetDB(ctx, tx).Model(models.Org{}).Preload("GithubAppInstallations").Preload("JiraIntegrations").Preload("GitLabIntegrations").Preload("Webhooks", "project_id IS NULL").Where("slug = ?", slug).First(&t).Error
	return t, err
}

func (g *orgRepository) List(ctx context.Context, tx *gorm.DB, ids []uuid.UUID) ([]models.Org, error) {
	var ts []models.Org
	err := g.GetDB(ctx, tx).Model(models.Org{}).Preload("GithubAppInstallations").Where("id IN ?", ids).Find(&ts).Error
	return ts, err
}

func (g *orgRepository) Update(ctx context.Context, tx *gorm.DB, org *models.Org) error {
	return g.GetDB(ctx, tx).Save(org).Error
}

func (g *orgRepository) ContentTree(ctx context.Context, tx *gorm.DB, orgID uuid.UUID, projects []string) []any {
	var projectModels []models.Project

	g.GetDB(ctx, tx).Preload("Assets").Where(`projects.id IN (?) AND projects.organization_id = ?`, projects, orgID).Find(&projectModels)

	result := make([]any, 0, len(projectModels))
	for _, p := range projectModels {
		result = append(result, transformer.ProjectModelToDTO(p))
	}
	return result
}

func (g *orgRepository) GetOrgByID(ctx context.Context, tx *gorm.DB, id uuid.UUID) (models.Org, error) {
	var org models.Org
	err := g.GetDB(ctx, tx).Model(models.Org{}).Where("id = ?", id).First(&org).Error
	return org, err
}

func (g *orgRepository) GetOrgByIDs(ctx context.Context, tx *gorm.DB, ids []uuid.UUID) ([]models.Org, error) {
	var orgs []models.Org
	err := g.GetDB(ctx, tx).Model(models.Org{}).Where("id IN ?", ids).Find(&orgs).Error
	return orgs, err
}

func (g *orgRepository) firstFreeSlug(ctx context.Context, tx *gorm.DB, organizationSlug string) (string, error) {
	var slugs []string
	err := g.GetDB(ctx, tx).Model(&models.Org{}).
		Where("slug LIKE ?", organizationSlug+"%").
		Pluck("slug", &slugs).Error
	if err != nil {
		return "", err
	}

	baseTaken := false
	existing := make(map[string]bool)
	for _, s := range slugs {
		existing[s] = true
		if s == organizationSlug {
			baseTaken = true
		}
	}

	if !baseTaken {
		return organizationSlug, nil
	}

	for i := 1; ; i++ {
		candidate := fmt.Sprintf("%s-%d", organizationSlug, i)
		if !existing[candidate] {
			return candidate, nil
		}
	}
}

func (g *orgRepository) GetOrgsWithVulnSharingAssets(ctx context.Context, tx *gorm.DB) ([]models.Org, error) {
	var orgs []models.Org
	err := g.GetDB(ctx, tx).Model(&models.Org{}).
		Where("EXISTS (SELECT 1 FROM projects WHERE projects.organization_id = organizations.id AND EXISTS (SELECT 1 FROM assets WHERE assets.project_id = projects.id AND assets.shares_information = true))").Find(&orgs).Error
	return orgs, err
}
