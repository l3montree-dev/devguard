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
	"fmt"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"

	project "github.com/l3montree-dev/devguard/internal/core/project"
)

type orgRepository struct {
	db core.DB
	common.Repository[uuid.UUID, models.Org, core.DB]
}

func NewOrgRepository(db core.DB) *orgRepository {
	return &orgRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.Org](db),
	}
}

func (g *orgRepository) Create(tx core.DB, org *models.Org) error {
	firstFreeSlug, err := g.firstFreeSlug(org.Slug)
	if err != nil {
		return fmt.Errorf("could not generate next slug: %w", err)
	}
	org.Slug = firstFreeSlug

	return g.GetDB(tx).Create(org).Error
}

func (g *orgRepository) Save(tx core.DB, org *models.Org) error {
	// if the slug is empty, generate a new one
	if org.ID == uuid.Nil {
		firstFreeSlug, err := g.firstFreeSlug(org.Name)
		if err != nil {
			return fmt.Errorf("could not generate next slug: %w", err)
		}
		org.Slug = firstFreeSlug
	}

	return g.GetDB(tx).Save(org).Error
}

func (g *orgRepository) ReadBySlug(slug string) (models.Org, error) {
	var t models.Org
	err := g.db.Model(models.Org{}).Preload("GithubAppInstallations").Preload("JiraIntegrations").Preload("GitLabIntegrations").Preload("Webhooks", "project_id IS NULL").Where("slug = ?", slug).First(&t).Error
	return t, err
}

func (g *orgRepository) List(ids []uuid.UUID) ([]models.Org, error) {
	var ts []models.Org
	err := g.db.Model(models.Org{}).Preload("GithubAppInstallations").Where("id IN ?", ids).Find(&ts).Error
	return ts, err
}

func (g *orgRepository) Update(tx core.DB, org *models.Org) error {
	return g.GetDB(tx).Save(org).Error
}

func (g *orgRepository) ContentTree(orgID uuid.UUID, projects []string) []any {
	var projectModels []models.Project

	g.GetDB(nil).Preload("Assets").Where(`projects.id IN (?) AND projects.organization_id = ?`, projects, orgID).Find(&projectModels)

	result := make([]any, 0, len(projectModels))
	for _, p := range projectModels {
		result = append(result, project.FromModel(p))
	}
	return result
}

func (g *orgRepository) GetOrgByID(id uuid.UUID) (models.Org, error) {
	var org models.Org
	err := g.db.Model(models.Org{}).Where("id = ?", id).First(&org).Error
	return org, err
}

func (g *orgRepository) firstFreeSlug(organizationSlug string) (string, error) {
	var slugs []string
	err := g.db.Model(&models.Org{}).
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
