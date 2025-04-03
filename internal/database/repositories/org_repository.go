// Copyright (C) 2023 Tim Bastin, l3montree UG (haftungsbeschränkt)
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
	"slices"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type orgRepository struct {
	db core.DB
	common.Repository[uuid.UUID, models.Org, core.DB]
}

func NewOrgRepository(db core.DB) *orgRepository {
	if err := db.AutoMigrate(&models.Org{}); err != nil {
		panic(err)
	}
	return &orgRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.Org](db),
	}
}
func (g *orgRepository) GetOrgByID(id uuid.UUID) (models.Org, error) {
	var t models.Org
	err := g.db.Model(models.Org{}).Where("id = ?", id).First(&t).Error
	return t, err
}
func (g *orgRepository) ReadBySlug(slug string) (models.Org, error) {
	var t models.Org
	err := g.db.Model(models.Org{}).Preload("GithubAppInstallations").Preload("GitLabIntegrations").Where("slug = ?", slug).First(&t).Error
	return t, err
}

func (g *orgRepository) List(
	ids []uuid.UUID,
) ([]models.Org, error) {
	var ts []models.Org
	err := g.db.Model(models.Org{}).Preload("GithubAppInstallations").Where("id IN ?", ids).Find(&ts).Error
	return ts, err
}

func (g *orgRepository) Update(tx core.DB, org *models.Org) error {
	return g.GetDB(tx).Save(org).Error
}

func (g *orgRepository) ContentTree(orgID uuid.UUID, projects []string) []common.ContentTreeElement {
	contentTreeMap := make(map[uuid.UUID]common.ContentTreeElement)
	// fetch all asset ids inside those projects
	var res []struct {
		AssetID     uuid.UUID `json:"asset_id"`
		ProjectID   uuid.UUID `json:"project_id"`
		AssetName   string    `json:"asset_name"`
		ProjectName string    `json:"project_name"`
		AssetSlug   string    `json:"asset_slug"`
		ProjectSlug string    `json:"project_slug"`
	}

	g.GetDB(nil).Raw(`SELECT assets.slug as asset_slug, projects.slug as project_slug, assets.name as asset_name, projects.name as project_name, assets.id as asset_id, project_id FROM assets INNER JOIN projects ON assets.project_id = projects.id WHERE projects.id IN (?) AND projects.organization_id = ?`, projects, orgID).Scan(&res)

	for _, r := range res {
		if _, ok := contentTreeMap[r.ProjectID]; !ok {
			contentTreeMap[r.ProjectID] = common.ContentTreeElement{
				ID:    r.ProjectID.String(),
				Title: r.ProjectName,
				Slug:  r.ProjectSlug,
			}
		}

		project := contentTreeMap[r.ProjectID]

		project.Assets = append(project.Assets, struct {
			ID    string `json:"id"`
			Title string `json:"title"`
			Slug  string `json:"slug"`
		}{
			ID:    r.AssetID.String(),
			Title: r.AssetName,
			Slug:  r.AssetSlug,
		})

		contentTreeMap[r.ProjectID] = project
	}

	// convert map to array
	var contentTree []common.ContentTreeElement
	for _, v := range contentTreeMap {
		contentTree = append(contentTree, v)
	}

	// do a sort on the id
	slices.SortFunc(contentTree, func(i, j common.ContentTreeElement) int {
		if i.ID < j.ID {
			return -1
		}
		if i.ID > j.ID {
			return 1
		}
		return 0
	})

	return contentTree
}
