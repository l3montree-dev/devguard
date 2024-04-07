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
	"fmt"

	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/database"
	"github.com/l3montree-dev/flawfix/internal/database/models"
	"github.com/l3montree-dev/flawfix/internal/obj"
)

type assetRepository struct {
	db database.DB
	Repository[uuid.UUID, models.Asset, core.DB]
}

func NewAssetRepository(db core.DB) *assetRepository {
	err := db.AutoMigrate(&models.Asset{})
	if err != nil {
		panic(err)
	}

	return &assetRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.Asset](db),
	}
}

func (a *assetRepository) FindByName(name string) (models.Asset, error) {
	var app models.Asset
	err := a.db.Where("name = ?", name).First(&app).Error
	if err != nil {
		return app, err
	}
	return app, nil
}

func (a *assetRepository) GetAllComponentsByAssetID(assetID uuid.UUID) []obj.ComponentDepth {
	res := make([]obj.ComponentDepth, 0)
	a.db.Raw(`
        WITH RECURSIVE ComponentHierarchy AS (
            SELECT c.purl_or_cpe, 1 AS depth
            FROM asset_components ac
            INNER JOIN components c ON ac.component_purl_or_cpe = c.purl_or_cpe
            WHERE ac.asset_id = ?
        
            UNION ALL
        
            SELECT cd.depends_on_purl_or_cpe, ch.depth + 1 AS depth
            FROM ComponentHierarchy ch
            JOIN component_dependencies cd ON ch.purl_or_cpe = cd.component_purl_or_cpe
            WHERE ch.depth < 10
        )
        SELECT DISTINCT purl_or_cpe, 
            CASE 
                WHEN depth > 10 THEN 10 
                ELSE depth 
            END AS depth
        FROM ComponentHierarchy;
    `, assetID).Scan(&res)

	return res
}

func (a *assetRepository) GetTransitiveDependencies(assetID uuid.UUID) []obj.Dependency {
	var results []obj.Dependency

	fmt.Println("assetID", assetID.String())
	a.db.Raw(`
	WITH RECURSIVE ComponentHierarchy AS (
		SELECT
			source.purl_or_cpe AS source,
			dependencies.depends_on_purl_or_cpe AS dep,
			1 AS depth
		FROM
			components source
		LEFT JOIN component_dependencies dependencies ON source.purl_or_cpe = dependencies.component_purl_or_cpe
		WHERE EXISTS (
		   SELECT 1 from asset_components WHERE asset_components.asset_id = ? AND asset_components.component_purl_or_cpe = source.purl_or_cpe
		)
		UNION ALL
	
		SELECT
			ch.source,
			cd.depends_on_purl_or_cpe,
			ch.depth + 1
		FROM
			ComponentHierarchy ch
		INNER JOIN component_dependencies cd ON ch.dep = cd.component_purl_or_cpe
		WHERE
			ch.depth < 10
	)
	SELECT
		DISTINCT source, dep,
		CASE
			WHEN depth > 10 THEN 10
			ELSE depth
		END AS depth
	FROM
		ComponentHierarchy;
	`, assetID).Scan(&results)

	return results
}

func (a *assetRepository) FindOrCreate(tx core.DB, name string) (models.Asset, error) {
	app, err := a.FindByName(name)
	if err != nil {
		app = models.Asset{Name: name}
		err = a.Create(tx, &app)
		if err != nil {
			return app, err
		}
	}
	return app, nil
}

func (a *assetRepository) GetByProjectID(projectID uuid.UUID) ([]models.Asset, error) {
	var apps []models.Asset
	err := a.db.Where("project_id = ?", projectID).Find(&apps).Error
	if err != nil {
		return nil, err
	}
	return apps, nil
}

func (g *assetRepository) ReadBySlug(projectID uuid.UUID, slug string) (models.Asset, error) {
	var t models.Asset
	err := g.db.Where("slug = ? AND project_id = ?", slug, projectID).First(&t).Error
	return t, err
}

func (g *assetRepository) GetAssetIDBySlug(projectID uuid.UUID, slug string) (uuid.UUID, error) {
	app, err := g.ReadBySlug(projectID, slug)
	if err != nil {
		return uuid.UUID{}, err
	}
	return app.ID, nil
}
