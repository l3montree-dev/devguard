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

package asset

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/database"
)

type GormRepository struct {
	db core.DB
	database.Repository[uuid.UUID, Model, core.DB]
}

type Repository interface {
	database.Repository[uuid.UUID, Model, core.DB]
	FindByName(name string) (Model, error)
	FindOrCreate(tx core.DB, name string) (Model, error)
	GetByProjectID(projectID uuid.UUID) ([]Model, error)
	ReadBySlug(projectID uuid.UUID, slug string) (Model, error)
	GetAssetIDBySlug(projectID uuid.UUID, slug string) (uuid.UUID, error)
}

func NewGormRepository(db core.DB) *GormRepository {
	return &GormRepository{
		db:         db,
		Repository: database.NewGormRepository[uuid.UUID, Model](db),
	}
}

func (a *GormRepository) FindByName(name string) (Model, error) {
	var app Model
	err := a.db.Where("name = ?", name).First(&app).Error
	if err != nil {
		return app, err
	}
	return app, nil
}

func (a *GormRepository) FindOrCreate(tx core.DB, name string) (Model, error) {
	app, err := a.FindByName(name)
	if err != nil {
		app = Model{Name: name}
		err = a.Create(tx, &app)
		if err != nil {
			return app, err
		}
	}
	return app, nil
}

func (a *GormRepository) GetByProjectID(projectID uuid.UUID) ([]Model, error) {
	var apps []Model
	err := a.db.Where("project_id = ?", projectID).Find(&apps).Error
	if err != nil {
		return nil, err
	}
	return apps, nil
}

func (g *GormRepository) ReadBySlug(projectID uuid.UUID, slug string) (Model, error) {
	var t Model
	err := g.db.Preload("Envs").Where("slug = ? AND project_id = ?", slug, projectID).First(&t).Error
	return t, err
}

func (g *GormRepository) GetAssetIDBySlug(projectID uuid.UUID, slug string) (uuid.UUID, error) {
	app, err := g.ReadBySlug(projectID, slug)
	if err != nil {
		return uuid.UUID{}, err
	}
	return app.ID, nil
}
