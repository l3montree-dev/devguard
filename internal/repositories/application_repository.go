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
	"github.com/l3montree-dev/flawfix/internal/models"
	"gorm.io/gorm"
)

type GormApplicationRepository struct {
	db *gorm.DB
}

func NewGormApplicationRepository(db *gorm.DB) *GormApplicationRepository {
	return &GormApplicationRepository{
		db: db,
	}
}

func (a *GormApplicationRepository) Save(app models.Application) error {
	return a.db.Create(&app).Error
}

func (a *GormApplicationRepository) FindByName(name string) (models.Application, error) {
	var app models.Application
	err := a.db.Where("name = ?", name).First(&app).Error
	if err != nil {
		return app, err
	}
	return app, nil
}

func (a *GormApplicationRepository) FindOrCreate(name string) (models.Application, error) {
	app, err := a.FindByName(name)
	if err != nil {
		app = models.Application{Name: name}
		err = a.Save(app)
		if err != nil {
			return app, err
		}
	}
	return app, nil
}
