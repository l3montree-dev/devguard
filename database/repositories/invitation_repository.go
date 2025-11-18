// Copyright 2024 Tim Bastin, l3montree GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package repositories

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type InvitationRepository struct {
	db *gorm.DB
	utils.Repository[uuid.UUID, models.Invitation, *gorm.DB]
}

func NewInvitationRepository(db *gorm.DB) *InvitationRepository {
	return &InvitationRepository{
		db:         db,
		Repository: newGormRepository[uuid.UUID, models.Invitation](db),
	}
}

func (g *InvitationRepository) FindByCode(code string) (models.Invitation, error) {
	var t models.Invitation
	err := g.db.Model(models.Invitation{}).Preload("Organization").Where("code = ?", code).First(&t).Error
	return t, err
}

func (g *InvitationRepository) Save(db *gorm.DB, invitation *models.Invitation) error {
	return g.Repository.GetDB(db).Omit(clause.Associations).Save(invitation).Error
}
