// Copyright 2024 Tim Bastin, l3montree UG (haftungsbeschränkt)
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
	"os"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"gorm.io/gorm/clause"
)

type InvitationRepository struct {
	db core.DB
	common.Repository[uuid.UUID, models.Invitation, core.DB]
}

func NewInvitationRepository(db core.DB) *InvitationRepository {
	if os.Getenv("DISABLE_AUTOMIGRATE") != "true" {
		if err := db.AutoMigrate(&models.Invitation{}); err != nil {
			panic(err)
		}
	}
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

func (g *InvitationRepository) Save(db core.DB, invitation *models.Invitation) error {
	return g.Repository.GetDB(db).Omit(clause.Associations).Save(invitation).Error
}
