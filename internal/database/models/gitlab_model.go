// Copyright (C) 2024 Tim Bastin, l3montree UG (haftungsbeschränkt)
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

package models

import (
	"github.com/google/uuid"
)

type GitLabIntegration struct {
	Model

	Name string `json:"name"`

	AccessToken string `json:"accessToken"`
	GitLabUrl   string `json:"gitLabUrl" gorm:"column:gitlab_url"`

	Org   Org       `json:"org" gorm:"foreignKey:OrgID;constraint:OnDelete:CASCADE;"`
	OrgID uuid.UUID `json:"orgId" gorm:"column:org_id"`
}

func (GitLabIntegration) TableName() string {
	return "gitlab_integrations"
}
