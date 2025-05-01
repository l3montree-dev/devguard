// Copyright (C) 2025 l3montree UG (haftungsbeschraenkt)
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
	"time"

	"github.com/google/uuid"
)

type PolicyViolation struct {
	ID string `json:"id" gorm:"primaryKey"`

	Message          string    `json:"message" gorm:"type:text;"`
	AssetID          uuid.UUID `json:"assetId"`
	AssetVersionName string    `json:"assetVersionName"`

	PolicyID        string `json:"policyId"`
	AttestationName string `json:"attestationName"`

	AssetVersion AssetVersion `json:"assetVersion" gorm:"foreignKey:AssetID,AssetVersionName;references:AssetID,Name;constraint:OnDelete:CASCADE"`

	TicketID             *string `json:"ticketId" gorm:"default:null"`
	TicketURL            *string `json:"ticketUrl" gorm:"default:null"`
	ManualTicketCreation bool    `json:"manualTicketCreation" gorm:"default:false"`

	CreatedAt time.Time `json:"createdAt" gorm:"autoCreateTime"`
	UpdatedAt time.Time `json:"updatedAt" gorm:"autoUpdateTime"`

	State VulnState `json:"state" gorm:"default:'open';not null;type:text;"`
}
