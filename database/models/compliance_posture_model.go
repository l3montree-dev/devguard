// Copyright (C) 2026 l3montree GmbH
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
	"fmt"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/utils"
	"gorm.io/gorm"
)

type CompliancePosture struct {
	Vulnerability

	FrameworkControlID string           `json:"frameworkControlId" gorm:"type:text;not null;"`
	FrameworkControl   FrameworkControl `json:"frameworkControl" gorm:"foreignKey:FrameworkControlID;references:FrameworkControlID;constraint:OnDelete:CASCADE;"`
	AssetVersionName   *string          `json:"assetVersionName" gorm:"type:text;"`
	AssetVersion       AssetVersion     `json:"assetVersion" gorm:"foreignKey:AssetVersionName,AssetID;references:Name,AssetID;constraint:OnDelete:CASCADE;"`

	AssetID   *uuid.UUID `json:"assetId" gorm:"type:uuid;"`
	Asset     Asset      `json:"asset" gorm:"foreignKey:AssetID;references:ID;constraint:OnDelete:CASCADE;"`
	ProjectID *uuid.UUID `json:"projectId" gorm:"type:uuid"`
	Project   Project    `json:"project" gorm:"foreignKey:ProjectID;references:ID;constraint:OnDelete:CASCADE;"`
	OrgID     uuid.UUID  `json:"orgId" gorm:"type:uuid;not null;"`
	Org       Org        `json:"org" gorm:"foreignKey:OrgID;references:ID;constraint:OnDelete:CASCADE;"`

	Events []VulnEvent `json:"events" gorm:"foreignKey:CompliancePostureID;constraint:OnDelete:CASCADE;"`
}

func (m CompliancePosture) GetAssetVersionName() string {
	if m.AssetVersionName != nil {
		return *m.AssetVersionName
	}
	return ""
}

func (m CompliancePosture) AssetVersionIndependentHash() string {
	s := fmt.Sprintf("%s:%s", m.FrameworkControlID, m.OrgID.String())
	if m.ProjectID != nil {
		s = fmt.Sprintf("%s:%s", s, m.ProjectID.String())
	}
	if m.AssetID != nil {
		s = fmt.Sprintf("%s:%s", s, m.AssetID.String())
	}
	return utils.HashString(s)
}

func (m CompliancePosture) GetEvents() []VulnEvent {
	return m.Events
}

func (m CompliancePosture) GetArtifacts() []Artifact {
	return nil
}

func (m CompliancePosture) GetType() dtos.VulnType {
	return dtos.VulnTypeCompliancePosture
}

func (m CompliancePosture) TableName() string {
	return "compliance_postures"
}

func (m CompliancePosture) CalculateHash() uuid.UUID {
	s := fmt.Sprintf("%s:%s", m.FrameworkControlID, m.OrgID.String())
	if m.ProjectID != nil {
		s = fmt.Sprintf("%s:%s", s, m.ProjectID.String())
	}
	if m.AssetID != nil {
		s = fmt.Sprintf("%s:%s", s, m.AssetID.String())
	}
	if m.AssetVersionName != nil {
		s = fmt.Sprintf("%s:%s", s, *m.AssetVersionName)
	}
	return utils.HashToUUID(s)
}

func (m CompliancePosture) BeforeSave(tx *gorm.DB) error {
	m.ID = m.CalculateHash()
	return nil
}
