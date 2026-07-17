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

	AssetID   *uuid.UUID `json:"assetId" gorm:"type:uuid;column:asset_id"`
	Asset     Asset      `json:"asset" gorm:"foreignKey:AssetID;references:ID;constraint:OnDelete:CASCADE;"`
	ProjectID *uuid.UUID `json:"projectId" gorm:"type:uuid;column:project_id"`
	Project   Project    `json:"project" gorm:"foreignKey:ProjectID;references:ID;constraint:OnDelete:CASCADE;"`
	OrgID     uuid.UUID  `json:"orgId" gorm:"type:uuid;not null;column:org_id"`
	Org       Org        `json:"org" gorm:"foreignKey:OrgID;references:ID;constraint:OnDelete:CASCADE;"`

	Events       []VulnEvent                                     `json:"events" gorm:"foreignKey:CompliancePostureID;constraint:OnDelete:CASCADE;"`
	ByComponents []ComplianceComponentImplementsControlStatement `json:"byComponents" gorm:"foreignKey:CompliancePostureID;constraint:OnDelete:CASCADE;"`
}

// this connects a component to a specific complianceComponentImplementsControl, which connects a component to a specific control
// this allows the user to say: Hey thats cool that I can use protected branches, but currently I did not enable it.
type ComplianceComponentImplementsControlStatement struct {
	ID uuid.UUID `json:"id" gorm:"type:uuid;primaryKey;column:id;default:gen_random_uuid()"`

	CompliancePostureID uuid.UUID         `json:"compliancePostureId" gorm:"type:uuid;not null;column:compliance_posture_id;uniqueIndex:idx_statement_posture_component"`
	CompliancePosture   CompliancePosture `json:"compliancePosture" gorm:"foreignKey:CompliancePostureID;references:ID;constraint:OnDelete:CASCADE;"`

	ComplianceComponentID uuid.UUID `json:"complianceComponentId" gorm:"type:uuid;not null;column:compliance_component_id;uniqueIndex:idx_statement_posture_component"`
	FrameworkControlID    string    `json:"frameworkControlId" gorm:"type:text;not null;column:framework_control_id"`

	ComplianceComponentImplementsControl ComplianceComponentImplementsControl `json:"complianceComponentImplementsControl" gorm:"foreignKey:ComplianceComponentID,FrameworkControlID;references:ComplianceComponentID,FrameworkControlID;constraint:OnDelete:CASCADE;"`

	ImplementationStatus string `json:"implementationStatus" gorm:"type:text;not null;column:implementation_status"`
	Description          string `json:"description" gorm:"type:text;not null;column:description"`
}

// A component itself can say something about "Hey this components help you to implement requirement XYZ, if you enable protected branches" for example.
// This is a catalog-level claim (from a component-definition), so it is always "implemented" by definition -
// whether it's actually enabled for a specific system is decided per-posture in ComplianceComponentImplementsControlStatement.
type ComplianceComponentImplementsControl struct {
	FrameworkControlID    string              `json:"frameworkControlId" gorm:"type:text;primaryKey;column:framework_control_id"`
	FrameworkControl      FrameworkControl    `json:"frameworkControl" gorm:"foreignKey:FrameworkControlID;references:FrameworkControlID;constraint:OnDelete:CASCADE;"`
	ComplianceComponentID uuid.UUID           `json:"complianceComponentId" gorm:"type:uuid;primaryKey;column:compliance_component_id"`
	ComplianceComponent   ComplianceComponent `json:"complianceComponent" gorm:"foreignKey:ComplianceComponentID;references:UUID;constraint:OnDelete:CASCADE;"`
	Description           string              `json:"description" gorm:"type:text;not null;column:description"`
}

type ComplianceComponent struct {
	UUID                uuid.UUID                              `json:"uuid" gorm:"type:uuid;primaryKey;column:uuid"`
	ImplementedControls []ComplianceComponentImplementsControl `json:"implementedControls" gorm:"foreignKey:ComplianceComponentID;constraint:OnDelete:CASCADE;"`
	Title               string                                 `json:"title" gorm:"type:text;not null;column:title"`
	Description         string                                 `json:"description" gorm:"type:text;not null;column:description"`
}

func (m ComplianceComponent) TableName() string {
	return "compliance_components"
}

func (m ComplianceComponentImplementsControl) TableName() string {
	return "compliance_component_implements_controls"
}

func (m ComplianceComponentImplementsControlStatement) TableName() string {
	return "compliance_component_implements_control_statements"
}

func (m CompliancePosture) GetAssetVersionName() string {
	if m.AssetVersionName != nil {
		return *m.AssetVersionName
	}
	return ""
}
func (m CompliancePosture) GetAssetID() uuid.UUID {
	if m.AssetID != nil {
		return *m.AssetID
	}
	return uuid.Nil
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
	return CalculateCompliancePostureHash(m.FrameworkControlID, m.OrgID, m.ProjectID, m.AssetID, m.AssetVersionName)
}

func (m CompliancePosture) BeforeSave(tx *gorm.DB) error {
	m.ID = m.CalculateHash()
	return nil
}

func CalculateCompliancePostureHash(frameworkControlID string, orgID uuid.UUID, projectID *uuid.UUID, assetID *uuid.UUID, assetVersionName *string) uuid.UUID {
	s := fmt.Sprintf("%s:%s", frameworkControlID, orgID.String())
	if projectID != nil {
		s = fmt.Sprintf("%s:%s", s, projectID.String())
	}
	if assetID != nil {
		s = fmt.Sprintf("%s:%s", s, assetID.String())
	}
	if assetVersionName != nil {
		s = fmt.Sprintf("%s:%s", s, *assetVersionName)
	}

	return uuid.NewSHA1(uuid.NameSpaceURL, []byte(s))
}
