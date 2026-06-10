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

type PolicyFrameworks struct {
	Framework string   `yaml:"framework" json:"framework"`
	Controls  []string `yaml:"controls"  json:"controls"`
}
type ComplianceRisk struct {
	Vulnerability

	PolicyID               string             `json:"policyId" gorm:"type:text;"`
	PolicyTitle            string             `json:"policyTitle" gorm:"type:text;"`
	PolicyDescription      *string            `json:"policyDescription" gorm:"type:text;"`
	PolicyRelatedResources []string           `json:"policyRelatedResources" gorm:"type:jsonb;serializer:json"`
	PolicyTags             []string           `json:"policyTags" gorm:"type:jsonb;serializer:json"`
	PolicyPriority         int                `json:"policyPriority"`
	PolicyFrameworks       []PolicyFrameworks `json:"policyFrameworks" gorm:"column:policyFrameworks;type:jsonb;serializer:json"`
	EvidenceType           string             `json:"evidenceType" gorm:"type:text;"`
	EvidenceContent        []byte             `json:"evidenceContent" gorm:"type:bytea;"`

	Message string `json:"message" gorm:"type:text;"`

	Violations []string `json:"violations" gorm:"type:jsonb;serializer:json"`

	Events []VulnEvent `gorm:"foreignKey:ComplianceRiskID;constraint:OnDelete:CASCADE,OnUpdate:CASCADE;" json:"events"`

	Artifacts []Artifact `json:"artifacts" gorm:"many2many:artifact_compliance_risks;constraint:OnDelete:CASCADE"`
}

func (complianceRisk ComplianceRisk) TableName() string {
	return "compliance_risks"
}

func (complianceRisk ComplianceRisk) GetType() dtos.VulnType {
	return dtos.VulnTypeComplianceRisk
}

func (complianceRisk *ComplianceRisk) CalculateHash() uuid.UUID {
	return utils.HashToUUID(fmt.Sprintf("%s/%s/%s", complianceRisk.PolicyID, complianceRisk.AssetVersionName, complianceRisk.AssetID))
}

func (complianceRisk *ComplianceRisk) BeforeSave(tx *gorm.DB) error {
	complianceRisk.ID = complianceRisk.CalculateHash()
	return nil
}

func (complianceRisk ComplianceRisk) GetEvents() []VulnEvent {
	return complianceRisk.Events
}

func (complianceRisk *ComplianceRisk) GetArtifacts() []Artifact {
	return complianceRisk.Artifacts
}

func (complianceRisk ComplianceRisk) GetAssetVersionName() string {
	return complianceRisk.AssetVersionName
}

func (complianceRisk ComplianceRisk) AssetVersionIndependentHash() string {
	return utils.HashString(complianceRisk.PolicyID)
}

func (complianceRisk *ComplianceRisk) GetArtifactNames() string {
	names := ""
	for _, a := range complianceRisk.Artifacts {
		if names != "" {
			names += ", "
		}
		names += a.ArtifactName
	}
	return names
}

func (complianceRisk ComplianceRisk) Title() string {
	return fmt.Sprintf("Compliance risk for policy %s", complianceRisk.PolicyID)
}
