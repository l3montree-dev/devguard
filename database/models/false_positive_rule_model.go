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
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/dtos"
)

// FalsePositiveRule represents a rule for automatically marking vulnerabilities as false positives
// based on CVE ID and path patterns. Rules are scoped to an asset and apply to all matching dependency vulnerabilities.
type FalsePositiveRule struct {
	Model
	AssetID                 uuid.UUID                        `json:"assetId" gorm:"type:uuid;not null;index:idx_false_positive_rule_asset"`
	Asset                   Asset                            `json:"asset,omitempty" gorm:"foreignKey:AssetID;references:ID;constraint:OnDelete:CASCADE;"`
	CVEID                   string                           `json:"cveId" gorm:"type:text;not null;index:idx_false_positive_rule_cve"`
	Justification           string                           `json:"justification" gorm:"type:text;not null"`
	MechanicalJustification dtos.MechanicalJustificationType `json:"mechanicalJustification" gorm:"type:text;"`
	// PathPattern stores the path suffix patterns for this false positive rule.
	// When a vulnerability's path ends with any of these patterns, the rule applies.
	PathPattern []string `json:"pathPattern" gorm:"type:jsonb;not null;serializer:json"`
	CreatedByID string   `json:"createdById" gorm:"type:text;not null"`
}

func (FalsePositiveRule) TableName() string {
	return "false_positive_rules"
}
