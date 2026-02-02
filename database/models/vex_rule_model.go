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
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/utils"
)

// VEXRule represents a rule for automatically marking vulnerabilities based on VEX statements.
// Rules are scoped to an asset and apply to all matching dependency vulnerabilities.
// Path patterns support wildcards: "*" matches any single path element, "**" matches any number of elements.
// Primary key: Hash(AssetID, CVEID, PathPattern, VexSource)
type VEXRule struct {
	// Single primary key - hash of composite components
	ID string `json:"id" gorm:"primaryKey;not null;"`

	// Composite key components (for indexing and queries)
	AssetID          uuid.UUID `json:"assetId" gorm:"type:uuid;not null;index:,composite:vex_composite_key"`
	AssetVersionName string    `json:"assetVersionName" gorm:"type:text;not null;index:,composite:vex_composite_key"`
	CVEID            string    `json:"cveId" gorm:"type:text;not null;index:,composite:vex_composite_key"`
	VexSource        string    `json:"vexSource" gorm:"type:text;not null;index:,composite:vex_composite_key"`

	// Timestamps
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`

	// Relationships
	Asset        Asset        `json:"asset" gorm:"foreignKey:AssetID;references:ID;constraint:OnDelete:CASCADE;"`
	CVE          CVE          `json:"cve" gorm:"foreignKey:CVEID;references:CVE;constraint:OnDelete:CASCADE;"`
	AssetVersion AssetVersion `json:"assetVersion" gorm:"foreignKey:AssetVersionName,AssetID;references:Name,AssetID;constraint:OnDelete:CASCADE;"`

	// Rule data
	Justification           string                           `json:"justification" gorm:"type:text;not null"`
	MechanicalJustification dtos.MechanicalJustificationType `json:"mechanicalJustification" gorm:"type:text;"`
	EventType               dtos.VulnEventType               `json:"eventType" gorm:"type:text;not null;"`

	// PathPattern stores the path patterns for this VEX rule.
	// Supports wildcards: "*" matches any single element, "**" matches any number of elements.
	PathPattern []string `json:"pathPattern" gorm:"type:jsonb;not null;serializer:json"`
	CreatedByID string   `json:"createdById" gorm:"type:text;not null"`
}

func (VEXRule) TableName() string {
	return "vex_rules"
}

// CalculateID computes a SHA256 hash of AssetID, CVEID, PathPattern, and VexSource for use as the primary key.
// This ensures a deterministic, unique ID for each VEX rule combination.
func CalculateVEXRuleID(assetID uuid.UUID, cveID string, pathPattern []string, vexSource string) string {
	data := fmt.Sprintf("%s/%s/%s/%s", assetID.String(), cveID, strings.Join(pathPattern, ","), vexSource)
	return utils.HashString(data)
}

// SetPathPattern sets the PathPattern and recalculates the ID.
func (r *VEXRule) SetPathPattern(pattern []string) {
	r.PathPattern = pattern
	r.ID = CalculateVEXRuleID(r.AssetID, r.CVEID, pattern, r.VexSource)
}

// EnsureID calculates the ID if it hasn't been set yet.
func (r *VEXRule) EnsureID() {
	if r.ID == "" {
		r.ID = CalculateVEXRuleID(r.AssetID, r.CVEID, r.PathPattern, r.VexSource)
	}
}
