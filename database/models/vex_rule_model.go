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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/dtos"
)

// VEXRule represents a rule for automatically marking vulnerabilities based on VEX statements.
// Rules are scoped to an asset and apply to all matching dependency vulnerabilities.
// Path patterns support wildcards: "*" matches any single path element, "**" matches any number of elements.
// Composite primary key: (AssetID, CVEID, PathPatternHash, VexSource)
type VEXRule struct {
	// Composite primary key fields
	AssetID         uuid.UUID `json:"assetId" gorm:"type:uuid;not null;primaryKey"`
	CVEID           string    `json:"cveId" gorm:"type:text;not null;primaryKey"`
	PathPatternHash string    `json:"-" gorm:"type:text;not null;primaryKey"` // SHA256 hash of PathPattern for indexing
	VexSource       string    `json:"vexSource" gorm:"type:text;not null;primaryKey"`

	// Timestamps
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`

	// Relationships
	Asset Asset `json:"asset,omitempty" gorm:"foreignKey:AssetID;references:ID;constraint:OnDelete:CASCADE;"`
	CVE   CVE   `json:"cve,omitempty" gorm:"foreignKey:CVEID;references:CVE;constraint:OnDelete:CASCADE;"`

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

// CalculatePathPatternHash computes a SHA256 hash of the PathPattern for use in the composite key.
func CalculatePathPatternHash(pattern []string) string {
	data, _ := json.Marshal(pattern)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// SetPathPattern sets the PathPattern and automatically updates the PathPatternHash.
func (r *VEXRule) SetPathPattern(pattern []string) {
	r.PathPattern = pattern
	r.PathPatternHash = CalculatePathPatternHash(pattern)
}
