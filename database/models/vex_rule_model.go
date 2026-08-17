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
)

// VEXRule represents a rule for automatically marking vulnerabilities based on VEX statements.
// Rules are scoped to an asset and apply to all matching dependency vulnerabilities.
// Path patterns support wildcards: "*" matches any single path element, "**" matches any number of elements.
// Primary key: Hash(AssetID, CVEID, PathPattern, VexSource)
type VEXRule struct {
	UpstreamVEXRule
	// Composite key components (for indexing and queries)
	AssetID uuid.UUID `json:"assetId" gorm:"type:uuid;not null;index:,composite:vex_composite_key"`
	// Relationships
	Asset       Asset  `json:"asset" gorm:"foreignKey:AssetID;references:ID;constraint:OnDelete:CASCADE;"`
	CreatedByID string `json:"createdById" gorm:"type:text;not null"`
	// Enabled indicates whether this rule should be applied to matching vulnerabilities.
	// When false, the rule exists but does not create events or modify vulnerability state.
	// Rules are disabled when uploaded in ParanoidMode, requiring manual review/enabling.
	Enabled bool `json:"enabled" gorm:"default:true;not null;"`

	// this will be set, when the rule was recommended by the crowdsourced vexing algorithm.
	WasRecommended bool `json:"recommendedRule" gorm:"default:false;not null;"`
}

func (VEXRule) TableName() string {
	return "vex_rules"
}

// SetCELExpression sets the CELExpression and recalculates the ID.
func (r *VEXRule) SetCELExpression(expression string) {
	r.CELExpression = expression
	r.ID = CalculateVEXRuleID(r.AssetID, r.CELExpression, r.VexSource)
}

// EnsureID calculates the ID if it hasn't been set yet.
func (r *VEXRule) EnsureID() {
	if r.ID == "" {
		r.ID = CalculateVEXRuleID(r.AssetID, r.CELExpression, r.VexSource)
	}
}

// VEXRuleRecommendation is either an upstream-rule match (UpstreamVEXRuleID set) or a
// crowdsourced match against an existing local rule (VEXRuleID set) - never both.
type VEXRuleRecommendation struct {
	DependencyVulnID uuid.UUID `json:"dependencyVulnerabilityId" gorm:"type:uuid;primaryKey;not null;"`
	VEXRuleID        *string   `json:"vexRuleId" gorm:"type:text;"`
	VEXRule          VEXRule   `json:"vexRule" gorm:"foreignKey:VEXRuleID;references:ID;constraint:OnDelete:CASCADE;"`

	UpstreamVEXRuleID *string         `json:"upstreamVexRuleId" gorm:"type:text;"`
	UpstreamVEXRule   UpstreamVEXRule `json:"upstreamVexRule" gorm:"foreignKey:UpstreamVEXRuleID;references:ID;constraint:OnDelete:CASCADE;"`

	VerifiedVotes int     `json:"verifiedVotes" gorm:"default:0;not null;"`
	TotalVotes    int     `json:"totalVotes" gorm:"default:0;not null;"`
	Confidence    float64 `json:"confidence" gorm:"default:0;not null;"`

	DependencyVulnSignature int64 `json:"dependencyVulnSignature" gorm:"type:bigint;not null;index;primaryKey"`
}

func (VEXRuleRecommendation) TableName() string {
	return "vex_rule_recommendations"
}
