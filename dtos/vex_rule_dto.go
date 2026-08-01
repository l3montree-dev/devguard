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

package dtos

import (
	"github.com/google/uuid"
)

type VEXRuleDTO struct {
	// Primary key
	ID string `json:"id"`

	// Composite key components
	AssetID   uuid.UUID `json:"assetId"`
	CVEID     string    `json:"cveId"`
	VexSource string    `json:"vexSource"`

	// Rule data
	Title                   string                      `json:"title"`
	Justification           string                      `json:"justification"`
	MechanicalJustification MechanicalJustificationType `json:"mechanicalJustification"`
	EventType               VulnEventType               `json:"eventType"`
	PathPattern             []string                    `json:"pathPattern"`
	CELExpression           string                      `json:"celExpression"`
	CreatedByID             string                      `json:"createdById"`
	CreatedAt               string                      `json:"createdAt"`
	UpdatedAt               string                      `json:"updatedAt"`

	// Metrics
	AppliesToAmountOfDependencyVulns int `json:"appliesToAmountOfDependencyVulns"`
}

// VexRuleRecommendationSource identifies how a recommendation was derived,
// since that determines which of its fields (Confidence/votes) are meaningful.
type VexRuleRecommendationSource string

const (
	// VexRuleRecommendationSourceOrigin: taken directly from a matching rule on
	// an asset the requesting user already has access to.
	VexRuleRecommendationSourceOrigin VexRuleRecommendationSource = "origin"
	// VexRuleRecommendationSourceCrowdsourced: derived from voting across every
	// matching asset-owned VEX rule.
	VexRuleRecommendationSourceCrowdsourced VexRuleRecommendationSource = "crowdsourced"
	// VexRuleRecommendationSourceUpstream: matched a trusted upstream VEX rule;
	// always fully confident and has no votes.
	VexRuleRecommendationSourceUpstream VexRuleRecommendationSource = "upstream"
)

type VexRuleRecommendation struct {
	Title                            string                       `json:"title"`
	CELExpression                    string                       `json:"celExpression"`
	Justification                    string                       `json:"justification"`
	MechanicalJustification          MechanicalJustificationType  `json:"mechanicalJustification"`
	EventType                        VulnEventType                `json:"eventType"`
	Source                           VexRuleRecommendationSource  `json:"source"`
	Confidence                       float64                      `json:"confidence"`
	AppliesToAmountOfDependencyVulns int                          `json:"appliesToAmountOfDependencyVulns"`
	VerifiedVotes                    int                          `json:"verifiedVotes"`
	TotalVotes                       int                          `json:"totalVotes"`

	// ProjectSlug/OriginAssetSlug are set when this recommendation was
	// taken directly from a rule on an asset the requesting user already has
	// access to, rather than from the crowd-voted recommendation across
	// every matching rule. Lets the frontend link to that project/asset.
	ProjectSlug *string `json:"projectSlug,omitempty"`
	AssetSlug   *string `json:"assetSlug,omitempty"`
}

type TestVEXRulesRequest struct {
	ID            string   `json:"id" validate:"required"`
	CelExpression []string `json:"celExpression" validate:"required"`
}
type CreateVEXRuleRequest struct {
	Title                   string                      `json:"title"`
	Justification           string                      `json:"justification" validate:"required"`
	MechanicalJustification MechanicalJustificationType `json:"mechanicalJustification"`
	CELExpression           string                      `json:"celExpression"`
	EventType               VulnEventType               `json:"eventType"`
	WasRecommended          bool                        `json:"wasRecommended"`
}
