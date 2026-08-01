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

package transformer

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
)

func VEXRuleToDTOWithCount(rule models.VEXRule, appliesToCount int) dtos.VEXRuleDTO {
	return dtos.VEXRuleDTO{
		// Primary key
		ID: rule.ID,

		// Composite key components
		AssetID:   rule.AssetID,
		VexSource: rule.VexSource,

		// Rule data
		Title:                   rule.Title,
		Justification:           rule.Justification,
		MechanicalJustification: rule.MechanicalJustification,
		EventType:               rule.EventType,
		CELExpression:           rule.CELExpression,
		CreatedByID:             rule.CreatedByID,
		CreatedAt:               rule.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:               rule.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),

		// Metrics
		AppliesToAmountOfDependencyVulns: appliesToCount,
	}
}

func VEXRuleToUpstreamVEXRule(rule models.VEXRule) models.UpstreamVEXRule {
	return rule.UpstreamVEXRule
}

// VEXRuleToRecommendationDTO builds a crowdsourced recommendation DTO from an
// asset-owned VEX rule that won the cross-asset vote.
func VEXRuleToRecommendationDTO(rule models.VEXRule, appliesToAmountOfDependencyVulns int, confidence float64, verifiedVotes, totalVotes int) dtos.VexRuleRecommendation {
	return dtos.VexRuleRecommendation{
		Title:                            rule.Title,
		CELExpression:                    rule.CELExpression,
		Justification:                    rule.Justification,
		MechanicalJustification:          rule.MechanicalJustification,
		EventType:                        rule.EventType,
		Source:                           dtos.VexRuleRecommendationSourceCrowdsourced,
		Confidence:                       confidence,
		VerifiedVotes:                    verifiedVotes,
		TotalVotes:                       totalVotes,
		AppliesToAmountOfDependencyVulns: appliesToAmountOfDependencyVulns,
	}
}

// UpstreamVEXRuleToRecommendationDTO builds a recommendation DTO for a trusted
// upstream VEX rule. Upstream rules are trusted outright rather than voted on,
// so there is no meaningful confidence/vote count beyond "fully confident".
func UpstreamVEXRuleToRecommendationDTO(rule models.UpstreamVEXRule, appliesToAmountOfDependencyVulns int) dtos.VexRuleRecommendation {
	return dtos.VexRuleRecommendation{
		Title:                            rule.Title,
		CELExpression:                    rule.CELExpression,
		Justification:                    rule.Justification,
		MechanicalJustification:          rule.MechanicalJustification,
		EventType:                        rule.EventType,
		Source:                           dtos.VexRuleRecommendationSourceUpstream,
		Confidence:                       1,
		AppliesToAmountOfDependencyVulns: appliesToAmountOfDependencyVulns,
	}
}

// VEXRuleRecommendationToDTO converts a stored recommendation to its DTO. A
// recommendation either matched an asset-owned VEX rule (VEXRuleID set) via
// the crowdsourced vote, or, failing that, a trusted upstream VEX rule
// (UpstreamVEXRuleID set).
func VEXRuleRecommendationToDTO(rec models.VEXRuleRecommendation, appliesToAmountOfDependencyVulns int) dtos.VexRuleRecommendation {
	if rec.VEXRuleID != "" {
		return VEXRuleToRecommendationDTO(rec.VEXRule, appliesToAmountOfDependencyVulns, rec.Confidence, rec.VerifiedVotes, rec.TotalVotes)
	}
	return UpstreamVEXRuleToRecommendationDTO(rec.UpstreamVEXRule, appliesToAmountOfDependencyVulns)
}

func VEXRuleToOriginRecommendationDTO(rule models.VEXRule, appliesToAmountOfDependencyVulns int, originProjectSlug, originAssetSlug string) dtos.VexRuleRecommendation {
	return dtos.VexRuleRecommendation{
		Title:                            rule.Title,
		CELExpression:                    rule.CELExpression,
		Justification:                    rule.Justification,
		MechanicalJustification:          rule.MechanicalJustification,
		EventType:                        rule.EventType,
		Source:                           dtos.VexRuleRecommendationSourceOrigin,
		Confidence:                       1,
		ProjectSlug:                      &originProjectSlug,
		AssetSlug:                        &originAssetSlug,
		AppliesToAmountOfDependencyVulns: appliesToAmountOfDependencyVulns,
	}
}

func UpstreamVEXRuleToVEXRule(rule models.UpstreamVEXRule, createdByID string, assetID uuid.UUID) models.VEXRule {
	return models.VEXRule{
		UpstreamVEXRule: rule,
		AssetID:         assetID,
		CreatedByID:     createdByID,
	}
}

func AllUpstreamVEXRulesToVEXRules(rules []models.UpstreamVEXRule, createdByID string, assetID uuid.UUID) []models.VEXRule {
	vexRules := make([]models.VEXRule, 0, len(rules))
	for _, rule := range rules {
		vexRules = append(vexRules, UpstreamVEXRuleToVEXRule(rule, createdByID, assetID))
	}
	return vexRules
}

func VEXRulesToUpstreamVEXRules(rules []models.VEXRule) []models.UpstreamVEXRule {
	upstreamRules := make([]models.UpstreamVEXRule, 0, len(rules))
	for _, rule := range rules {
		upstreamRules = append(upstreamRules, VEXRuleToUpstreamVEXRule(rule))
	}
	return upstreamRules
}
