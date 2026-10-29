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

package vexrules

import (
	"fmt"
	"log/slog"
	"slices"
	"sort"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/vexexchange"
)

const ExchangeDominanceThreshold = 0.8

func PrepareVEXRulesForExchange(rules []models.VEXRule) []dtos.VEXExchangeRuleDTO {
	sorted := sortedForExchange(rules)
	submission := make([]dtos.VEXExchangeRuleDTO, 0, len(sorted))
	for _, rule := range sorted {
		submission = append(submission, dtos.VEXExchangeRuleDTO{
			CELExpression:           rule.CELExpression,
			Title:                   rule.Title,
			Justification:           rule.Justification,
			EventType:               rule.EventType,
			MechanicalJustification: rule.MechanicalJustification,
		})
	}
	return vexexchange.ConsistentRules(submission, ExchangeDominanceThreshold)
}

func sortedForExchange(rules []models.VEXRule) []models.VEXRule {
	sorted := slices.Clone(rules)
	sort.SliceStable(sorted, func(i, j int) bool {
		if !sorted[i].CreatedAt.Equal(sorted[j].CreatedAt) {
			return sorted[i].CreatedAt.Before(sorted[j].CreatedAt)
		}
		return sorted[i].ID < sorted[j].ID
	})
	return sorted
}

func RecommendationsToVEXExchangeRules(recommendations []dtos.VEXExchangeRecommendationDTO) ([]models.VEXExchangeRule, error) {
	celEnv, err := CelEnv()
	if err != nil {
		return nil, fmt.Errorf("could not create CEL environment: %w", err)
	}

	rules := make([]models.VEXExchangeRule, 0, len(recommendations))
	seen := make(map[string]struct{}, len(recommendations))
	skipped := 0
	for _, recommendation := range recommendations {
		if !vexexchange.IsExchangeableAssessment(recommendation.EventType, recommendation.MechanicalJustification) {
			skipped++
			continue
		}
		normalized, err := normalize.NormalizeCELExpression(recommendation.CELExpression)
		if err != nil {
			skipped++
			continue
		}
		if _, issues := celEnv.Compile(normalized.CELExpression); issues != nil && issues.Err() != nil {
			skipped++
			continue
		}

		var title string
		if recommendation.Title != "" {
			title = recommendation.Title
		} else {
			if normalized.CVEScope != nil {
				title = fmt.Sprintf("VEX exchange recommendation for %s", *normalized.CVEScope)
			} else {
				title = "VEX exchange recommendation"
			}
		}

		rule := models.VEXExchangeRule{
			UpstreamVEXRule: models.UpstreamVEXRule{
				Title:                   title,
				Justification:           recommendation.Justification,
				MechanicalJustification: recommendation.MechanicalJustification,
				EventType:               recommendation.EventType,
				CELExpression:           normalized.CELExpression,
				CVEScope:                normalized.CVEScope,
			},
			ConfidenceScore: recommendation.ConfidenceScore,
		}
		rule.EnsureID()
		if _, ok := seen[rule.ID]; ok {
			continue
		}
		seen[rule.ID] = struct{}{}
		rules = append(rules, rule)
	}
	if skipped > 0 {
		slog.Warn("skipped invalid recommendations of the exchange server", "skipped", skipped)
	}
	return rules, nil
}
