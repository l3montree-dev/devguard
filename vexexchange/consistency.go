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

// Package vexexchange contains the rules of the VEX exchange that DevGuard and the central exchange server
// both apply. It only depends on dtos and normalize, so the exchange server can import it without the
// database models of DevGuard.
package vexexchange

import (
	"log/slog"
	"slices"
	"sort"

	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/normalize"
)

// EventTypes are the assessments that are exchanged.
var EventTypes = []dtos.VulnEventType{dtos.EventTypeAccepted, dtos.EventTypeFalsePositive}

// mechanicalJustifications are the justifications a false positive may have.
var mechanicalJustifications = []dtos.MechanicalJustificationType{
	dtos.ComponentNotPresent,
	dtos.VulnerableCodeNotPresent,
	dtos.VulnerableCodeNotInExecutePath,
	dtos.VulnerableCodeCannotBeControlledByAdversary,
	dtos.InlineMitigationsAlreadyExist,
}

func IsExchangeableAssessment(eventType dtos.VulnEventType, mechanicalJustification dtos.MechanicalJustificationType) bool {
	switch eventType {
	case dtos.EventTypeAccepted:
		return true
	case dtos.EventTypeFalsePositive:
		return slices.Contains(mechanicalJustifications, mechanicalJustification)
	default:
		return false
	}
}

func ConsistentRules(rules []dtos.VEXExchangeRuleDTO, dominanceThreshold float64) []dtos.VEXExchangeRuleDTO {
	groups := make(map[string][]dtos.VEXExchangeRuleDTO)
	dropped := 0
	for _, rule := range rules {
		if !IsExchangeableAssessment(rule.EventType, rule.MechanicalJustification) {
			dropped++
			continue
		}
		normalized, err := normalize.NormalizeCELExpression(rule.CELExpression)
		if err != nil {
			dropped++
			continue
		}
		rule.CELExpression = normalized.CELExpression
		rule.CVEScope = normalized.CVEScope
		groups[rule.CELExpression] = append(groups[rule.CELExpression], rule)
	}
	if dropped > 0 {
		slog.Warn("dropped VEX rules with an assessment that is not exchanged or an invalid expression", "dropped", dropped)
	}

	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	consistent := make([]dtos.VEXExchangeRuleDTO, 0, len(keys))
	contradicting := 0
	for _, key := range keys {
		dominant, ok := dominantRule(groups[key], dominanceThreshold)
		if !ok {
			contradicting++
			continue
		}
		consistent = append(consistent, dominant)
	}
	if contradicting > 0 {
		slog.Info("skipped contradicting VEX rules without a dominant assessment", "groups", contradicting)
	}
	return consistent
}

func dominantRule(group []dtos.VEXExchangeRuleDTO, dominanceThreshold float64) (dtos.VEXExchangeRuleDTO, bool) {
	rulesPerEventType := make(map[dtos.VulnEventType]int)
	for _, rule := range group {
		rulesPerEventType[rule.EventType]++
	}

	for _, rule := range group {
		share := float64(rulesPerEventType[rule.EventType]) / float64(len(group))
		if share >= dominanceThreshold {
			return rule, true
		}
	}
	return dtos.VEXExchangeRuleDTO{}, false
}
