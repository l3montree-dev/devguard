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

package vexexchange

import (
	"testing"

	"github.com/l3montree-dev/devguard/dtos"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testAssessmentPrimary   = dtos.EventTypeFalsePositive
	testAssessmentSecondary = dtos.EventTypeAccepted
	testDominanceThreshold  = 0.8
)

func makeRule(expression string, eventType dtos.VulnEventType) dtos.VEXExchangeRuleDTO {
	rule := dtos.VEXExchangeRuleDTO{CELExpression: expression, EventType: eventType}
	if eventType == dtos.EventTypeFalsePositive {
		rule.MechanicalJustification = dtos.ComponentNotPresent
	}
	return rule
}

func makeRules(n int, expression string, eventType dtos.VulnEventType) []dtos.VEXExchangeRuleDTO {
	var rules []dtos.VEXExchangeRuleDTO
	for range n {
		rules = append(rules, makeRule(expression, eventType))
	}
	return rules
}

func TestConsistentRules_AgreeingRulesAreReducedToOne(t *testing.T) {
	consistent := ConsistentRules(makeRules(3, `a && b`, testAssessmentPrimary), testDominanceThreshold)

	require.Len(t, consistent, 1)
	assert.Equal(t, testAssessmentPrimary, consistent[0].EventType)
}

func TestConsistentRules_DominanceThreshold(t *testing.T) {
	cases := []struct {
		name      string
		primary   int
		secondary int
		expected  []dtos.VulnEventType
	}{
		{"4 vs 1 (80 %) keeps the dominant assessment", 4, 1, []dtos.VulnEventType{testAssessmentPrimary}},
		{"1 vs 4 (80 %) keeps the dominant assessment", 1, 4, []dtos.VulnEventType{testAssessmentSecondary}},
		{"9 vs 1 (90 %) keeps the dominant assessment", 9, 1, []dtos.VulnEventType{testAssessmentPrimary}},
		{"3 vs 1 (75 %) drops the group", 3, 1, nil},
		{"1 vs 1 (50 %) drops the group", 1, 1, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rules := append(makeRules(tc.primary, `a && b`, testAssessmentPrimary), makeRules(tc.secondary, `a && b`, testAssessmentSecondary)...)

			var eventTypes []dtos.VulnEventType
			for _, rule := range ConsistentRules(rules, testDominanceThreshold) {
				eventTypes = append(eventTypes, rule.EventType)
			}
			assert.Equal(t, tc.expected, eventTypes)
		})
	}
}

func TestConsistentRules_DifferentExpressionsAreNoContradiction(t *testing.T) {
	consistent := ConsistentRules([]dtos.VEXExchangeRuleDTO{
		makeRule(`a && b`, testAssessmentPrimary),
		makeRule(`a && c`, testAssessmentSecondary),
	}, testDominanceThreshold)

	assert.Len(t, consistent, 2)
}

func TestConsistentRules_ContradictionAfterNormalization(t *testing.T) {
	// contradicting rules that only differ in the order of the operands must be detected
	consistent := ConsistentRules([]dtos.VEXExchangeRuleDTO{
		makeRule(`a && b`, testAssessmentPrimary),
		makeRule(`b && a`, testAssessmentSecondary),
	}, testDominanceThreshold)

	assert.Empty(t, consistent, "a 50/50 contradiction must not be submitted")
}

func TestConsistentRules_KeepsTheFirstRuleOfTheDominantAssessment(t *testing.T) {
	first := makeRule(`a`, testAssessmentPrimary)
	first.Title = "first"
	second := makeRule(`a`, testAssessmentPrimary)
	second.Title = "second"

	consistent := ConsistentRules([]dtos.VEXExchangeRuleDTO{first, second}, testDominanceThreshold)

	require.Len(t, consistent, 1)
	assert.Equal(t, "first", consistent[0].Title)
}

func TestConsistentRules_NormalizesAndDerivesTheScope(t *testing.T) {
	rule := makeRule(`vuln.cveId == "CVE-2025-0001" && matchesPattern(vuln, ["*"])`, testAssessmentPrimary)
	// the given scope is ignored
	rule.CVEScope = new("CVE-0000-0000")

	consistent := ConsistentRules([]dtos.VEXExchangeRuleDTO{rule}, testDominanceThreshold)

	require.Len(t, consistent, 1)
	assert.Equal(t, `matchesPattern(vuln, ["*"]) && vuln.cveId == "CVE-2025-0001"`, consistent[0].CELExpression)
	require.NotNil(t, consistent[0].CVEScope)
	assert.Equal(t, "CVE-2025-0001", *consistent[0].CVEScope)
}

func TestConsistentRules_SortedByExpression(t *testing.T) {
	consistent := ConsistentRules([]dtos.VEXExchangeRuleDTO{
		makeRule(`c`, testAssessmentPrimary),
		makeRule(`a`, testAssessmentPrimary),
		makeRule(`b`, testAssessmentPrimary),
	}, testDominanceThreshold)

	require.Len(t, consistent, 3)
	assert.Equal(t, []string{"a", "b", "c"}, []string{consistent[0].CELExpression, consistent[1].CELExpression, consistent[2].CELExpression})
}

func TestConsistentRules_DropsInvalidRules(t *testing.T) {
	consistent := ConsistentRules([]dtos.VEXExchangeRuleDTO{
		{CELExpression: `a`, EventType: dtos.EventTypeAccepted},
		{CELExpression: `b`, EventType: "irgendwas"},
		{CELExpression: `c`, EventType: dtos.EventTypeFalsePositive, MechanicalJustification: dtos.ComponentNotPresent},
		{CELExpression: `d`, EventType: dtos.EventTypeFalsePositive, MechanicalJustification: "quatsch"},
		{CELExpression: `e &&`, EventType: dtos.EventTypeAccepted},
	}, testDominanceThreshold)

	require.Len(t, consistent, 2)
	assert.Equal(t, `a`, consistent[0].CELExpression)
	assert.Equal(t, `c`, consistent[1].CELExpression)
}

func TestConsistentRules_EmptyInput(t *testing.T) {
	assert.Empty(t, ConsistentRules(nil, testDominanceThreshold))
}

func TestIsExchangeableAssessment(t *testing.T) {
	cases := []struct {
		name                    string
		eventType               dtos.VulnEventType
		mechanicalJustification dtos.MechanicalJustificationType
		allowed                 bool
	}{
		{"accepted without justification", dtos.EventTypeAccepted, "", true},
		{"false positive: component not present", dtos.EventTypeFalsePositive, dtos.ComponentNotPresent, true},
		{"false positive: vulnerable code not present", dtos.EventTypeFalsePositive, dtos.VulnerableCodeNotPresent, true},
		{"false positive: not in execute path", dtos.EventTypeFalsePositive, dtos.VulnerableCodeNotInExecutePath, true},
		{"false positive: cannot be controlled by adversary", dtos.EventTypeFalsePositive, dtos.VulnerableCodeCannotBeControlledByAdversary, true},
		{"false positive: inline mitigations", dtos.EventTypeFalsePositive, dtos.InlineMitigationsAlreadyExist, true},
		{"false positive without justification", dtos.EventTypeFalsePositive, "", false},
		{"false positive with unknown justification", dtos.EventTypeFalsePositive, "quatsch", false},
		{"unknown event type", "irgendwas", "", false},
		{"other DevGuard event type", dtos.EventTypeReopened, "", false},
		{"empty event type", "", dtos.ComponentNotPresent, false},
		{"event type with different case", "FalsePositive", dtos.ComponentNotPresent, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.allowed, IsExchangeableAssessment(tc.eventType, tc.mechanicalJustification))
		})
	}
}
