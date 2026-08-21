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
	"context"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIdentityOfRule(t *testing.T) {
	base := models.UpstreamVEXRule{CELExpression: `vuln.cve == "a" && vuln.severity == "high"`, EventType: dtos.EventTypeAccepted}

	tests := []struct {
		name      string
		other     models.UpstreamVEXRule
		wantEqual bool
	}{
		{"&& operand order swapped", models.UpstreamVEXRule{CELExpression: `vuln.severity == "high" && vuln.cve == "a"`, EventType: dtos.EventTypeAccepted}, true},
		{"identical rule", base, true},
		{"|| instead of &&", models.UpstreamVEXRule{CELExpression: `vuln.cve == "a" || vuln.severity == "high"`, EventType: dtos.EventTypeAccepted}, false},
		{"different literal", models.UpstreamVEXRule{CELExpression: `vuln.cve == "b" && vuln.severity == "high"`, EventType: dtos.EventTypeAccepted}, false},
		{"different event type", models.UpstreamVEXRule{CELExpression: base.CELExpression, EventType: dtos.EventTypeFalsePositive}, false},
	}

	baseID, err := IdentityOfRule(base)
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			otherID, err := IdentityOfRule(tt.other)
			require.NoError(t, err)
			if tt.wantEqual {
				assert.Equal(t, baseID, otherID)
			} else {
				assert.NotEqual(t, baseID, otherID)
			}
		})
	}
}

func TestIdentityOfRuleInvalidExpression(t *testing.T) {
	_, err := IdentityOfRule(models.UpstreamVEXRule{CELExpression: `this is not cel`})
	assert.Error(t, err)
}

// evalRule reports whether rule matches vuln.
func evalRule(t *testing.T, rule models.UpstreamVEXRule, vuln models.DependencyVuln) bool {
	t.Helper()
	compiled, err := CompileRules(context.Background(), []models.UpstreamVEXRule{rule})
	require.NoError(t, err)
	vulnMaps, err := PrepareVulnsForEval(context.Background(), []models.DependencyVuln{vuln})
	require.NoError(t, err)
	matches, err := EvalCompiledRules(context.Background(), compiled, vulnMaps)
	require.NoError(t, err)
	for _, matchingRuleIDs := range matches {
		if slices.Contains(matchingRuleIDs, rule.ID) {
			return true
		}
	}
	return false
}

func TestNowFunctionComparesLastStateChangeAge(t *testing.T) {
	rule := models.UpstreamVEXRule{
		ID:            "stale-30-days",
		CELExpression: `now() - timestamp(vuln.lastStateChange) > duration("720h")`, // 720h == 30 days
	}
	assetID := uuid.New()

	newVuln := models.DependencyVuln{
		Vulnerability: models.Vulnerability{
			AssetVersionName: "main",
			AssetID:          assetID,
			LastStateChange:  time.Now().Add(-time.Hour),
		},
		CVEID: "CVE-2024-0001",
	}
	assert.False(t, evalRule(t, rule, newVuln), "a vuln whose state changed an hour ago should not be considered stale")

	staleVuln := models.DependencyVuln{
		Vulnerability: models.Vulnerability{
			AssetVersionName: "main",
			AssetID:          assetID,
			LastStateChange:  time.Now().Add(-31 * 24 * time.Hour),
		},
		CVEID: "CVE-2024-0001",
	}
	assert.True(t, evalRule(t, rule, staleVuln), "a vuln whose state changed 31 days ago should be considered stale")
}
