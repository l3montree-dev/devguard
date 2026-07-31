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
	"testing"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIdentityOfRule(t *testing.T) {
	base := models.VEXRule{CELExpression: `vuln.cve == "a" && vuln.severity == "high"`, EventType: dtos.EventTypeAccepted}

	tests := []struct {
		name      string
		other     models.VEXRule
		wantEqual bool
	}{
		{"&& operand order swapped", models.VEXRule{CELExpression: `vuln.severity == "high" && vuln.cve == "a"`, EventType: dtos.EventTypeAccepted}, true},
		{"identical rule", base, true},
		{"|| instead of &&", models.VEXRule{CELExpression: `vuln.cve == "a" || vuln.severity == "high"`, EventType: dtos.EventTypeAccepted}, false},
		{"different literal", models.VEXRule{CELExpression: `vuln.cve == "b" && vuln.severity == "high"`, EventType: dtos.EventTypeAccepted}, false},
		{"different event type", models.VEXRule{CELExpression: base.CELExpression, EventType: dtos.EventTypeFalsePositive}, false},
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
	_, err := IdentityOfRule(models.VEXRule{CELExpression: `this is not cel`})
	assert.Error(t, err)
}

func TestEvalCELExpression(t *testing.T) {
	t.Run("matchesPattern function should be define and work as expected", func(t *testing.T) {

		res, err := EvalRule(
			t.Context(),
			models.VEXRule{
				CELExpression: `matchesPattern(vuln, ["pkg:golang/lib@v1.0"])`,
			},
			models.DependencyVuln{
				VulnerabilityPath: []string{"pkg:golang/lib@v1.0"},
			},
		)
		assert.NoError(t, err)
		assert.Equal(t, true, res)
	})

	t.Run("matchesPurl should treat the second argument as the constraint", func(t *testing.T) {
		vuln := models.DependencyVuln{ComponentPurl: "pkg:npm/undici@6.26.4"}

		tests := []struct {
			pattern string
			want    bool
		}{
			{"pkg:npm/undici@6.26.*", true},
			{"pkg:npm/undici@6.26.4", true},
			{"pkg:npm/undici@>=6.0.0", true},
			{"pkg:npm/undici@6.25.*", false},
			{"pkg:npm/other@6.26.*", false},
		}

		for _, tt := range tests {
			t.Run(tt.pattern, func(t *testing.T) {
				res, err := EvalRule(
					t.Context(),
					models.VEXRule{
						CELExpression: `matchesPurl(vuln.componentPurl, "` + tt.pattern + `")`,
					},
					vuln,
				)
				assert.NoError(t, err)
				assert.Equal(t, tt.want, res)
			})
		}
	})

	t.Run("vuln should be provided as variable", func(t *testing.T) {
		res, err := EvalRule(
			t.Context(),
			models.VEXRule{
				CELExpression: `matchesPattern(vuln, ["pkg:golang/lib@v1.0"])`,
			},
			models.DependencyVuln{
				VulnerabilityPath: []string{"pkg:golang/lib@v1.0"},
			},
		)
		assert.NoError(t, err)
		assert.Equal(t, true, res)

		res, err = EvalRule(
			t.Context(),
			models.VEXRule{
				CELExpression: `matchesPattern(vuln, ["pkg:golang/lib@v1.0"])`,
			},
			models.DependencyVuln{
				VulnerabilityPath: []string{"pkg:golang/lib@v1.0", "pkg:golang/other@v1.0"},
			},
		)
		assert.NoError(t, err)
		assert.Equal(t, false, res)
	})

	t.Run("should be filterable by cve id, or other properties", func(t *testing.T) {
		res, err := EvalRule(
			t.Context(),
			models.VEXRule{
				CELExpression: `vuln.cveId == "CVE-2024-1234"`,
			},
			models.DependencyVuln{
				CVEID: "CVE-2024-1234",
			},
		)
		assert.NoError(t, err)
		assert.Equal(t, true, res)
	})

	t.Run("matchesPattern should respect semver constraints", func(t *testing.T) {
		res, err := EvalRule(
			t.Context(),
			models.VEXRule{
				CELExpression: `matchesPattern(vuln, ["pkg:golang/lib@>=1.0.0,<2.0.0"])`,
			},
			models.DependencyVuln{
				VulnerabilityPath: []string{"pkg:golang/lib@1.5.0"},
			},
		)
		assert.NoError(t, err)
		assert.Equal(t, true, res)
	})

	t.Run("how should the path pattern work for artifacts", func(t *testing.T) {
		res, err := EvalRule(
			t.Context(),
			models.VEXRule{
				CELExpression: `matchesPattern(vuln, ["pkg:golang/github.com/l3montree-dev/devguard@<3.0.0", "pkg:golang/vulnlib@1.0.0"])`,
			},

			models.DependencyVuln{
				Artifacts: []models.Artifact{
					{
						ArtifactName: "pkg:/golang/github.com/l3montree-dev/devguard",
					},
				},
				Vulnerability: models.Vulnerability{
					AssetVersionName: "1.0.0",
				},
				VulnerabilityPath: []string{"pkg:golang/vulnlib@1.0.0"},
			},
		)
		assert.NoError(t, err)
		assert.Equal(t, true, res)
	})
	t.Run("how should the path pattern work for artifacts", func(t *testing.T) {
		res, err := EvalRule(
			t.Context(),
			models.VEXRule{
				CELExpression: `matchesPattern(vuln, ["pkg:golang/github.com/l3montree-dev/devguard@<3.0.0", "pkg:golang/vulnlib@1.0.0"])`,
			},

			models.DependencyVuln{
				Artifacts: []models.Artifact{
					{
						ArtifactName: "pkg:/golang/github.com/l3montree-dev/devguard",
					},
				},
				Vulnerability: models.Vulnerability{
					AssetVersionName: "4.0.0",
				},
				VulnerabilityPath: []string{"pkg:golang/vulnlib@1.0.0"},
			},
		)
		assert.NoError(t, err)
		assert.Equal(t, false, res)
	})
}

func BenchmarkEvalCELExpression(b *testing.B) {
	rule := models.VEXRule{
		CELExpression: `matchesPattern(vuln, ["pkg:golang/lib@v1.0"]) && vuln.cveId == "CVE-2024-1234"`,
	}
	vuln := models.DependencyVuln{
		CVEID:             "CVE-2024-1234",
		VulnerabilityPath: []string{"pkg:golang/lib@v1.0"},
	}
	ctx := b.Context()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := EvalRule(ctx, rule, vuln); err != nil {
			b.Fatal(err)
		}
	}
}
