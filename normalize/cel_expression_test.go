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

package normalize

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustNormalize(t *testing.T, expression string) string {
	t.Helper()
	normalized, err := NormalizeCELExpression(expression)
	require.NoError(t, err)
	return normalized.CELExpression
}

func TestNormalizeCELExpression_EquivalentExpressionsBecomeIdentical(t *testing.T) {
	cases := []struct {
		name  string
		left  string
		right string
	}{
		{"whitespace", `vuln.cveId=="CVE-2025-0001"`, `vuln.cveId  ==  "CVE-2025-0001"`},
		{"swapped && operands", `a && b`, `b && a`},
		{"swapped || operands", `a || b`, `b || a`},
		{"different nesting of &&", `a && (b && c)`, `(c && a) && b`},
		{"|| nested in &&", `(x || y) && z`, `z && (y || x)`},
		{"&& nested in ||", `(a && b) || c`, `c || (b && a)`},
		{
			"DevGuard path pattern expression",
			`vuln.cveId == "CVE-2025-61725" && matchesPattern(vuln, ["*", "pkg:golang/stdlib"])`,
			`matchesPattern(vuln, ["*", "pkg:golang/stdlib"]) && vuln.cveId == "CVE-2025-61725"`,
		},
		{"operands inside a macro", `vuln.paths.exists(p, p == "a" && p != "b")`, `vuln.paths.exists(p, p != "b" && p == "a")`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, mustNormalize(t, tc.left), mustNormalize(t, tc.right))
		})
	}
}

func TestNormalizeCELExpression_DifferentExpressionsStayDifferent(t *testing.T) {
	cases := []struct {
		name  string
		left  string
		right string
	}{
		{"different operators", `a && b`, `a || b`},
		{"different operands", `a && b`, `a && c`},
		{"different grouping of mixed operators", `(a && b) || c`, `a && (b || c)`},
		// documented limitation: only && and || are treated as commutative
		{"swapped == operands", `a == b`, `b == a`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.NotEqual(t, mustNormalize(t, tc.left), mustNormalize(t, tc.right))
		})
	}
}

func TestNormalizeCELExpression_SortsOperands(t *testing.T) {
	assert.Equal(t, "a && b && c", mustNormalize(t, `c && (b && a)`))
}

func TestNormalizeCELExpression_IsIdempotent(t *testing.T) {
	expressions := []string{
		`c && (b && a)`,
		`(x || y) && z`,
		`vuln.cveId == "CVE-2025-61725" && matchesPattern(vuln, ["*", "pkg:golang/stdlib"])`,
		`vuln.paths.exists(p, p == "a" && p != "b")`,
	}

	for _, expression := range expressions {
		t.Run(expression, func(t *testing.T) {
			normalized := mustNormalize(t, expression)
			assert.Equal(t, normalized, mustNormalize(t, normalized))
		})
	}
}

func TestNormalizeCELExpression_RejectsInvalidInput(t *testing.T) {
	for _, expression := range []string{``, `vuln.cveId ==`, `a && && b`, `(a && b`} {
		t.Run("invalid expression: "+expression, func(t *testing.T) {
			_, err := NormalizeCELExpression(expression)
			assert.Error(t, err)
		})
	}
}

func TestCVEScope(t *testing.T) {
	cases := []struct {
		name     string
		expr     string
		expected *string
	}{
		{"standalone CVE check", `vuln.cveId == "CVE-2025-61725"`, new("CVE-2025-61725")},
		{"CVE check before matchesPattern", `vuln.cveId == "CVE-2025-61725" && matchesPattern(vuln, ["*"])`, new("CVE-2025-61725")},
		{"CVE check after matchesPattern", `matchesPattern(vuln, ["*"]) && vuln.cveId == "CVE-2025-61725"`, new("CVE-2025-61725")},
		{"CVE check in a longer && chain", `vuln.componentPurl == "pkg:npm/a" && (vuln.cveId == "CVE-2025-61725" && matchesPattern(vuln, ["*"]))`, new("CVE-2025-61725")},
		{"CVE check OR-ed is not scoped", `vuln.cveId == "CVE-2025-61725" || matchesPattern(vuln, ["*"])`, nil},
		{"CVE check nested in an || is not scoped", `matchesPattern(vuln, ["*"]) && (vuln.cveId == "CVE-1" || vuln.cveId == "CVE-2")`, nil},
		{"swapped operands are not scoped", `"CVE-2025-61725" == vuln.cveId`, nil},
		{"other identifier is not scoped", `other.cveId == "CVE-2025-61725"`, nil},
		{"empty CVE is not scoped", `vuln.cveId == ""`, nil},
		{"no CVE check", `matchesPattern(vuln, ["*"])`, nil},
		{"invalid expression", `vuln.cveId == "CVE-2025-61725" && `, nil},
		{"empty expression", ``, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := CVEScopeOfCELExpression(tc.expr)
			assert.Equal(t, tc.expected, got)

			// both functions derive the scope the same way
			if normalized, err := NormalizeCELExpression(tc.expr); err == nil {
				assert.Equal(t, tc.expected, normalized.CVEScope)
			}
		})
	}
}
