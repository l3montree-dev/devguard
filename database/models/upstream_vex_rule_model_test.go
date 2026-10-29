package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetCVEScopeFromCELExpression(t *testing.T) {
	tests := []struct {
		name     string
		expr     string
		expected *string
	}{
		{
			name:     "standalone CVE check",
			expr:     `vuln.cveId == "CVE-2025-61725"`,
			expected: new("CVE-2025-61725"),
		},
		{
			name:     "standalone non-standard CVE-like identifier",
			expr:     `vuln.cveId == "DEBIAN-CVE-2019-1010022"`,
			expected: new("DEBIAN-CVE-2019-1010022"),
		},
		{
			name:     "CVE check AND-ed with matchesPattern",
			expr:     `vuln.cveId == "CVE-2025-61725" && matchesPattern(vuln, ["*", "pkg:golang/example/pkg@1.0.0"])`,
			expected: new("CVE-2025-61725"),
		},
		{
			name:     "CVE check AND-ed after matchesPattern",
			expr:     `matchesPattern(vuln, ["*", "pkg:golang/example/pkg@1.0.0"]) && vuln.cveId == "CVE-2025-61725"`,
			expected: new("CVE-2025-61725"),
		},
		{
			name:     "CVE check in the middle of a longer && chain",
			expr:     `vuln.componentPurl == "pkg:npm/a" && (vuln.cveId == "CVE-2025-61725" && matchesPattern(vuln, ["*"]))`,
			expected: new("CVE-2025-61725"),
		},
		{
			name:     "CVE check OR-ed with another condition is not scoped",
			expr:     `vuln.cveId == "CVE-2025-61725" || matchesPattern(vuln, ["*", "pkg:golang/example/pkg@1.0.0"])`,
			expected: nil,
		},
		{
			name:     "no cveId reference at all",
			expr:     `matchesPattern(vuln, ["*", "pkg:golang/example/pkg@1.0.0"])`,
			expected: nil,
		},
		{
			name:     "CVE check nested in an || is not scoped",
			expr:     `matchesPattern(vuln, ["*"]) && (vuln.cveId == "CVE-2025-61725" || vuln.cveId == "CVE-2025-1")`,
			expected: nil,
		},
		{
			name:     "invalid expression is not scoped",
			expr:     `vuln.cveId == "CVE-2025-61725" && `,
			expected: nil,
		},
		{
			name:     "empty expression",
			expr:     "",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := UpstreamVEXRule{CELExpression: tt.expr}
			rule.SetCVEScopeFromCELExpression()
			got := rule.CVEScope
			assert.Equal(t, tt.expr, rule.CELExpression, "the expression must not be changed")
			if tt.expected == nil {
				assert.Nil(t, got)
				return
			}
			if assert.NotNil(t, got) {
				assert.Equal(t, *tt.expected, *got)
			}
		})
	}
}
