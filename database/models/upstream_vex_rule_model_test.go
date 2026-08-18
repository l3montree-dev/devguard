package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractCVEScopeFromCELExpression(t *testing.T) {
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
			name:     "empty expression",
			expr:     "",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractCVEScopeFromCELExpression(tt.expr)
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
