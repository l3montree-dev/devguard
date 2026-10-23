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

package celrules

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseConfig(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantRules int
		wantErr   bool
	}{
		{
			name: "valid rules",
			input: `rules:
  - name: block-new
    action: deny
    expr: now() - timestamp(pkg.releasedAt) < duration("120h")
  - name: allow-trusted
    action: allow
    expr: pkg.name == "trusted"
`,
			wantRules: 2,
		},
		{
			name:      "empty config",
			input:     "",
			wantRules: 0,
		},
		{
			name: "invalid expression",
			input: `rules:
  - name: broken
    action: deny
    expr: pkg.name ==
`,
			wantErr: true,
		},
		{
			name: "invalid action",
			input: `rules:
  - name: broken
    action: foo
    expr: pkg.name == "x"
`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := ParsePackageRules(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Len(t, rules, tt.wantRules)
		})
	}
}
