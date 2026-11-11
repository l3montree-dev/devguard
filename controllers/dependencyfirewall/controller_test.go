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

package dependencyfirewall

import (
	"testing"
	"time"

	"github.com/l3montree-dev/devguard/celrules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckNotAllowedPackage(t *testing.T) {
	d := &DependencyProxyController{}

	configs, err := parseDependencyProxyConfigs(`rules:
  - name: block-new
    action: deny
    expr: now() - timestamp(pkg.releasedAt) < duration("120h")
  - name: allow-trusted
    action: allow
    expr: pkg.name == "trusted"
`)
	require.NoError(t, err)

	tests := []struct {
		name        string
		pkg         celrules.Package
		wantBlocked bool
		wantReason  string
	}{
		{
			name:        "blocks new package",
			pkg:         celrules.Package{Name: "lodash", ReleasedAt: time.Now().Add(-time.Hour)},
			wantBlocked: true,
			wantReason:  "block-new",
		},
		{
			name:        "allows old package",
			pkg:         celrules.Package{Name: "lodash", ReleasedAt: time.Now().Add(-30 * 24 * time.Hour)},
			wantBlocked: false,
		},
		{
			name:        "allow rule overrides deny",
			pkg:         celrules.Package{Name: "trusted", ReleasedAt: time.Now().Add(-time.Hour)},
			wantBlocked: false,
		},
		{
			name:        "fails closed on evaluation error",
			pkg:         celrules.Package{Name: "lodash"},
			wantBlocked: true,
			wantReason:  "block-new",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocked, reason := d.CheckNotAllowedPackage(tt.pkg, configs)
			assert.Equal(t, tt.wantBlocked, blocked)
			if tt.wantReason == "" {
				assert.Empty(t, reason)
				return
			}
			assert.Contains(t, reason, tt.wantReason)
		})
	}
}

func TestCheckNotAllowedPackageWithoutRules(t *testing.T) {
	d := &DependencyProxyController{}
	blocked, reason := d.CheckNotAllowedPackage(celrules.Package{Name: "lodash"}, DependencyProxyConfigs{})
	assert.False(t, blocked)
	assert.Empty(t, reason)
}
