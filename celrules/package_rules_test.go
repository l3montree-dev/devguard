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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRules(t *testing.T) {
	tests := []struct {
		name        string
		rules       []PackageRule
		pkg         Package
		wantBlocked bool
		wantRule    string
	}{
		{
			name: "no rule fits",
			rules: []PackageRule{
				{Name: "deny package X", Action: ActionDeny, Expr: `pkg.name == "X"`},
			},
			pkg: Package{
				Name: "foo",
			},
			wantBlocked: false,
			wantRule:    "",
		},
		{
			name: "deny fits",
			rules: []PackageRule{
				{Name: "deny < 7 days", Action: ActionDeny, Expr: `now() - timestamp(pkg.releasedAt) < duration("168h")`},
			},
			pkg: Package{
				Name:       "foo",
				ReleasedAt: time.Now().Add(-time.Hour),
			},
			wantBlocked: true,
			wantRule:    "deny < 7 days",
		},
		{
			name: "allow after deny",
			rules: []PackageRule{
				{Name: "deny < 7 days", Action: ActionDeny, Expr: `now() - timestamp(pkg.releasedAt) < duration("168h")`},
				{Name: "allow pkg trusted", Action: ActionAllow, Expr: `pkg.name == "trusted"`},
			},
			pkg: Package{
				Name:       "trusted",
				ReleasedAt: time.Now().Add(-time.Hour),
			},
			wantBlocked: false,
			wantRule:    "allow pkg trusted",
		},
		{
			name: "deny after allow",
			rules: []PackageRule{
				{Name: "allow pkg trusted", Action: ActionAllow, Expr: `pkg.name == "trusted"`},
				{Name: "deny < 7 days", Action: ActionDeny, Expr: `now() - timestamp(pkg.releasedAt) < duration("168h")`},
			},
			pkg: Package{
				Name:       "trusted",
				ReleasedAt: time.Now().Add(-time.Hour),
			},
			wantBlocked: true,
			wantRule:    "deny < 7 days",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compiledRules, err := CompilePackageRules(tt.rules)
			require.NoError(t, err)

			blocked, ruleName, err := EvaluatePackage(compiledRules, tt.pkg)
			require.NoError(t, err)

			assert.Equal(t, tt.wantBlocked, blocked)
			assert.Equal(t, tt.wantRule, ruleName)
		})
	}
}

func TestCompileRulesInvalidAction(t *testing.T) {
	_, err := CompilePackageRules([]PackageRule{
		{Name: "action is foo", Action: "foo", Expr: `pkg.name == "x"`},
	})
	assert.Error(t, err)
}

func TestCompileRulesNonBoolExpression(t *testing.T) {
	_, err := CompilePackageRules([]PackageRule{
		{Name: "returns int", Action: ActionDeny, Expr: `pkg.name.size()`},
	})
	assert.Error(t, err)

	_, err = CompilePackageRules([]PackageRule{
		{Name: "returns dyn", Action: ActionDeny, Expr: `pkg.trusted`},
	})
	assert.NoError(t, err)
}
