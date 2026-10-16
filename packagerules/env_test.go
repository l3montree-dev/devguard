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

package packagerules

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEval(t *testing.T) {
	tests := []struct {
		name string
		pkg  Package
		want bool
		rule string
	}{
		{name: "1 hour old", pkg: Package{
			Name: "express", ReleasedAt: time.Now().Add(-time.Hour),
		}, want: true, rule: `now() - timestamp(pkg.releasedAt) < duration("72h")`},
		{name: "5 days old", pkg: Package{
			Name: "express2", ReleasedAt: time.Now().Add(-time.Hour * 120),
		}, want: false, rule: `now() - timestamp(pkg.releasedAt) < duration("72h")`},
		{name: "evil scope", pkg: Package{
			Name: "@evil-scope/foo", Purl: "pkg:npm/%40evil-scope/foo@1.0.0",
		}, want: true, rule: `pkg.name.startsWith("@evil-scope/")`},
		{name: "good scope", pkg: Package{
			Name: "@good-scope/foo", Purl: "pkg:npm/%40good-scope/foo@1.0.0",
		}, want: false, rule: `pkg.name.startsWith("@evil-scope/")`},
		{name: "no provenance", pkg: Package{
			Name: "express",
		}, want: true, rule: `!has(pkg.provenance) || !pkg.provenance.sourceRepository.startsWith("github.com/expressjs/")`},
		{name: "provenance from expressjs", pkg: Package{
			Name: "express", Provenance: &Provenance{SourceRepository: "github.com/expressjs/express"},
		}, want: false, rule: `!has(pkg.provenance) || !pkg.provenance.sourceRepository.startsWith("github.com/expressjs/")`},
		{name: "provenance from other repo", pkg: Package{
			Name: "express", Provenance: &Provenance{SourceRepository: "github.com/evil/express"},
		}, want: true, rule: `!has(pkg.provenance) || !pkg.provenance.sourceRepository.startsWith("github.com/expressjs/")`},
		{name: "missing release time is skipped with has", pkg: Package{
			Name: "nginx", Ecosystem: "oci",
		}, want: false, rule: `has(pkg.releasedAt) && now() - timestamp(pkg.releasedAt) < duration("120h")`},
		{name: "missing release time is blocked without has", pkg: Package{
			Name: "lodash", Ecosystem: "npm",
		}, want: true, rule: `!has(pkg.releasedAt) || now() - timestamp(pkg.releasedAt) < duration("120h")`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prg, err := Compile(tt.rule)
			require.NoError(t, err)

			result, err := Eval(prg, tt.pkg)
			require.NoError(t, err)

			assert.Equal(t, tt.want, result)
		})
	}
}

func TestEvalMissingReleaseTimeErrors(t *testing.T) {
	prg, err := Compile(`now() - timestamp(pkg.releasedAt) < duration("120h")`)
	require.NoError(t, err)

	_, err = Eval(prg, Package{Name: "nginx"})
	assert.Error(t, err)
}
