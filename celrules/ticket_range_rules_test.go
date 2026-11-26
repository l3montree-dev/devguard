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

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompileTicketRangeRule(t *testing.T) {
	_, err := CompileTicketRangeRule(`vuln.cve.cvss >= 8`)
	require.NoError(t, err)

	_, err = CompileTicketRangeRule(`vuln.cve.cvss >=`)
	assert.Error(t, err)
}

func TestEvalTicketRangeRule(t *testing.T) {
	const migrated = `ref.defaultBranch == true && ((vuln.cve != null && vuln.cve.cvss >= 8) || (vuln.riskAssessment != null && vuln.riskAssessment >= 7.5))`
	risk := 7.6
	mainBranch := models.AssetVersion{Name: "main", Type: models.AssetVersionBranch, DefaultBranch: true}
	featureBranch := models.AssetVersion{Name: "feature", Type: models.AssetVersionBranch}

	cases := []struct {
		name         string
		expr         string
		vuln         models.DependencyVuln
		assetVersion models.AssetVersion
		expected     bool
		expectErr    bool
	}{
		{"cvss above threshold", migrated, models.DependencyVuln{CVE: &models.CVE{CVSS: 9}}, mainBranch, true, false},
		{"cvss below threshold", migrated, models.DependencyVuln{CVE: &models.CVE{CVSS: 5}}, mainBranch, false, false},
		{"risk above threshold without cve", migrated, models.DependencyVuln{RiskAssessment: &risk}, mainBranch, true, false},
		{"neither cve nor risk", migrated, models.DependencyVuln{}, mainBranch, false, false},
		{"not the default branch", migrated, models.DependencyVuln{CVE: &models.CVE{CVSS: 9}}, featureBranch, false, false},
		{"tag", `ref.type == "tag"`, models.DependencyVuln{}, models.AssetVersion{Type: models.AssetVersionTag}, true, false},
		{"missing cve without null guard", `vuln.cve.cvss >= 8`, models.DependencyVuln{}, mainBranch, false, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result, err := EvalTicketRangeRule(c.expr, c.vuln, NewRefs([]models.AssetVersion{c.assetVersion}))
			if c.expectErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, c.expected, result)
		})
	}
}
