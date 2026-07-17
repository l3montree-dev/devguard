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

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
)

func vuln(id string, state cdx.ImpactAnalysisState, refs ...string) cdx.Vulnerability {
	v := cdx.Vulnerability{ID: id}
	if len(refs) > 0 {
		affects := make([]cdx.Affects, 0, len(refs))
		for _, r := range refs {
			affects = append(affects, cdx.Affects{Ref: r})
		}
		v.Affects = &affects
	}
	if state != "" {
		v.Analysis = &cdx.VulnerabilityAnalysis{State: state}
	}
	return v
}

func TestDedupVexVulnerabilities(t *testing.T) {
	t.Run("empty input returns empty", func(t *testing.T) {
		assert.Empty(t, dedupVexVulnerabilities(nil))
	})

	t.Run("unique vulnerabilities are all kept", func(t *testing.T) {
		got := dedupVexVulnerabilities([]cdx.Vulnerability{
			vuln("CVE-1", "", "pkg:npm/a@1"),
			vuln("CVE-2", "", "pkg:npm/b@1"),
			vuln("CVE-3", "", "pkg:npm/c@1"),
		})
		assert.Len(t, got, 3)
	})

	t.Run("same CVE with different affects is NOT deduplicated (affects is part of the key)", func(t *testing.T) {
		got := dedupVexVulnerabilities([]cdx.Vulnerability{
			vuln("CVE-1", "", "pkg:npm/lodash@4.17.20"),
			vuln("CVE-1", "", "pkg:npm/lodash@4.17.21"),
		})
		assert.Len(t, got, 2)
	})

	t.Run("same CVE + same affects is deduplicated, higher state priority wins", func(t *testing.T) {
		// in_triage first, then exploitable -> exploitable wins
		got := dedupVexVulnerabilities([]cdx.Vulnerability{
			vuln("CVE-1", cdx.IASInTriage, "pkg:npm/lodash@4.17.20"),
			vuln("CVE-1", cdx.IASExploitable, "pkg:npm/lodash@4.17.20"),
		})
		assert.Len(t, got, 1)
		assert.Equal(t, cdx.IASExploitable, got[0].Analysis.State)
	})

	t.Run("a lower-priority state does not replace an existing higher-priority one", func(t *testing.T) {
		// exploitable first, then in_triage -> exploitable stays
		got := dedupVexVulnerabilities([]cdx.Vulnerability{
			vuln("CVE-1", cdx.IASExploitable, "pkg:npm/lodash@4.17.20"),
			vuln("CVE-1", cdx.IASInTriage, "pkg:npm/lodash@4.17.20"),
		})
		assert.Len(t, got, 1)
		assert.Equal(t, cdx.IASExploitable, got[0].Analysis.State)
	})

	t.Run("first-seen order is preserved", func(t *testing.T) {
		got := dedupVexVulnerabilities([]cdx.Vulnerability{
			vuln("CVE-3", "", "pkg:npm/c@1"),
			vuln("CVE-1", "", "pkg:npm/a@1"),
			vuln("CVE-2", "", "pkg:npm/b@1"),
		})
		assert.Equal(t, []string{"CVE-3", "CVE-1", "CVE-2"}, []string{got[0].ID, got[1].ID, got[2].ID})
	})
}
