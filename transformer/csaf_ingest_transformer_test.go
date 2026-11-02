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

package transformer

import (
	"encoding/json"
	"os"
	"testing"

	gocsaf "github.com/gocsaf/csaf/v3/csaf"
	"github.com/l3montree-dev/devguard/celrules"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCSAFtoVexRules(t *testing.T) {
	// read the csaf_vex.json from testdata
	data, err := os.ReadFile("testdata/csaf_vex.json")
	if err != nil {
		t.Fatalf("could not read testdata/csaf_vex.json: %v", err)
	}

	var advisory gocsaf.Advisory
	err = json.Unmarshal(data, &advisory)
	if err != nil {
		t.Fatalf("could not unmarshal testdata/csaf_vex.json: %v", err)
	}

	rules, err := CSAFVEXToRules(&advisory, "test")
	if err != nil {
		t.Fatalf("CSAFVEXToRules failed: %v", err)
	}

	// two distinct paths are marked known_not_affected in the testdata, so we expect one rule per path
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}

	gotExpressions := make([]string, 0, len(rules))
	for _, r := range rules {
		gotExpressions = append(gotExpressions, r.CELExpression)
	}

	expectedExpressions := []string{
		celrules.ToCELExpression("GHSA-fxhp-mv3v-67qp", celrules.PathPattern{
			"pkg:golang/github.com/l3montree-dev/devguard@main",
			"pkg:golang/oras.land/oras-go/v2@v2.6.1",
		}),
		celrules.ToCELExpression("GHSA-fxhp-mv3v-67qp", celrules.PathPattern{
			"pkg:golang/github.com/l3montree-dev/devguard@main",
			"pkg:golang/github.com/open-policy-agent/opa@v1.18.2",
			"pkg:golang/oras.land/oras-go/v2@v2.6.1",
		}),
	}
	assert.ElementsMatch(t, expectedExpressions, gotExpressions, "CEL expressions do not match expected")
}

func TestCSAFtoVexRulesWithProductsInBranches(t *testing.T) {
	// rancher/vexhub declares its products under product_tree.branches instead of full_product_names
	data, err := os.ReadFile("testdata/csaf_vex_branches.json")
	if err != nil {
		t.Fatalf("could not read testdata/csaf_vex_branches.json: %v", err)
	}

	var advisory gocsaf.Advisory
	err = json.Unmarshal(data, &advisory)
	if err != nil {
		t.Fatalf("could not unmarshal testdata/csaf_vex_branches.json: %v", err)
	}

	rules, err := CSAFVEXToRules(&advisory, "test")
	if err != nil {
		t.Fatalf("CSAFVEXToRules failed: %v", err)
	}

	require.NotEmpty(t, rules)
	assert.Contains(t, rules[0].CELExpression, "CVE-2025-22873")
	assert.Equal(t, celrules.ToCELExpression("CVE-2025-22873", celrules.PathPattern{
		"pkg:golang/datadog-lambda-extension/recorder-extension",
		"pkg:golang/stdlib@v1.22.7",
	}), rules[0].CELExpression)
}

func TestCSAFtoVexRulesJustifications(t *testing.T) {
	data, err := os.ReadFile("testdata/csaf_vex_branches.json")
	if err != nil {
		t.Fatalf("could not read testdata/csaf_vex_branches.json: %v", err)
	}

	var advisory gocsaf.Advisory
	err = json.Unmarshal(data, &advisory)
	if err != nil {
		t.Fatalf("could not unmarshal testdata/csaf_vex_branches.json: %v", err)
	}

	rules, err := CSAFVEXToRules(&advisory, "test")
	if err != nil {
		t.Fatalf("CSAFVEXToRules failed: %v", err)
	}
	require.NotEmpty(t, rules)

	// mechanical justification comes from the flag label, justification from the description note
	assert.Equal(t, dtos.VulnerableCodeNotInExecutePath, rules[0].MechanicalJustification)
	assert.Contains(t, rules[0].Justification, "Govulncheck determined that the vulnerable code isn't called")
	for _, r := range rules {
		assert.NotEmpty(t, r.MechanicalJustification, r.Title)
		assert.NotEmpty(t, r.Justification, r.Title)
	}
}

func TestCSAFtoVexRulesOneDescriptionNotePerProduct(t *testing.T) {
	// rancher/vexhub writes one description note per product, in the same order as known_not_affected
	doc := `{
	  "document": {"category": "csaf_vex", "csaf_version": "2.0", "title": "t", "publisher": {"category": "vendor", "name": "n", "namespace": "https://example.com"}, "tracking": {"id": "t", "status": "final", "version": "1", "current_release_date": "2026-01-01T00:00:00Z", "initial_release_date": "2026-01-01T00:00:00Z", "revision_history": [{"date": "2026-01-01T00:00:00Z", "number": "1", "summary": "s"}]}},
	  "product_tree": {
	    "branches": [
	      {"category": "product_name", "name": "a", "product": {"name": "a", "product_id": "app", "product_identification_helper": {"purl": "pkg:golang/app"}}},
	      {"category": "product_name", "name": "b", "product": {"name": "b", "product_id": "app-v3", "product_identification_helper": {"purl": "pkg:golang/app@v3.6.7"}}},
	      {"category": "product_name", "name": "c", "product": {"name": "c", "product_id": "stdlib", "product_identification_helper": {"purl": "pkg:golang/stdlib@v1.24.11"}}}
	    ],
	    "relationships": [
	      {"category": "default_component_of", "full_product_name": {"name": "x", "product_id": "stdlib-in-app"}, "product_reference": "stdlib", "relates_to_product_reference": "app"},
	      {"category": "default_component_of", "full_product_name": {"name": "y", "product_id": "stdlib-in-app-v3"}, "product_reference": "stdlib", "relates_to_product_reference": "app-v3"}
	    ]
	  },
	  "vulnerabilities": [{
	    "cve": "CVE-2025-61726",
	    "flags": [{"label": "vulnerable_code_not_in_execute_path", "product_ids": ["stdlib-in-app", "stdlib-in-app-v3"]}],
	    "notes": [
	      {"category": "description", "text": "concerns pkg:golang/app"},
	      {"category": "description", "text": "concerns pkg:golang/app@v3.6.7"}
	    ],
	    "product_status": {"known_not_affected": ["stdlib-in-app", "stdlib-in-app-v3"]}
	  }]
	}`

	var advisory gocsaf.Advisory
	require.NoError(t, json.Unmarshal([]byte(doc), &advisory))

	rules, err := CSAFVEXToRules(&advisory, "test")
	require.NoError(t, err)
	require.Len(t, rules, 2)

	assert.Equal(t, "concerns pkg:golang/app", rules[0].Justification)
	assert.Contains(t, rules[0].CELExpression, `"pkg:golang/app"`)
	assert.Equal(t, "concerns pkg:golang/app@v3.6.7", rules[1].Justification)
	assert.Contains(t, rules[1].CELExpression, "pkg:golang/app@v3.6.7")
	for _, r := range rules {
		assert.Equal(t, dtos.VulnerableCodeNotInExecutePath, r.MechanicalJustification)
	}
}
