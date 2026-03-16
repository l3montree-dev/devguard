// Copyright (C) 2025 l3montree GmbH
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

package scanner

import (
	"testing"

	"github.com/l3montree-dev/devguard/compliance"
	"github.com/l3montree-dev/devguard/dtos/sarif"
	"github.com/l3montree-dev/devguard/utils"
)

func resultKey(r sarif.Result) string {
	kind := string(r.Kind)
	return kind + "|" + r.Message.Text
}

func hasDuplicateResults(results []sarif.Result) bool {
	seen := make(map[string]bool, len(results))
	for _, r := range results {
		k := resultKey(r)
		if seen[k] {
			return true
		}
		seen[k] = true
	}
	return false
}

func TestBuildSarifFromPolicy_NoDuplicateResults(t *testing.T) {
	policy := compliance.PolicyFS{
		PolicyMetadata: compliance.PolicyMetadata{
			Filename:    "test-policy.rego",
			Title:       "Test Policy",
			Description: "A test policy",
			Tags:        []string{"test"},
		},
	}

	t.Run("duplicate violations across evaluations produce no duplicates", func(t *testing.T) {
		compliant := false
		evaluations := []compliance.PolicyEvaluation{
			{Compliant: &compliant, Violations: []string{"missing signature", "untrusted source"}},
			{Compliant: &compliant, Violations: []string{"missing signature", "untrusted source"}}, // same violations again
		}

		result := buildSarifFromPolicy("registry.example.com/image:latest", policy, evaluations)
		results := result.Runs[0].Results

		if hasDuplicateResults(results) {
			t.Errorf("buildSarifFromPolicy returned duplicate result entries: %v", results)
		}
	})

	t.Run("same violation repeated within one evaluation produces no duplicates", func(t *testing.T) {
		compliant := false
		evaluations := []compliance.PolicyEvaluation{
			{Compliant: &compliant, Violations: []string{"missing signature", "missing signature"}},
		}

		result := buildSarifFromPolicy("registry.example.com/image:latest", policy, evaluations)
		results := result.Runs[0].Results

		if hasDuplicateResults(results) {
			t.Errorf("buildSarifFromPolicy returned duplicate result entries: %v", results)
		}
	})

	t.Run("multiple compliant evaluations produce no duplicate pass results", func(t *testing.T) {
		compliant := true
		evaluations := []compliance.PolicyEvaluation{
			{Compliant: &compliant, Violations: nil},
			{Compliant: &compliant, Violations: nil},
			{Compliant: &compliant, Violations: nil},
		}

		result := buildSarifFromPolicy("registry.example.com/image:latest", policy, evaluations)
		results := result.Runs[0].Results

		if hasDuplicateResults(results) {
			t.Errorf("buildSarifFromPolicy returned duplicate pass result entries: %v", results)
		}
	})

	t.Run("mix of compliant and non-compliant evaluations with overlapping violations", func(t *testing.T) {
		compliant := true
		notCompliant := false
		evaluations := []compliance.PolicyEvaluation{
			{Compliant: &compliant, Violations: nil},
			{Compliant: &notCompliant, Violations: []string{"missing signature"}},
			{Compliant: &notCompliant, Violations: []string{"missing signature"}},
			{Compliant: &compliant, Violations: nil},
		}

		result := buildSarifFromPolicy("registry.example.com/image:latest", policy, evaluations)
		results := result.Runs[0].Results

		if hasDuplicateResults(results) {
			t.Errorf("buildSarifFromPolicy returned duplicate result entries: %v", results)
		}
	})

	t.Run("single evaluation with no violations produces no results", func(t *testing.T) {
		evaluations := []compliance.PolicyEvaluation{
			{Compliant: utils.Ptr(true), Violations: nil},
		}

		result := buildSarifFromPolicy("registry.example.com/image:latest", policy, evaluations)
		results := result.Runs[0].Results

		if hasDuplicateResults(results) {
			t.Errorf("buildSarifFromPolicy returned duplicate result entries: %v", results)
		}
	})
}
