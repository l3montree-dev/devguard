// Copyright 2024 Tim Bastin, l3montree GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package scanner

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/l3montree-dev/devguard/dtos/sarif"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/stretchr/testify/assert"
)

func TestPrintCycloneDXVexResults(t *testing.T) {
	assetName := "test-asset"
	webUI := "https://app.devguard.org"

	t.Run("should return nil when no vulnerabilities found", func(t *testing.T) {
		bom := cdx.BOM{}
		err := PrintCycloneDXVexResults(bom, "critical", "critical", assetName, webUI)
		assert.Nil(t, err)
	})

	t.Run("should return nil when vulnerabilities slice is empty", func(t *testing.T) {
		vulns := []cdx.Vulnerability{}
		bom := cdx.BOM{Vulnerabilities: &vulns}
		err := PrintCycloneDXVexResults(bom, "critical", "critical", assetName, webUI)
		assert.Nil(t, err)
	})

	t.Run("should not fail when all vulnerabilities are suppressed", func(t *testing.T) {
		score := 9.5
		vulns := []cdx.Vulnerability{
			{
				ID: "CVE-2023-12345",
				Ratings: &[]cdx.VulnerabilityRating{
					{Score: &score, Method: cdx.ScoringMethodCVSSv31},
				},
				Analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASFalsePositive},
			},
		}
		bom := cdx.BOM{Vulnerabilities: &vulns}
		err := PrintCycloneDXVexResults(bom, "low", "low", assetName, webUI)
		assert.Nil(t, err)
	})

	t.Run("failOnRisk thresholds", func(t *testing.T) {
		testCases := []struct {
			name       string
			risk       float64
			threshold  string
			shouldFail bool
		}{
			{"low threshold pass", 0.05, "low", false},
			{"low threshold fail", 0.2, "low", true},
			{"medium threshold pass", 3.9, "medium", false},
			{"medium threshold fail", 4.5, "medium", true},
			{"high threshold pass", 6.9, "high", false},
			{"high threshold fail", 7.2, "high", true},
			{"critical threshold pass", 8.9, "critical", false},
			{"critical threshold fail", 9.5, "critical", true},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				vulns := []cdx.Vulnerability{
					{
						ID: "CVE-2023-12345",
						Ratings: &[]cdx.VulnerabilityRating{
							{Score: &tc.risk},
						},
					},
				}
				bom := cdx.BOM{Vulnerabilities: &vulns}
				err := PrintCycloneDXVexResults(bom, tc.threshold, "critical", assetName, webUI)
				if tc.shouldFail {
					assert.NotNil(t, err)
					assert.Contains(t, err.Error(), "exceed the configured risk threshold")
				} else {
					assert.Nil(t, err)
				}
			})
		}
	})

	t.Run("failOnCVSS thresholds", func(t *testing.T) {
		testCases := []struct {
			name       string
			cvss       float64
			threshold  string
			shouldFail bool
		}{
			{"low threshold pass", 0.05, "low", false},
			{"low threshold fail", 0.2, "low", true},
			{"medium threshold pass", 3.9, "medium", false},
			{"medium threshold fail", 4.5, "medium", true},
			{"high threshold pass", 6.9, "high", false},
			{"high threshold fail", 7.2, "high", true},
			{"critical threshold pass", 8.9, "critical", false},
			{"critical threshold fail", 9.5, "critical", true},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				vulns := []cdx.Vulnerability{
					{
						ID: "CVE-2023-12345",
						Ratings: &[]cdx.VulnerabilityRating{
							{Score: &tc.cvss, Method: cdx.ScoringMethodCVSSv31},
						},
					},
				}
				bom := cdx.BOM{Vulnerabilities: &vulns}
				err := PrintCycloneDXVexResults(bom, "critical", tc.threshold, assetName, webUI)
				if tc.shouldFail {
					assert.NotNil(t, err)
					assert.Contains(t, err.Error(), "exceed the configured risk threshold")
				} else {
					assert.Nil(t, err)
				}
			})
		}
	})

	t.Run("should resolve library name from component purl via affects", func(t *testing.T) {
		score := 5.0
		vulns := []cdx.Vulnerability{
			{
				ID: "CVE-2023-99999",
				Ratings: &[]cdx.VulnerabilityRating{
					{Score: &score},
				},
				Affects: &[]cdx.Affects{{Ref: "comp-1"}},
			},
		}
		comps := []cdx.Component{
			{BOMRef: "comp-1", PackageURL: "pkg:golang/github.com/example/lib@v1.2.3"},
		}
		bom := cdx.BOM{Vulnerabilities: &vulns, Components: &comps}
		err := PrintCycloneDXVexResults(bom, "critical", "critical", assetName, webUI)
		assert.Nil(t, err)
	})

	t.Run("unknown failOn values should not cause failures", func(t *testing.T) {
		score := 10.0
		vulns := []cdx.Vulnerability{
			{
				ID:      "CVE-2023-12345",
				Ratings: &[]cdx.VulnerabilityRating{{Score: &score, Method: cdx.ScoringMethodCVSSv31}},
			},
		}
		bom := cdx.BOM{Vulnerabilities: &vulns}
		err := PrintCycloneDXVexResults(bom, "unknown", "invalid", assetName, webUI)
		assert.Nil(t, err)
	})
}

func TestPrintSarifResults(t *testing.T) {
	assetName := "test-asset"
	webUI := "https://app.devguard.org"
	ref := "main"

	ruleID := "rule-001"
	uri := "src/main.go"
	snippet := "password := \"secret\""

	t.Run("should return nil when no runs", func(t *testing.T) {
		report := sarif.SarifSchema210Json{Version: "2.1.0"}
		err := PrintSarifResults(report, "sast", assetName, webUI, ref)
		assert.Nil(t, err)
	})

	t.Run("should return nil when all results are suppressed", func(t *testing.T) {
		justification := "accepted"
		report := sarif.SarifSchema210Json{
			Version: "2.1.0",
			Runs: []sarif.Run{{
				Results: []sarif.Result{
					{
						RuleID:  &ruleID,
						Message: sarif.Message{Text: "test finding"},
						Suppressions: []sarif.Suppression{{
							Kind:          sarif.SuppressionKind("inSource"),
							Justification: &justification,
						}},
					},
				},
			}},
		}
		err := PrintSarifResults(report, "sast", assetName, webUI, ref)
		assert.Nil(t, err)
	})

	t.Run("should return error when open vulnerabilities exist", func(t *testing.T) {
		report := sarif.SarifSchema210Json{
			Version: "2.1.0",
			Runs: []sarif.Run{{
				Results: []sarif.Result{
					{
						RuleID:  &ruleID,
						Message: sarif.Message{Text: "open finding"},
						Locations: []sarif.Location{{
							PhysicalLocation: sarif.PhysicalLocation{
								ArtifactLocation: sarif.ArtifactLocation{URI: &uri},
								Region: &sarif.Region{
									Snippet: &sarif.ArtifactContent{Text: &snippet},
								},
							},
						}},
					},
				},
			}},
		}
		err := PrintSarifResults(report, "sast", assetName, webUI, ref)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "1 unhandled vulnerabilities")
	})

	t.Run("should count only open results across mixed states", func(t *testing.T) {
		justification := "accepted"
		report := sarif.SarifSchema210Json{
			Version: "2.1.0",
			Runs: []sarif.Run{{
				Results: []sarif.Result{
					{
						RuleID:  &ruleID,
						Message: sarif.Message{Text: "open finding"},
					},
					{
						RuleID:  utils.Ptr("rule-002"),
						Message: sarif.Message{Text: "suppressed finding"},
						Suppressions: []sarif.Suppression{{
							Kind:          sarif.SuppressionKind("inSource"),
							Justification: &justification,
						}},
					},
				},
			}},
		}
		err := PrintSarifResults(report, "sast", assetName, webUI, ref)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "1 unhandled vulnerabilities")
	})
}
