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
	"fmt"
	"strings"
	"testing"

	"github.com/l3montree-dev/devguard/internal/core/vuln"
	"github.com/l3montree-dev/devguard/internal/core/vulndb/scan"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
)

func TestDependencyVulnToTableRow(t *testing.T) {
	t.Run("should print normally with 2 strings when providing a namespace", func(t *testing.T) {
		pURL := packageurl.PackageURL{}
		pURL.Type = "npm"
		pURL.Namespace = "Example Namespace"
		pURL.Name = "next"

		cveid := "Example CVEID"
		rawRiskAssessment := 42424.42
		componentFixedVersion := "Example Version"

		v := vuln.DependencyVulnDTO{}
		v.CVEID = &cveid
		v.CVE = &models.CVE{
			CVSS: 7.0,
		}

		v.RawRiskAssessment = &rawRiskAssessment
		v.ComponentFixedVersion = &componentFixedVersion
		v.State = models.VulnState("Example State")

		output := dependencyVulnToTableRow(pURL, v)
		firstValue := fmt.Sprintln(output[0])
		count := strings.Count(firstValue, "/")
		assert.Equal(t, 2, count, "should be equal")

	})
	t.Run("test with empty namespace should result in only 1 slash instead of a double slash", func(t *testing.T) {
		pURL := packageurl.PackageURL{}
		pURL.Type = "npm"
		pURL.Namespace = ""
		pURL.Name = "next"

		cveid := "Example CVEID"
		rawRiskAssessment := 42424.42
		componentFixedVersion := "Example Version"

		v := vuln.DependencyVulnDTO{}
		v.CVEID = &cveid
		v.CVE = &models.CVE{
			CVSS: 7.0,
		}
		v.RawRiskAssessment = &rawRiskAssessment
		v.ComponentFixedVersion = &componentFixedVersion
		v.State = models.VulnState("Example State")

		output := dependencyVulnToTableRow(pURL, v)
		firstValue := fmt.Sprintln(output[0])
		count := strings.Count(firstValue, "/")

		assert.Equal(t, 1, count, "should be equal")

	})

}

func TestPrintScaResults(t *testing.T) {
	assetName := "test-asset"
	webUI := "https://app.devguard.org"

	t.Run("should return nil when no vulnerabilities found", func(t *testing.T) {
		scanResponse := scan.ScanResponse{
			DependencyVulns: []vuln.DependencyVulnDTO{},
			AmountOpened:    0,
			AmountClosed:    0,
		}

		err := PrintScaResults(scanResponse, "critical", "critical", assetName, webUI)
		assert.Nil(t, err)
	})

	t.Run("should not fail when all vulnerabilities are closed/accepted - even with high risk/CVSS", func(t *testing.T) {
		scanResponse := scan.ScanResponse{
			DependencyVulns: []vuln.DependencyVulnDTO{
				{
					CVEID:             utils.Ptr("CVE-2023-12345"),
					ComponentPurl:     utils.Ptr("pkg:golang/github.com/example/lib@v1.0.0"),
					State:             "closed",       // CLOSED vulnerability should not cause failure
					RawRiskAssessment: utils.Ptr(9.5), // High risk but closed
					AssetVersionName:  "main",
					CVE: &models.CVE{
						CVE:  "CVE-2023-12345",
						CVSS: 9.0, // High CVSS but closed
					},
				},
				{
					CVEID:             utils.Ptr("CVE-2023-67890"),
					ComponentPurl:     utils.Ptr("pkg:golang/github.com/example/lib2@v1.0.0"),
					State:             "accepted",      // ACCEPTED vulnerability should not cause failure
					RawRiskAssessment: utils.Ptr(10.0), // High risk but accepted
					AssetVersionName:  "main",
					CVE: &models.CVE{
						CVE:  "CVE-2023-67890",
						CVSS: 9.8, // High CVSS but accepted
					},
				},
			},
			AmountOpened: 0,
			AmountClosed: 2,
		}

		// Should pass even with low thresholds because vulnerabilities are closed/accepted
		err := PrintScaResults(scanResponse, "low", "low", assetName, webUI)
		assert.Nil(t, err)
	})

	// Test failOnRisk conditions - consolidated table-driven test
	t.Run("failOnRisk thresholds", func(t *testing.T) {
		testCases := []struct {
			name          string
			risk          float64
			threshold     string
			shouldFail    bool
			expectedError string
		}{
			{"low threshold pass", 0.05, "low", false, ""},
			{"low threshold fail", 0.2, "low", true, "max risk exceeds threshold 0.20"},
			{"medium threshold pass", 3.9, "medium", false, ""},
			{"medium threshold fail", 4.5, "medium", true, "max risk exceeds threshold 4.50"},
			{"high threshold pass", 6.9, "high", false, ""},
			{"high threshold fail", 7.2, "high", true, "max risk exceeds threshold 7.20"},
			{"critical threshold pass", 8.9, "critical", false, ""},
			{"critical threshold fail", 9.5, "critical", true, "max risk exceeds threshold 9.50"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				scanResponse := scan.ScanResponse{
					DependencyVulns: []vuln.DependencyVulnDTO{
						{
							CVEID:             utils.Ptr("CVE-2023-12345"),
							ComponentPurl:     utils.Ptr("pkg:golang/github.com/example/lib@v1.0.0"),
							State:             "open",
							RawRiskAssessment: utils.Ptr(tc.risk),
							AssetVersionName:  "main",
							CVE: &models.CVE{
								CVE:  "CVE-2023-12345",
								CVSS: 5.0,
							},
						},
					},
					AmountOpened: 1,
					AmountClosed: 0,
				}

				err := PrintScaResults(scanResponse, tc.threshold, "critical", assetName, webUI)
				if tc.shouldFail {
					assert.NotNil(t, err)
					assert.Contains(t, err.Error(), tc.expectedError)
				} else {
					assert.Nil(t, err)
				}
			})
		}
	})

	// Test failOnCVSS conditions - consolidated table-driven test
	t.Run("failOnCVSS thresholds", func(t *testing.T) {
		testCases := []struct {
			name          string
			cvss          float32
			threshold     string
			shouldFail    bool
			expectedError string
		}{
			{"low threshold pass", 0.05, "low", false, ""},
			{"low threshold fail", 0.2, "low", true, "max CVSS exceeds threshold 0.20"},
			{"medium threshold pass", 3.9, "medium", false, ""},
			{"medium threshold fail", 4.5, "medium", true, "max CVSS exceeds threshold 4.50"},
			{"high threshold pass", 6.9, "high", false, ""},
			{"high threshold fail", 7.2, "high", true, "max CVSS exceeds threshold 7.20"},
			{"critical threshold pass", 8.9, "critical", false, ""},
			{"critical threshold fail", 9.5, "critical", true, "max CVSS exceeds threshold 9.50"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				scanResponse := scan.ScanResponse{
					DependencyVulns: []vuln.DependencyVulnDTO{
						{
							CVEID:             utils.Ptr("CVE-2023-12345"),
							ComponentPurl:     utils.Ptr("pkg:golang/github.com/example/lib@v1.0.0"),
							State:             "open",
							RawRiskAssessment: utils.Ptr(1.0),
							AssetVersionName:  "main",
							CVE: &models.CVE{
								CVE:  "CVE-2023-12345",
								CVSS: tc.cvss,
							},
						},
					},
					AmountOpened: 1,
					AmountClosed: 0,
				}

				err := PrintScaResults(scanResponse, "critical", tc.threshold, assetName, webUI)
				if tc.shouldFail {
					assert.NotNil(t, err)
					assert.Contains(t, err.Error(), tc.expectedError)
				} else {
					assert.Nil(t, err)
				}
			})
		}
	})

	// Test edge cases
	t.Run("should handle vulnerabilities without CVE (no CVSS)", func(t *testing.T) {
		scanResponse := scan.ScanResponse{
			DependencyVulns: []vuln.DependencyVulnDTO{
				{
					CVEID:             nil, // No CVE ID
					ComponentPurl:     utils.Ptr("pkg:golang/github.com/example/lib@v1.0.0"),
					State:             "open",
					RawRiskAssessment: utils.Ptr(5.0),
					AssetVersionName:  "main",
					CVE:               nil, // No CVE data - should default CVSS to 0.0
				},
			},
			AmountOpened: 1,
			AmountClosed: 0,
		}

		// Should fail on risk but pass on CVSS (defaults to 0.0)
		err := PrintScaResults(scanResponse, "medium", "critical", assetName, webUI)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "max risk exceeds threshold 5.00")
	})

	t.Run("should only consider OPEN vulnerabilities - mixed states scenario", func(t *testing.T) {
		scanResponse := scan.ScanResponse{
			DependencyVulns: []vuln.DependencyVulnDTO{
				{
					CVEID:             utils.Ptr("CVE-2023-12345"),
					ComponentPurl:     utils.Ptr("pkg:golang/github.com/example/lib1@v1.0.0"),
					State:             "open", // OPEN - should be considered
					RawRiskAssessment: utils.Ptr(3.0),
					AssetVersionName:  "main",
					CVE: &models.CVE{
						CVE:  "CVE-2023-12345",
						CVSS: 5.0,
					},
				},
				{
					CVEID:             utils.Ptr("CVE-2023-67890"),
					ComponentPurl:     utils.Ptr("pkg:golang/github.com/example/lib2@v2.0.0"),
					State:             "open",         // OPEN - should be considered (highest values)
					RawRiskAssessment: utils.Ptr(8.5), // Higher risk
					AssetVersionName:  "main",
					CVE: &models.CVE{
						CVE:  "CVE-2023-67890",
						CVSS: 7.8, // Higher CVSS
					},
				},
				{
					CVEID:             utils.Ptr("CVE-2023-11111"),
					ComponentPurl:     utils.Ptr("pkg:golang/github.com/example/lib3@v3.0.0"),
					State:             "closed",        // CLOSED - should be IGNORED even though it has highest values
					RawRiskAssessment: utils.Ptr(10.0), // Highest risk but closed
					AssetVersionName:  "main",
					CVE: &models.CVE{
						CVE:  "CVE-2023-11111",
						CVSS: 10.0, // Highest CVSS but closed
					},
				},
				{
					CVEID:             utils.Ptr("CVE-2023-22222"),
					ComponentPurl:     utils.Ptr("pkg:golang/github.com/example/lib4@v4.0.0"),
					State:             "accepted",     // ACCEPTED - should be IGNORED even though it has highest values
					RawRiskAssessment: utils.Ptr(9.8), // Very high risk but accepted
					AssetVersionName:  "main",
					CVE: &models.CVE{
						CVE:  "CVE-2023-22222",
						CVSS: 9.9, // Very high CVSS but accepted
					},
				},
			},
			AmountOpened: 2,
			AmountClosed: 2,
		}

		// Should fail on high risk threshold (8.5 >= 7) - only considering open vulns
		err := PrintScaResults(scanResponse, "high", "critical", assetName, webUI)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "max risk exceeds threshold 8.50")

		// Should fail on high CVSS threshold (7.8 >= 7) - only considering open vulns
		err = PrintScaResults(scanResponse, "critical", "high", assetName, webUI)
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "max CVSS exceeds threshold 7.80")
	})

	t.Run("should handle nil RawRiskAssessment gracefully", func(t *testing.T) {
		scanResponse := scan.ScanResponse{
			DependencyVulns: []vuln.DependencyVulnDTO{
				{
					CVEID:             utils.Ptr("CVE-2023-12345"),
					ComponentPurl:     utils.Ptr("pkg:golang/github.com/example/lib@v1.0.0"),
					State:             "open",
					RawRiskAssessment: nil, // Should default to 0
					AssetVersionName:  "main",
					CVE: &models.CVE{
						CVE:  "CVE-2023-12345",
						CVSS: 5.0,
					},
				},
			},
			AmountOpened: 1,
			AmountClosed: 0,
		}

		// Should pass all risk thresholds (defaults to 0)
		err := PrintScaResults(scanResponse, "low", "critical", assetName, webUI)
		assert.Nil(t, err)
	})

	t.Run("should handle unknown failOn values gracefully", func(t *testing.T) {
		scanResponse := scan.ScanResponse{
			DependencyVulns: []vuln.DependencyVulnDTO{
				{
					CVEID:             utils.Ptr("CVE-2023-12345"),
					ComponentPurl:     utils.Ptr("pkg:golang/github.com/example/lib@v1.0.0"),
					State:             "open",
					RawRiskAssessment: utils.Ptr(10.0),
					AssetVersionName:  "main",
					CVE: &models.CVE{
						CVE:  "CVE-2023-12345",
						CVSS: 10.0,
					},
				},
			},
			AmountOpened: 1,
			AmountClosed: 0,
		}

		// Unknown failOn values should not cause failures
		err := PrintScaResults(scanResponse, "unknown", "invalid", assetName, webUI)
		assert.Nil(t, err)
	})
}
