// Copyright (C) 2024 Tim Bastin, l3montree GmbH
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

package vulndb

import (
	"fmt"
	"math"
	"testing"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/stretchr/testify/assert"
)

type tableTest struct {
	vector             string
	metrics            dtos.RiskMetrics
	env                shared.Environmental
	exploits           []models.Exploit
	expectedVector     string
	cvss               float32
	affectedComponents []models.AffectedComponent
}

func ptr[T any](s T) *T {
	return &s
}

func TestCalculateRawRisk(t *testing.T) {
	t.Run("should never divide by zero - instead divide by 1", func(t *testing.T) {
		sut := models.CVE{
			CVSS:   5,
			Vector: "AV:L/AC:H/Au:M/C:C/I:C/A:C",
		}
		env := shared.Environmental{
			ConfidentialityRequirements: "L",
			IntegrityRequirements:       "L",
			AvailabilityRequirements:    "L",
		}
		affectedComponentDepth := 0
		riskReport := RawRisk(sut, env, affectedComponentDepth)

		if riskReport.Risk != 1.7 {
			t.Errorf("Expected risk to be 1.7, got %f", riskReport.Risk)
		}
	})
}
func TestCalculateRisk(t *testing.T) {

	t.Run("should not panic if no vector is defined", func(t *testing.T) {
		sut := models.CVE{
			CVSS:   5,
			Vector: "",
		}
		env := shared.Environmental{}
		riskMetrics, vector := RiskCalculation(sut, env)

		if riskMetrics.BaseScore != 0 {
			t.Errorf("Expected base score to be 5, got %f", riskMetrics.BaseScore)
		}

		if riskMetrics.WithEnvironment != dtos.CannotCalculateRisk {
			t.Errorf("Expected with environment score to be %f, got %f", dtos.CannotCalculateRisk, riskMetrics.WithEnvironment)
		}

		if riskMetrics.WithThreatIntelligence != dtos.CannotCalculateRisk {
			t.Errorf("Expected with threat intelligence score to be %f, got %f", dtos.CannotCalculateRisk, riskMetrics.WithThreatIntelligence)
		}

		if riskMetrics.WithEnvironmentAndThreatIntelligence != dtos.CannotCalculateRisk {
			t.Errorf("Expected with environment and threat intelligence score to be %f, got %f", dtos.CannotCalculateRisk, riskMetrics.WithEnvironmentAndThreatIntelligence)
		}

		if vector != "" {
			t.Errorf("Expected vector to be empty, got %s", vector)
		}
	})

	table := []tableTest{
		{
			vector: "AV:L/AC:H/Au:M/C:C/I:C/A:C",
			metrics: dtos.RiskMetrics{
				BaseScore:                            5.9,
				WithEnvironment:                      5.9,
				WithThreatIntelligence:               5.0,
				WithEnvironmentAndThreatIntelligence: 5.0,
			},
			env:            shared.Environmental{},
			expectedVector: "AV:L/AC:H/Au:M/C:C/I:C/A:C/E:U/RL:ND/RC:C",
			cvss:           5.9,
		},
		{
			vector: "AV:L/AC:H/Au:M/C:C/I:C/A:C",
			metrics: dtos.RiskMetrics{
				BaseScore:                            5.9,
				WithEnvironment:                      4.0,
				WithThreatIntelligence:               5.0,
				WithEnvironmentAndThreatIntelligence: 3.4,
			},
			env: shared.Environmental{
				ConfidentialityRequirements: "L",
				IntegrityRequirements:       "L",
				AvailabilityRequirements:    "L",
			},
			expectedVector: "AV:L/AC:H/Au:M/C:C/I:C/A:C/E:U/RL:ND/RC:C/CDP:ND/TD:ND/CR:L/IR:L/AR:L",
			cvss:           5.9,
		},
		{
			vector: "AV:L/AC:H/Au:M/C:C/I:C/A:C",
			metrics: dtos.RiskMetrics{
				BaseScore:                            5.9,
				WithEnvironment:                      4.0,
				WithThreatIntelligence:               5.6,
				WithEnvironmentAndThreatIntelligence: 3.8,
			},
			env: shared.Environmental{
				ConfidentialityRequirements: "L",
				IntegrityRequirements:       "L",
				AvailabilityRequirements:    "L",
			},
			exploits: []models.Exploit{
				{
					Verified: true,
				},
			},
			expectedVector: "AV:L/AC:H/Au:M/C:C/I:C/A:C/E:F/RL:ND/RC:C/CDP:ND/TD:ND/CR:L/IR:L/AR:L",
			cvss:           5.9,
		},
		{
			vector: "AV:L/AC:H/Au:M/C:C/I:C/A:C",
			metrics: dtos.RiskMetrics{
				BaseScore:                            5.9,
				WithEnvironment:                      4.0,
				WithThreatIntelligence:               5.6,
				WithEnvironmentAndThreatIntelligence: 3.8,
			},
			env: shared.Environmental{
				ConfidentialityRequirements: "L",
				IntegrityRequirements:       "L",
				AvailabilityRequirements:    "L",
			},
			exploits: []models.Exploit{
				{
					Verified: true,
				},
			},
			expectedVector: "AV:L/AC:H/Au:M/C:C/I:C/A:C/E:F/RL:ND/RC:C/CDP:ND/TD:ND/CR:L/IR:L/AR:L",
			cvss:           5.9,
			affectedComponents: []models.AffectedComponent{{
				SemverFixed: ptr("v1.0.0"), // this should not matter. Reducing the score, since a fix is available, makes no sense in this application. Actually we want those cves to be handled first, since they are easy to handle.
			}},
		},
		{
			vector: "AV:L/AC:H/Au:M/C:C/I:C/A:C",
			metrics: dtos.RiskMetrics{
				BaseScore:                            5.9,
				WithEnvironment:                      4.0,
				WithThreatIntelligence:               5.6,
				WithEnvironmentAndThreatIntelligence: 3.8,
			},
			env: shared.Environmental{
				ConfidentialityRequirements: "L",
				IntegrityRequirements:       "L",
				AvailabilityRequirements:    "L",
			},
			exploits: []models.Exploit{
				{
					Verified: true,
				},
			},
			expectedVector: "AV:L/AC:H/Au:M/C:C/I:C/A:C/E:F/RL:ND/RC:C/CDP:ND/TD:ND/CR:L/IR:L/AR:L",
			cvss:           5.9,
			affectedComponents: []models.AffectedComponent{{
				SemverFixed: nil,
			}},
		},
		{
			vector: "CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:U/C:N/I:N/A:L",
			metrics: dtos.RiskMetrics{
				BaseScore:                            2.6,
				WithEnvironment:                      2.6,
				WithThreatIntelligence:               2.4,
				WithEnvironmentAndThreatIntelligence: 2.4,
			},
			env:            shared.Environmental{},
			expectedVector: "CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:U/C:N/I:N/A:L/E:U/RC:C",
			cvss:           2.6,
		},
		{
			vector: "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:N/I:N/A:L",
			metrics: dtos.RiskMetrics{
				BaseScore:                            2.6,
				WithEnvironment:                      1.9,
				WithThreatIntelligence:               2.4,
				WithEnvironmentAndThreatIntelligence: 1.8,
			},
			env: shared.Environmental{
				IntegrityRequirements:       "L",
				ConfidentialityRequirements: "L",
				AvailabilityRequirements:    "L",
			},
			expectedVector: "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:N/I:N/A:L/E:U/RC:C/CR:L/IR:L/AR:L",
			cvss:           2.6,
		},
		{
			vector: "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:N/I:N/A:L",
			metrics: dtos.RiskMetrics{
				BaseScore:                            2.6,
				WithEnvironment:                      3.4,
				WithThreatIntelligence:               2.6,
				WithEnvironmentAndThreatIntelligence: 3.3,
			},
			env: shared.Environmental{
				IntegrityRequirements:       "H",
				ConfidentialityRequirements: "H",
				AvailabilityRequirements:    "H",
			},
			exploits: []models.Exploit{
				{
					Verified: true,
				},
			},
			affectedComponents: []models.AffectedComponent{{
				SemverFixed: ptr("v1.0.0"),
			}},
			expectedVector: "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:N/I:N/A:L/E:F/RC:C/CR:H/IR:H/AR:H",
			cvss:           2.6,
		},
		{
			vector: "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:N/I:N/A:L",
			metrics: dtos.RiskMetrics{
				BaseScore:                            2.6,
				WithEnvironment:                      3.4,
				WithThreatIntelligence:               2.6,
				WithEnvironmentAndThreatIntelligence: 3.3,
			},
			env: shared.Environmental{
				IntegrityRequirements:       "H",
				ConfidentialityRequirements: "H",
				AvailabilityRequirements:    "H",
			},
			exploits: []models.Exploit{
				{
					Verified: true,
				},
			},
			affectedComponents: []models.AffectedComponent{{
				SemverFixed: nil,
			}},
			expectedVector: "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:N/I:N/A:L/E:F/RC:C/CR:H/IR:H/AR:H",
			cvss:           2.6,
		},
		{
			vector: "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
			metrics: dtos.RiskMetrics{
				BaseScore:                            7.5,
				WithEnvironment:                      6.2,
				WithThreatIntelligence:               4.8,
				WithEnvironmentAndThreatIntelligence: 2.4,
			},
			env: shared.Environmental{
				IntegrityRequirements:       "L",
				ConfidentialityRequirements: "L",
				AvailabilityRequirements:    "L",
			},
			cvss:           7.5,
			expectedVector: "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U/CR:L/IR:L/AR:L",
		},
		{
			vector: "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
			metrics: dtos.RiskMetrics{
				BaseScore:                            7.5,
				WithEnvironment:                      6.2,
				WithThreatIntelligence:               6.6,
				WithEnvironmentAndThreatIntelligence: 5.1,
			},
			env: shared.Environmental{
				IntegrityRequirements:       "L",
				ConfidentialityRequirements: "L",
				AvailabilityRequirements:    "L",
			},
			exploits:       []models.Exploit{{Verified: true}},
			cvss:           7.5,
			expectedVector: "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P/CR:L/IR:L/AR:L",
		},
		{
			vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
			metrics: dtos.RiskMetrics{
				BaseScore:                            6.1,
				WithEnvironment:                      6.8,
				WithThreatIntelligence:               6.0,
				WithEnvironmentAndThreatIntelligence: 6.6,
			},
			env: shared.Environmental{
				IntegrityRequirements:       "M",
				ConfidentialityRequirements: "H",
				AvailabilityRequirements:    "M",
			},
			expectedVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N/E:F/RC:C/CR:H/IR:M/AR:M",
			cvss:           6.1,
			exploits:       []models.Exploit{{Verified: true}},
		},
	}

	for _, tableTest := range table {
		vector := tableTest.vector
		t.Run("should return same values, if no env metrics and threat metrics are defined. Vector: "+vector, func(t *testing.T) {
			sut := models.CVE{
				CVSS:               tableTest.cvss,
				Vector:             vector,
				Exploits:           tableTest.exploits,
				AffectedComponents: tableTest.affectedComponents,
			}
			env := tableTest.env
			expectedRiskMetrics := tableTest.metrics
			riskMetrics, vector := RiskCalculation(sut, env)

			if !floatsEqual(riskMetrics.BaseScore, expectedRiskMetrics.BaseScore) {
				t.Errorf("Expected base score to be %f, got %f", expectedRiskMetrics.BaseScore, riskMetrics.BaseScore)
			}

			if !floatsEqual(riskMetrics.WithEnvironment, expectedRiskMetrics.WithEnvironment) {
				t.Errorf("Expected with environment score to be %f, got %f", expectedRiskMetrics.WithEnvironment, riskMetrics.WithEnvironment)
			}

			if !floatsEqual(riskMetrics.WithThreatIntelligence, expectedRiskMetrics.WithThreatIntelligence) {
				t.Errorf("Expected with threat intelligence score to be %f, got %f", expectedRiskMetrics.WithThreatIntelligence, riskMetrics.WithThreatIntelligence)
			}

			if !floatsEqual(riskMetrics.WithEnvironmentAndThreatIntelligence, expectedRiskMetrics.WithEnvironmentAndThreatIntelligence) {
				t.Errorf("Expected with environment and threat intelligence score to be %f, got %f", expectedRiskMetrics.WithEnvironmentAndThreatIntelligence, riskMetrics.WithEnvironmentAndThreatIntelligence)
			}

			if vector != tableTest.expectedVector {
				t.Errorf("Expected vector to be %s, got %s", tableTest.expectedVector, vector)
			}
		})
	}
}

func TestGenerateCommandsToFixPackage(t *testing.T) {
	t.Run("invalid package URL should result in an empty string", func(t *testing.T) {
		result := Explanation{
			ComponentPurl: "pk:golang/crypto@0.0.32",
			FixedVersion:  utils.Ptr("0"),
		}.GenerateCommandsToFixPackage()
		assert.Equal(t, result, "")
	})
	t.Run("unknown namespace should also result in an empty string", func(t *testing.T) {
		result := Explanation{
			ComponentPurl: "pk:golang/crypto@0.0.32",
			FixedVersion:  utils.Ptr("0"),
		}.GenerateCommandsToFixPackage()
		assert.Equal(t, result, "")
	})
	t.Run("unknown namespace should also result in an empty string", func(t *testing.T) {
		result := Explanation{
			ComponentPurl: "pkg:golang/crypto@0.0.32",
			FixedVersion:  utils.Ptr("0"),
		}.GenerateCommandsToFixPackage()
		assert.Equal(t, "```\n# Update all golang packages\ngo get -u ./... \n# Update only this package\ngo get crypto@0 \n```", result)
	})
	t.Run("unknown namespace should also result in an empty string", func(t *testing.T) {
		result := Explanation{
			ComponentPurl: "pkg:npm/crypto@0.0.32",
			FixedVersion:  utils.Ptr("0"),
		}.GenerateCommandsToFixPackage()

		assert.Equal(t, "```\n# Update all vulnerable npm packages\nnpm audit fix\n# Update only this package\nnpm install crypto@0 \n```", result)
	})
	t.Run("unknown namespace should also result in an empty string", func(t *testing.T) {
		result := Explanation{
			ComponentPurl: "pkg:crates.io/crypto@0.0.32",
			FixedVersion:  utils.Ptr("0"),
		}.GenerateCommandsToFixPackage()
		assert.Equal(t, "```\n# Update all rust packages\ncargo Update\n# Update only this package\n# insert into Cargo.toml:\n# crypto = \"=0\"\n```", result)
	})
	t.Run("unknown namespace should also result in an empty string", func(t *testing.T) {

		result := Explanation{
			ComponentPurl: "pkg:pypi/crypto@0.0.32",
			FixedVersion:  utils.Ptr("0"),
		}.GenerateCommandsToFixPackage()
		assert.Equal(t, "```\n# Update all vulnerable python packages\npip install pip-audit\npip-audit\n # Update only this package\npip install crypto==0\n```", result)
	})
	t.Run("unknown namespace should also result in an empty string", func(t *testing.T) {
		result := Explanation{
			ComponentPurl: "pkg:apk/crypto@0.0.32",
			FixedVersion:  utils.Ptr("0"),
		}.GenerateCommandsToFixPackage()

		assert.Equal(t, "```\n# Update all apk packages\napk Update && apk upgrade\n# Update only this package\napk add crypto=0\n```", result)
	})
	t.Run("unknown namespace should also result in an empty string", func(t *testing.T) {
		result := Explanation{
			ComponentPurl: "pkg:deb/crypto@0.0.32",
			FixedVersion:  utils.Ptr("0"),
		}.GenerateCommandsToFixPackage()
		assert.Equal(t, "```\n# Update all debian packages\napt Update && apt upgrade\n# Update only this package\napt install crypto=0\n```", result)
	})
	t.Run("unknown namespace should also result in an empty string", func(t *testing.T) {
		result := Explanation{
			ComponentPurl: "pkg:NuGet/crypto@0.0.32",
			FixedVersion:  utils.Ptr("0"),
		}.GenerateCommandsToFixPackage()
		assert.Equal(t, "```\n# Update all vulnerable NuGet packages\ndotnet list package --vulnerable\n dotnet outdated\n# Update only this package dotnet add package crypto --version 0\n```", result)
	})

}

func floatsEqual(a, b float64) bool {
	return math.Abs(a-b) < 0.01
}

func TestExplanationMarkdown(t *testing.T) {
	baseURL := "https://devguard.example.com"
	orgSlug := "my-org"
	projectSlug := "my-project"
	assetSlug := "my-asset"
	assetVersionSlug := "v1-0-0"
	mermaidPathToComponent := "```mermaid\ngraph TD\n  A[Root] --> B[Component]\n```"

	t.Run("should generate complete markdown with all sections", func(t *testing.T) {
		explanation := Explanation{
			RiskMetrics: dtos.RiskMetrics{
				BaseScore:                            7.5,
				WithEnvironment:                      6.8,
				WithThreatIntelligence:               7.2,
				WithEnvironmentAndThreatIntelligence: 6.5,
			},
			ExploitMessage: struct {
				Short string
				Long  string
			}{
				Short: "Proof of Concept",
				Long:  "A proof of concept is available for this vulnerability",
			},
			EPSSMessage:            "The exploit probability is moderate. The vulnerability is likely to be exploited in the next 30 days.",
			CVSSBEMessage:          "- Exploiting this vulnerability significantly impacts availability.",
			ComponentDepthMessage:  "The vulnerability is in a direct dependency of your project.",
			CVSSMessage:            "- The vulnerability can be exploited over the network without needing physical access.",
			DependencyVulnID:       "test-vuln-id",
			Risk:                   7.5,
			Depth:                  1,
			EPSS:                   0.35,
			CVEID:                  "CVE-2023-1234",
			CVEDescription:         "This is a test vulnerability description with potential security implications.",
			ComponentPurl:          "pkg:npm/test-package@1.0.0",
			ArtifactNames:          "artifact1 artifact2",
			FixedVersion:           ptr("1.2.3"),
			ShortenedComponentPurl: "npm/test-package@1.0.0",
		}

		result := explanation.Markdown(baseURL, orgSlug, projectSlug, assetSlug, assetVersionSlug, mermaidPathToComponent)

		// Test header
		assert.Contains(t, result, "## CVE-2023-1234 found in npm/test-package@1.0.0")

		// Test risk information
		assert.Contains(t, result, "> **Risk**: `7.50 (High)`")
		assert.Contains(t, result, "> **CVSS**: `7.5`")

		// Test description
		assert.Contains(t, result, "### Description")
		assert.Contains(t, result, "This is a test vulnerability description with potential security implications.")

		// Test affected component
		assert.Contains(t, result, "### Affected component")
		assert.Contains(t, result, "The vulnerability is in `pkg:npm/test-package@1.0.0`, found in artifacts `artifact1`, `artifact2`.")

		// Test recommended fix
		assert.Contains(t, result, "### Recommended fix")
		assert.Contains(t, result, "Upgrade to version 1.2.3 or later.")
		assert.Contains(t, result, "npm install test-package@1.2.3")

		// Test additional guidance
		assert.Contains(t, result, "### Additional guidance for mitigating vulnerabilities")
		assert.Contains(t, result, "[devguard.org](https://devguard.org/risk-mitigation-guides/software-composition-analysis)")

		// Test details section
		assert.Contains(t, result, "<details>")
		assert.Contains(t, result, "<summary>See more details...</summary>")
		assert.Contains(t, result, "### Path to component")
		assert.Contains(t, result, mermaidPathToComponent)

		// Test risk factors table
		assert.Contains(t, result, "| Risk Factor  | Value | Description |")
		assert.Contains(t, result, "| Vulnerability Depth | `1` | The vulnerability is in a direct dependency of your project. |")
		assert.Contains(t, result, "| EPSS | `35.00 %` | The exploit probability is moderate. The vulnerability is likely to be exploited in the next 30 days. |")
		assert.Contains(t, result, "| EXPLOIT | `Proof of Concept` | A proof of concept is available for this vulnerability |")
		assert.Contains(t, result, "| CVSS-BE | `6.8` | - Exploiting this vulnerability significantly impacts availability. |")
		assert.Contains(t, result, "| CVSS-B | `7.5` | - The vulnerability can be exploited over the network without needing physical access. |")

		// Test DevGuard link
		assert.Contains(t, result, "More details can be found in [DevGuard](https://devguard.example.com/my-org/projects/my-project/assets/my-asset/refs/v1-0-0/dependency-risks/test-vuln-id)")

		// Test closing details tag
		assert.Contains(t, result, "</details>")
	})

	t.Run("should handle no fixed version available", func(t *testing.T) {
		explanation := Explanation{
			RiskMetrics: dtos.RiskMetrics{
				BaseScore: 5.0,
			},
			CVEID:                  "CVE-2023-5678",
			CVEDescription:         "Another test vulnerability",
			ComponentPurl:          "pkg:pypi/vulnerable-package@2.0.0",
			ArtifactNames:          "single-artifact",
			FixedVersion:           nil,
			ShortenedComponentPurl: "pypi/vulnerable-package@2.0.0",
			Risk:                   5.0,
		}

		result := explanation.Markdown(baseURL, orgSlug, projectSlug, assetSlug, assetVersionSlug, mermaidPathToComponent)

		assert.Contains(t, result, "## CVE-2023-5678 found in pypi/vulnerable-package@2.0.0")
		assert.Contains(t, result, "No fix is available.")
		assert.NotContains(t, result, "Upgrade to version")
	})

	t.Run("should handle critical risk level", func(t *testing.T) {
		explanation := Explanation{
			RiskMetrics: dtos.RiskMetrics{
				BaseScore: 9.5,
			},
			CVEID:                  "CVE-2023-9999",
			CVEDescription:         "Critical vulnerability",
			ComponentPurl:          "pkg:golang/critical-package@1.0.0",
			ArtifactNames:          "critical-artifact",
			FixedVersion:           ptr("2.0.0"),
			ShortenedComponentPurl: "golang/critical-package@1.0.0",
			Risk:                   9.5,
		}

		result := explanation.Markdown(baseURL, orgSlug, projectSlug, assetSlug, assetVersionSlug, mermaidPathToComponent)

		assert.Contains(t, result, "> **Risk**: `9.50 (Critical)`")
		assert.Contains(t, result, "go get critical-package@2.0.0")
	})

	t.Run("should handle low risk level", func(t *testing.T) {
		explanation := Explanation{
			RiskMetrics: dtos.RiskMetrics{
				BaseScore: 2.1,
			},
			CVEID:                  "CVE-2023-0001",
			CVEDescription:         "Low severity vulnerability",
			ComponentPurl:          "pkg:deb/low-risk-package@1.0.0",
			ArtifactNames:          "low-risk-artifact",
			FixedVersion:           ptr("1.0.1"),
			ShortenedComponentPurl: "deb/low-risk-package@1.0.0",
			Risk:                   2.1,
		}

		result := explanation.Markdown(baseURL, orgSlug, projectSlug, assetSlug, assetVersionSlug, mermaidPathToComponent)

		assert.Contains(t, result, "> **Risk**: `2.10 (Low)`")
		assert.Contains(t, result, "apt install low-risk-package=1.0.1")
	})

	t.Run("should handle multiple artifacts", func(t *testing.T) {
		explanation := Explanation{
			RiskMetrics: dtos.RiskMetrics{
				BaseScore: 6.0,
			},
			CVEID:                  "CVE-2023-1111",
			CVEDescription:         "Multi-artifact vulnerability",
			ComponentPurl:          "pkg:npm/multi-package@1.0.0",
			ArtifactNames:          "artifact1 artifact2 artifact3",
			FixedVersion:           ptr("1.1.0"),
			ShortenedComponentPurl: "npm/multi-package@1.0.0",
			Risk:                   6.0,
		}

		result := explanation.Markdown(baseURL, orgSlug, projectSlug, assetSlug, assetVersionSlug, mermaidPathToComponent)

		assert.Contains(t, result, "The vulnerability is in `pkg:npm/multi-package@1.0.0`, found in artifacts `artifact1`, `artifact2`, `artifact3`.")
	})

	t.Run("should handle zero risk level", func(t *testing.T) {
		explanation := Explanation{
			RiskMetrics: dtos.RiskMetrics{
				BaseScore: 0,
			},
			CVEID:                  "CVE-2023-0000",
			CVEDescription:         "Zero risk vulnerability",
			ComponentPurl:          "pkg:npm/zero-risk@1.0.0",
			ArtifactNames:          "test-artifact",
			FixedVersion:           nil,
			ShortenedComponentPurl: "npm/zero-risk@1.0.0",
			Risk:                   0,
		}

		result := explanation.Markdown(baseURL, orgSlug, projectSlug, assetSlug, assetVersionSlug, mermaidPathToComponent)

		assert.Contains(t, result, "> **Risk**: `0.00 (Unknown)`")
	})

	t.Run("should include proper markdown formatting", func(t *testing.T) {
		explanation := Explanation{
			RiskMetrics: dtos.RiskMetrics{
				BaseScore: 5.5,
			},
			CVEID:                  "CVE-2023-FORMAT",
			CVEDescription:         "Formatting test vulnerability",
			ComponentPurl:          "pkg:maven/format-test@1.0.0",
			ArtifactNames:          "format-artifact",
			FixedVersion:           ptr("1.1.0"),
			ShortenedComponentPurl: "maven/format-test@1.0.0",
			Risk:                   5.5,
		}

		result := explanation.Markdown(baseURL, orgSlug, projectSlug, assetSlug, assetVersionSlug, mermaidPathToComponent)

		// Check for proper markdown headers
		assert.Contains(t, result, "## CVE-2023-FORMAT")
		assert.Contains(t, result, "### Description")
		assert.Contains(t, result, "### Affected component")
		assert.Contains(t, result, "### Recommended fix")
		assert.Contains(t, result, "### Additional guidance for mitigating vulnerabilities")
		assert.Contains(t, result, "### Path to component")

		// Check for proper markdown elements
		assert.Contains(t, result, "> [!important]")
		assert.Contains(t, result, "| Risk Factor  | Value | Description |")
		assert.Contains(t, result, "| ---- | ----- | ----------- |")
		assert.Contains(t, result, "<details>")
		assert.Contains(t, result, "<summary>See more details...</summary>")
		assert.Contains(t, result, "</details>")
	})
}

func TestExploitMessage(t *testing.T) {
	for _, exploitType := range []string{"P", "POC", "F"} {
		t.Run(fmt.Sprintf("should be deterministic: %s", exploitType), func(t *testing.T) {
			v := models.DependencyVuln{
				CVE: models.CVE{
					Exploits: []models.Exploit{
						{SourceURL: "http://exploit1.com"},
						{SourceURL: "http://exploit2.com"},
					},
				},
			}
			short1, long1 := exploitMessage(v, map[string]string{
				"E": exploitType,
			})

			// create another instance with exploits in different order
			v2 := models.DependencyVuln{
				CVE: models.CVE{
					Exploits: []models.Exploit{
						{SourceURL: "http://exploit2.com"},
						{SourceURL: "http://exploit1.com"},
					},
				},
			}
			short2, long2 := exploitMessage(v2, map[string]string{
				"E": exploitType,
			})

			assert.Equal(t, short1, short2)
			assert.Equal(t, long1, long2)
		})
	}
}
