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

package services

import (
	"testing"

	"github.com/gocsaf/csaf/v3/csaf"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
)

func TestGetVulnerabilitiesObject(t *testing.T) {
	t.Run("should respect if two vulnerabilities have a different state", func(t *testing.T) {
		openVuln := models.DependencyVuln{
			CVE: models.CVE{
				CVE: "CVE-2017-16136",
			},
			Vulnerability: models.Vulnerability{
				State: dtos.VulnStateOpen,
				Events: []models.VulnEvent{{
					Type: dtos.EventTypeDetected,
				}},
			},
		}
		falsePositiveVuln := models.DependencyVuln{
			CVE: models.CVE{
				CVE: "CVE-2017-16137",
			},
			Vulnerability: models.Vulnerability{
				State: dtos.VulnStateFalsePositive,
				Events: []models.VulnEvent{{
					Type: dtos.EventTypeDetected,
				}, {
					Type: dtos.EventTypeFalsePositive,
				}},
			},
		}

		vulns := []models.DependencyVuln{openVuln, falsePositiveVuln}
		vulnObjects, err := generateVulnerabilityObjects(vulns)
		assert.Nil(t, err)

		assert.Equal(t, 1, len(vulnObjects))

		labels := utils.Map(vulnObjects[0].Flags, func(flag *csaf.Flag) csaf.FlagLabel {
			return *flag.Label
		})
		// only a single false positive flag
		assert.Len(t, labels, 1)
		assert.Contains(t, labels, csaf.CSAFFlagLabelVulnerableCodeNotInExecutePath)
	})

}

func TestConvertAdvisoryToCdxVulnerability(t *testing.T) {
	t.Run("should build the vulnerabilities correctly", func(t *testing.T) {
		// read the advisory in the testdata folder
		advisory, err := csaf.LoadAdvisory("testdata/csaf_report.json")
		assert.Nil(t, err)

		purl, _ := packageurl.FromString("pkg:npm/super-logging@v1.0.0")
		vulns, err := convertAdvisoryToCdxVulnerability(advisory, purl)
		assert.Nil(t, err)

		assert.Equal(t, 1, len(vulns))
		// expect the single vuln to have pkg:npm/debug@3.0.0 as affected package
		assert.Equal(t, "pkg:npm/debug@3.0.0", (*vulns[0].Affects)[0].Ref)
		assert.Equal(t, "Marked as false positive: This doesnt affect us, since we are not using the vulnerable function at all.", vulns[0].Analysis.Detail)
	})
}
