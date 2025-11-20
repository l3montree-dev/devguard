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
	"github.com/stretchr/testify/assert"
)

func TestGetVulnerabilitiesObject(t *testing.T) {
	t.Run("should respect if two vulnerabilities have a different state", func(t *testing.T) {
		openVuln := models.DependencyVuln{
			CVE: &models.CVE{
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
			CVE: &models.CVE{
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
