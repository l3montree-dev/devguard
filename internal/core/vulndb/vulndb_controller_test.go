// Copyright (C) 2024 Tim Bastin, l3montree UG (haftungsbeschränkt)
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
	"testing"

	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/database/models"
	"github.com/l3montree-dev/flawfix/internal/obj"
)

func TestCalculateRisk(t *testing.T) {
	/*t.Run("should not panic if no vector is defined", func(t *testing.T) {
		sut := models.CVE{
			CVSS: 5,
		}
		env := core.Environmental{}
		riskMetrics, vector := riskCalculation(sut, env)

		if riskMetrics.BaseScore != 5 {
			t.Errorf("Expected base score to be 5, got %f", riskMetrics.BaseScore)
		}

		if riskMetrics.WithEnvironment != obj.CannotCalculateRisk {
			t.Errorf("Expected with environment score to be %f, got %f", obj.CannotCalculateRisk, riskMetrics.WithEnvironment)
		}

		if riskMetrics.WithThreatIntelligence != obj.CannotCalculateRisk {
			t.Errorf("Expected with threat intelligence score to be %f, got %f", obj.CannotCalculateRisk, riskMetrics.WithThreatIntelligence)
		}

		if riskMetrics.WithEnvironmentAndThreatIntelligence != obj.CannotCalculateRisk {
			t.Errorf("Expected with environment and threat intelligence score to be %f, got %f", obj.CannotCalculateRisk, riskMetrics.WithEnvironmentAndThreatIntelligence)
		}

		if vector != "" {
			t.Errorf("Expected vector to be empty, got %s", vector)
		}
	})*/

	table := []string{
		"CVSS:2.0/AV:L/AC:H/Au:M/C:C/I:C/A:C",
		// "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		// "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		// "CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	}

	for _, vector := range table {
		t.Run("should return cannot calculate risk magic number, if no env metrics and threat metrics are defined. Vector: "+vector, func(t *testing.T) {
			sut := models.CVE{
				CVSS:   5,
				Vector: vector,
			}
			env := core.Environmental{}
			riskMetrics, vector := riskCalculation(sut, env)

			if riskMetrics.BaseScore != 5 {
				t.Errorf("Expected base score to be 5, got %f", riskMetrics.BaseScore)
			}

			if riskMetrics.WithEnvironment != obj.CannotCalculateRisk {
				t.Errorf("Expected with environment score to be %f, got %f", obj.CannotCalculateRisk, riskMetrics.WithEnvironment)
			}

			if riskMetrics.WithThreatIntelligence != obj.CannotCalculateRisk {
				t.Errorf("Expected with threat intelligence score to be %f, got %f", obj.CannotCalculateRisk, riskMetrics.WithThreatIntelligence)
			}

			if riskMetrics.WithEnvironmentAndThreatIntelligence != obj.CannotCalculateRisk {
				t.Errorf("Expected with environment and threat intelligence score to be %f, got %f", obj.CannotCalculateRisk, riskMetrics.WithEnvironmentAndThreatIntelligence)
			}

			if vector != "" {
				t.Errorf("Expected vector to be empty, got %s", vector)
			}
		})
	}
}
