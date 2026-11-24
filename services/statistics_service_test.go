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

package services

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func newComponentRiskVuln(componentPurl, cveID string, cvss float32, risk float64) models.DependencyVuln {
	return models.DependencyVuln{
		CVEID:          cveID,
		CVE:            &models.CVE{CVE: cveID, CVSS: cvss},
		ComponentPurl:  componentPurl,
		RiskAssessment: new(risk),
	}
}

func TestGetComponentRisk(t *testing.T) {
	assetVersionID := uuid.New()

	getComponentRisk := func(t *testing.T, vulns []models.DependencyVuln) map[string]models.Distribution {
		dependencyVulnRepository := mocks.NewDependencyVulnRepository(t)
		dependencyVulnRepository.EXPECT().GetAllOpenVulnsByAssetVersionID(mock.Anything, mock.Anything, mock.Anything, assetVersionID).Return(vulns, nil)

		s := &statisticsService{dependencyVulnRepository: dependencyVulnRepository}

		result, err := s.GetComponentRisk(context.Background(), nil, assetVersionID)
		assert.NoError(t, err)
		return result
	}

	t.Run("components whose cves have no cvss score are not returned", func(t *testing.T) {
		result := getComponentRisk(t, []models.DependencyVuln{
			newComponentRiskVuln("pkg:golang/github.com/lib/pq@v1.12.3", "CVE-2026-0001", -1, -1),
		})

		assert.Empty(t, result)
	})

	t.Run("components with a scored cve are counted", func(t *testing.T) {
		result := getComponentRisk(t, []models.DependencyVuln{
			newComponentRiskVuln("pkg:golang/golang.org/x/crypto@v0.58.0", "CVE-2026-0002", 9.8, 7.5),
		})

		assert.Equal(t, map[string]models.Distribution{
			"pkg:golang/golang.org/x/crypto@v0.58.0": {High: 1, CriticalCVSS: 1},
		}, result)
	})

	t.Run("only the scored cves of a component are counted", func(t *testing.T) {
		result := getComponentRisk(t, []models.DependencyVuln{
			newComponentRiskVuln("pkg:golang/github.com/labstack/echo/v4@v4.16.3", "CVE-2026-0003", -1, -1),
			newComponentRiskVuln("pkg:golang/github.com/labstack/echo/v4@v4.16.3", "CVE-2026-0004", 5.3, 2.1),
		})

		assert.Equal(t, map[string]models.Distribution{
			"pkg:golang/github.com/labstack/echo/v4@v4.16.3": {Low: 1, MediumCVSS: 1},
		}, result)
	})
}
