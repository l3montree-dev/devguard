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

package flaw

import (
	"time"

	"github.com/l3montree-dev/flawfix/internal/database/models"
)

type pagedFlawDTO struct {
	ID                 string            `json:"id"`
	ScannerID          string            `json:"scanner"`
	Message            *string           `json:"message"`
	AssetID            string            `json:"assetId"`
	State              models.FlawState  `json:"state"`
	CVE                *models.CVE       `json:"cve"`
	CVEID              string            `json:"cveId"`
	Component          *models.Component `json:"component"`
	ComponentPurlOrCpe string            `json:"componentPurlOrCpe"`
	Effort             *int              `json:"effort"`
	RiskAssessment     *int              `json:"riskAssessment"`
	RawRiskAssessment  *int              `json:"rawRiskAssessment"`
	Priority           *int              `json:"priority"`
	ArbitraryJsonData  map[string]any    `json:"arbitraryJsonData"`
	LastDetected       time.Time         `json:"lastDetected"`
	CreatedAt          time.Time         `json:"createdAt"`
}
