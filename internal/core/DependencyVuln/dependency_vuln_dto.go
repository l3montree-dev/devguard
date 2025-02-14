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

package DependencyVuln

import (
	"time"

	"github.com/l3montree-dev/devguard/internal/database/models"
)

type DependencyVulnDTO struct {
	ID                    string                     `json:"id"`
	ScannerID             string                     `json:"scanner"`
	Message               *string                    `json:"message"`
	AssetID               string                     `json:"assetId"`
	State                 models.DependencyVulnState `json:"state"`
	CVE                   *models.CVE                `json:"cve"`
	CVEID                 *string                    `json:"cveId"`
	ComponentPurl         *string                    `json:"componentPurl"`
	ComponentDepth        *int                       `json:"componentDepth"`
	ComponentFixedVersion *string                    `json:"componentFixedVersion"`
	Effort                *int                       `json:"effort"`
	RiskAssessment        *int                       `json:"riskAssessment"`
	RawRiskAssessment     *float64                   `json:"rawRiskAssessment"`
	Priority              *int                       `json:"priority"`
	LastDetected          time.Time                  `json:"lastDetected"`
	CreatedAt             time.Time                  `json:"createdAt"`
	TicketID              *string                    `json:"ticketId"`
	TicketURL             *string                    `json:"ticketUrl"`

	RiskRecalculatedAt time.Time `json:"riskRecalculatedAt"`
}

type detailedDependencyVulnDTO struct {
	DependencyVulnDTO
	Events []DependencyVulnEventDTO `json:"events"`
}

func DependencyVulnToDto(f models.DependencyVulnerability) DependencyVulnDTO {

	return DependencyVulnDTO{
		ID:                    f.ID,
		ScannerID:             f.ScannerID,
		Message:               f.Message,
		AssetID:               f.AssetID.String(),
		State:                 f.State,
		CVE:                   f.CVE,
		CVEID:                 f.CVEID,
		ComponentPurl:         f.ComponentPurl,
		ComponentDepth:        f.ComponentDepth,
		ComponentFixedVersion: f.ComponentFixedVersion,
		Effort:                f.Effort,
		RiskAssessment:        f.RiskAssessment,
		RawRiskAssessment:     f.RawRiskAssessment,
		Priority:              f.Priority,
		LastDetected:          f.LastDetected,
		CreatedAt:             f.CreatedAt,
		TicketID:              f.TicketID,
		TicketURL:             f.TicketURL,
		RiskRecalculatedAt:    f.RiskRecalculatedAt,
	}
}
