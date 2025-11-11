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

package dtos

import (
	"time"

	"github.com/l3montree-dev/devguard/database/models"
)

type DependencyVulnDTO struct {
	ID                    string            `json:"id"`
	Message               *string           `json:"message"`
	AssetVersionName      string            `json:"assetVersionId"`
	AssetID               string            `json:"assetId"`
	State                 models.VulnState  `json:"state"`
	CVE                   *models.CVE       `json:"cve"`
	CVEID                 *string           `json:"cveID"`
	ComponentPurl         *string           `json:"componentPurl"`
	ComponentDepth        *int              `json:"componentDepth"`
	ComponentFixedVersion *string           `json:"componentFixedVersion"`
	Effort                *int              `json:"effort"`
	RiskAssessment        *int              `json:"riskAssessment"`
	RawRiskAssessment     *float64          `json:"rawRiskAssessment"`
	Priority              *int              `json:"priority"`
	LastDetected          time.Time         `json:"lastDetected"`
	CreatedAt             time.Time         `json:"createdAt"`
	TicketID              *string           `json:"ticketId"`
	TicketURL             *string           `json:"ticketUrl"`
	ManualTicketCreation  bool              `json:"manualTicketCreation"`
	Artifacts             []models.Artifact `json:"artifacts"`

	RiskRecalculatedAt time.Time `json:"riskRecalculatedAt"`
}

type detailedDependencyVulnDTO struct {
	DependencyVulnDTO
	Events []VulnEventDTO `json:"events"`
}

func DependencyVulnToDto(f models.DependencyVuln) DependencyVulnDTO {

	return DependencyVulnDTO{
		ID:                    f.ID,
		Message:               f.Message,
		AssetVersionName:      f.AssetVersionName,
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
		ManualTicketCreation:  f.ManualTicketCreation,
		RiskRecalculatedAt:    f.RiskRecalculatedAt,
		Artifacts:             f.Artifacts,
	}
}
