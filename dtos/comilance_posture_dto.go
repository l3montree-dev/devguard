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

package dtos

import (
	"github.com/google/uuid"
)

type CompliancePostureDTO struct {
	ControlID          string `json:"controlId"`
	ControlTitle       string `json:"controlTitle"`
	ControlDescription string `json:"controlDescription"`

	TicketID             *string `json:"ticketId"`
	TicketURL            *string `json:"ticketUrl"`
	ManualTicketCreation bool    `json:"manualTicketCreation"`

	AssetID   string `json:"assetId"`
	ProjectID string `json:"projectId"`
	OrgID     string `json:"orgId"`

	State string `json:"state"`
}

type DetailsCompliancePostureDTO struct {
	CompliancePostureDTO
	Events []VulnEventDTO `json:"events"`
}

type CompliancePostureWithControlDTO struct {
	FrameworkControlID  string     `json:"frameworkControlId"`
	Framework           string     `json:"framework"`
	ControlID           string     `json:"controlId"`
	Title               string     `json:"title"`
	Description         string     `json:"description"`
	CompliancePostureID string     `json:"compliancePostureId"`
	State               VulnState  `json:"state"`
	OrgID               *uuid.UUID `json:"orgId"`
	ProjectID           *uuid.UUID `json:"projectId"`
	AssetID             *uuid.UUID `json:"assetId"`
	AssetVersionName    *string    `json:"assetVersionName"`
	TicketID            *string    `json:"ticketId"`
	TicketURL           *string    `json:"ticketUrl"`
}

type CompliancePostureWithDetailsDTO struct {
	CompliancePostureWithControlDTO
	Events []VulnEventDTO `json:"events"`
}

type CompliancePostureStatsDTO struct {
	Open          int64 `json:"open"`
	Implemented   int64 `json:"implemented"`
	NotApplicable int64 `json:"notApplicable"`
}
