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

type ComplianceComponentDTO struct {
	UUID        string `json:"uuid"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

// ComplianceComponentImplementsControlDTO is a component's catalog-level claim
// that it implements a given control (models.ComplianceComponentImplementsControl).
type ComplianceComponentImplementsControlDTO struct {
	FrameworkControlID       string `json:"frameworkControlId"`
	ComplianceComponentID    string `json:"complianceComponentId"`
	ComplianceComponentTitle string `json:"complianceComponentTitle"`
	Description              string `json:"description"`
}

type ComplianceComponentDetailsDTO struct {
	ComplianceComponentDTO
	ImplementedControls []ComplianceComponentImplementsControlDTO `json:"implementedControls"`
}

type ComplianceComponentImplementsControlStatementDTO struct {
	ID                             string `json:"id"`
	CompliancePostureID            string `json:"compliancePostureId"`
	ComplianceComponentID          string `json:"complianceComponentId"`
	ComplianceComponentTitle       string `json:"complianceComponentTitle"`
	ComplianceComponentDescription string `json:"complianceComponentDescription"`
	FrameworkControlID             string `json:"frameworkControlId"`
	ImplementationStatus           string `json:"implementationStatus"`
	Description                    string `json:"description"`
}
