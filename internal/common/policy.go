// Copyright (C) 2025 l3montree UG (haftungsbeschraenkt)
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

package common

type PolicyEvaluation struct {
	PolicyMetadata
	Compliant  *bool    `json:"compliant"`
	Violations []string `json:"violations"`
}

type PolicyMetadata struct {
	Title                string   `yaml:"title" json:"title"`
	Description          string   `yaml:"description" json:"description"`
	Priority             int      `yaml:"priority" json:"priority"`
	Tags                 []string `yaml:"tags" json:"tags"`
	RelatedResources     []string `yaml:"relatedResources" json:"relatedResources"`
	ComplianceFrameworks []string `yaml:"complianceFrameworks" json:"complianceFrameworks"`
	Filename             string   `json:"filename"`
	Content              string   `json:"content"`
	AttestationName      string   `yaml:"attestationName" json:"attestationName"`
}
