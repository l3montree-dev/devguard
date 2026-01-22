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

	"gorm.io/datatypes"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type RelationshipDTO struct {
	RelationshipType string `json:"relationshipType"`
	TargetCVE        string `json:"targetCve"`
}

type CVEDTO struct {
	CVE                   string            `json:"cve"`
	CreatedAt             time.Time         `json:"createdAt"`
	UpdatedAt             time.Time         `json:"updatedAt"`
	DatePublished         time.Time         `json:"datePublished"`
	DateLastModified      time.Time         `json:"dateLastModified"`
	Description           string            `json:"description"`
	CVSS                  float32           `json:"cvss"`
	References            string            `json:"references"`
	CISAExploitAdd        *datatypes.Date   `json:"cisaExploitAdd" swaggertype:"string" format:"date"`
	CISAActionDue         *datatypes.Date   `json:"cisaActionDue" swaggertype:"string" format:"date"`
	CISARequiredAction    string            `json:"cisaRequiredAction"`
	CISAVulnerabilityName string            `json:"cisaVulnerabilityName"`
	EPSS                  *float64          `json:"epss"`
	Percentile            *float32          `json:"percentile"`
	Vector                string            `json:"vector"`
	Risk                  RiskMetrics       `json:"risk"`
	Exploits              []ExploitDTO      `json:"exploits"`
	Relationships         []RelationshipDTO `json:"relationships"`
}

type VulnState string

const (
	VulnStateOpen              VulnState = "open"
	VulnStateFixed             VulnState = "fixed"         // we did not find the dependencyVuln anymore in the last scan!
	VulnStateAccepted          VulnState = "accepted"      // like ignore
	VulnStateFalsePositive     VulnState = "falsePositive" // we can use that for crowdsource vulnerability management. 27 People marked this as false positive and they have the same dependency tree - propably you are not either
	VulnStateMarkedForTransfer VulnState = "markedForTransfer"
)

type ExploitDTO struct {
	ID          string     `json:"id"`
	Published   *time.Time `json:"pushed_at"`
	Updated     *time.Time `json:"updated_at"`
	Author      string     `json:"author"`
	Type        string     `json:"type"`
	Verified    bool       `json:"verified"`
	SourceURL   string     `json:"sourceURL"`
	Description string     `json:"description"`
	CVEID       string     `json:"cveID"`
	Tags        string     `json:"tags"`
	Forks       int        `json:"forks"`
	Watchers    int        `json:"watchers"`
	Subscribers int        `json:"subscribers_count"`
	Stars       int        `json:"stargazers_count"`
}

type DependencyVulnDTO struct {
	ID                    string        `json:"id"`
	Message               *string       `json:"message"`
	AssetVersionName      string        `json:"assetVersionId"`
	AssetID               string        `json:"assetId"`
	State                 VulnState     `json:"state"`
	CVE                   CVEDTO        `json:"cve"`
	CVEID                 string        `json:"cveID"`
	ComponentPurl         string        `json:"componentPurl"`
	ComponentFixedVersion *string       `json:"componentFixedVersion"`
	VulnerabilityPath     []string      `json:"vulnerabilityPath"`
	Effort                *int          `json:"effort"`
	RiskAssessment        *int          `json:"riskAssessment"`
	RawRiskAssessment     *float64      `json:"rawRiskAssessment"`
	Priority              *int          `json:"priority"`
	LastDetected          time.Time     `json:"lastDetected"`
	CreatedAt             time.Time     `json:"createdAt"`
	TicketID              *string       `json:"ticketId"`
	TicketURL             *string       `json:"ticketUrl"`
	ManualTicketCreation  bool          `json:"manualTicketCreation"`
	Artifacts             []ArtifactDTO `json:"artifacts"`
	Exploits              []ExploitDTO  `json:"exploits"`

	RiskRecalculatedAt time.Time `json:"riskRecalculatedAt"`
}

type DetailedDependencyVulnDTO struct {
	DependencyVulnDTO
	Events []VulnEventDTO `json:"events"`
}
