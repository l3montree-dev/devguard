package compat

import (
	"time"

	"github.com/l3montree-dev/devguard/dtos"
)

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

/**
Fixes: https://gitlab.opencode.de/oci-community/images/l3montree/devguard/devguard/-/jobs/2027715
Those interfaces only exists to make the devguard scanner :main compatible with the new backend
This allows easy migration. Can be removed after the 1.3.0 is released.
*/

type ScanResponse struct {
	AmountOpened    int                 `json:"amountOpened"`
	AmountClosed    int                 `json:"amountClosed"`
	DependencyVulns []DependencyVulnDTO `json:"dependencyVulns"`
}
type FirstPartyScanResponse struct {
	AmountOpened    int                 `json:"amountOpened"`
	AmountClosed    int                 `json:"amountClosed"`
	FirstPartyVulns []FirstPartyVulnDTO `json:"firstPartyVulns"`
}

type FirstPartyVulnDTO struct {
	ScannerIDs           string                `json:"scannerIds"`
	Message              *string               `json:"message"`
	AssetVersionName     string                `json:"assetVersionName"`
	AssetID              string                `json:"assetId"`
	State                dtos.VulnState        `json:"state"`
	RuleID               string                `json:"ruleId"`
	URI                  string                `json:"uri"`
	SnippetContents      []dtos.SnippetContent `json:"snippetContents"`
	CreatedAt            time.Time             `json:"createdAt"`
	TicketID             *string               `json:"ticketId"`
	TicketURL            *string               `json:"ticketUrl"`
	ManualTicketCreation bool                  `json:"manualTicketCreation"`
	Commit               string                `json:"commit"`
	Email                string                `json:"email"`
	Author               string                `json:"author"`
	Date                 string                `json:"date"`

	RuleName        string         `json:"ruleName"`
	RuleHelp        string         `json:"ruleHelp"`
	RuleHelpURI     string         `json:"ruleHelpURI"`
	RuleDescription string         `json:"ruleDescription"`
	RuleProperties  map[string]any `json:"ruleProperties"`
}

type DependencyVulnDTO struct {
	Message                      *string            `json:"message"`
	AssetVersionName             string             `json:"assetVersionId"`
	AssetID                      string             `json:"assetId"`
	State                        dtos.VulnState     `json:"state"`
	CVE                          dtos.CVEDTO        `json:"cve"`
	CVEID                        string             `json:"cveID"`
	ComponentPurl                string             `json:"componentPurl"`
	ComponentFixedVersion        *string            `json:"componentFixedVersion"`
	VulnerabilityPath            []string           `json:"vulnerabilityPath"`
	DirectDependencyFixedVersion *string            `json:"directDependencyFixedVersion"`
	Effort                       *int               `json:"effort"`
	RiskAssessment               *int               `json:"riskAssessment"`
	RawRiskAssessment            *float64           `json:"rawRiskAssessment"`
	Priority                     *int               `json:"priority"`
	LastDetected                 time.Time          `json:"lastDetected"`
	CreatedAt                    time.Time          `json:"createdAt"`
	TicketID                     *string            `json:"ticketId"`
	TicketURL                    *string            `json:"ticketUrl"`
	ManualTicketCreation         bool               `json:"manualTicketCreation"`
	Artifacts                    []dtos.ArtifactDTO `json:"artifacts"`
	Exploits                     []dtos.ExploitDTO  `json:"exploits"`

	RiskRecalculatedAt time.Time `json:"riskRecalculatedAt"`
}
