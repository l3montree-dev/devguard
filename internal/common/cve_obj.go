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

package common

import "encoding/json"

type RiskMetrics struct {
	BaseScore                            float64 `json:"baseScore"`
	WithEnvironment                      float64 `json:"withEnvironment"`
	WithThreatIntelligence               float64 `json:"withThreatIntelligence"`
	WithEnvironmentAndThreatIntelligence float64 `json:"withEnvironmentAndThreatIntelligence"`
}

const CannotCalculateRisk float64 = 0

type RiskCalculationReport struct {
	EPSS                  float64 `json:"epss"`
	BaseScore             float64 `json:"baseScore"`
	ExploitExists         bool    `json:"exploitExists"`
	VerifiedExploitExists bool    `json:"verifiedExploitExists"`
	UnderAttack           bool    `json:"underAttack"`

	// environment information
	ConfidentialityRequirement string `json:"confidentialityRequirement"`
	IntegrityRequirement       string `json:"integrityRequirement"`
	AvailabilityRequirement    string `json:"availabilityRequirement"`

	Risk float64 `json:"risk"`

	Vector string `json:"vector"`
}

func (r RiskCalculationReport) Map() map[string]any {
	return map[string]any{
		"epss":                       r.EPSS,
		"baseScore":                  r.BaseScore,
		"exploitExists":              r.ExploitExists,
		"verifiedExploitExists":      r.VerifiedExploitExists,
		"underAttack":                r.UnderAttack,
		"confidentialityRequirement": r.ConfidentialityRequirement,
		"integrityRequirement":       r.IntegrityRequirement,
		"availabilityRequirement":    r.AvailabilityRequirement,
		"risk":                       r.Risk,
		"vector":                     r.Vector,
	}
}

func (r RiskCalculationReport) String() string {
	m := r.Map()
	str, err := json.Marshal(m)
	if err != nil {
		return ""
	}
	return string(str)
}

// used to return information about other instances of a dependency vuln in other parts of an organization
type DependencyVulnHints struct {
	AmountOpen              int
	AmountFixed             int
	AmountAccepted          int
	AmountFalsePositives    int
	AmountMarkedForTransfer int
}
