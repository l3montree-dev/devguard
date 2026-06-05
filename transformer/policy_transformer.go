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

package transformer

import (
	"github.com/l3montree-dev/devguard/compliance"
	"github.com/l3montree-dev/devguard/dtos"
)

func PolicyEvaluationToDTO(e compliance.PolicyEvaluation) dtos.PolicyEvaluationDTO {
	state := dtos.VulnStateOpen
	if e.Compliant != nil && *e.Compliant {
		state = dtos.VulnStateFixed
	}
	var desc *string
	if e.Policy.Description != "" {
		d := e.Policy.Description
		desc = &d
	}
	return dtos.PolicyEvaluationDTO{
		PolicyID:              e.Policy.ID.String(),
		PolicyTitle:           e.Policy.Title,
		PolicyDescription:     desc,
		State:                 state,
		PredicateType:         e.Policy.PredicateType,
		AttestationViolations: e.Violations,
		AttestationUpdatedAt:  e.AttestationUpdatedAt,
	}
}
