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
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/stretchr/testify/assert"
)

func TestMapCDXToEventType(t *testing.T) {
	cases := []struct {
		name      string
		analysis  *cdx.VulnerabilityAnalysis
		want      dtos.VulnEventType
		wantError bool
	}{
		{
			name:      "nil analysis",
			analysis:  nil,
			wantError: true,
		},
		{
			name:      "resolved state",
			analysis:  &cdx.VulnerabilityAnalysis{State: cdx.IASResolved},
			wantError: true,
		},
		{
			name:     "false positive state",
			analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASFalsePositive},
			want:     dtos.EventTypeFalsePositive,
		},
		{
			name:     "not affected state",
			analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASNotAffected},
			want:     dtos.EventTypeFalsePositive,
		},
		{
			name:      "exploitable without response",
			analysis:  &cdx.VulnerabilityAnalysis{State: cdx.IASExploitable},
			wantError: true,
		},
		{
			name:     "exploitable with will not fix",
			analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASExploitable, Response: &[]cdx.ImpactAnalysisResponse{cdx.IARWillNotFix}},
			want:     dtos.EventTypeAccepted,
		},
		{
			name:     "exploitable with update",
			analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASExploitable, Response: &[]cdx.ImpactAnalysisResponse{cdx.IARUpdate}},
			want:     dtos.EventTypeComment,
		},
		{
			name:      "in triage",
			analysis:  &cdx.VulnerabilityAnalysis{State: cdx.IASInTriage},
			wantError: true,
		},
		{
			name:     "will not fix response fallback",
			analysis: &cdx.VulnerabilityAnalysis{State: "", Response: &[]cdx.ImpactAnalysisResponse{cdx.IARWillNotFix}},
			want:     dtos.EventTypeAccepted,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := mapCDXToEventType(tc.analysis)
			if tc.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.want, got)
			}
		})
	}
}
