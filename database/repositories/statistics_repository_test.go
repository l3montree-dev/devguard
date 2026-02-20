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

package repositories

import (
	"testing"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/stretchr/testify/assert"
)

// TestReplayHistoricalEvents reproduces the bug where TimeTravelDependencyVulnState
// returned the current database state instead of the reconstructed historical state.
//
// Symptom: after fixing vulnerabilities the risk history chart showed the fixed
// state for ALL historical days, not just the days after the actual fix.
func TestReplayHistoricalEvents(t *testing.T) {
	t.Run("vuln reopened before time-travel point but fixed after must be returned as open", func(t *testing.T) {
		// Timeline
		//   Day 1  EventTypeDetected  → state: open
		//   Day 2  EventTypeAccepted  → state: accepted
		//   Day 3  EventTypeReopened  → state: open   ← time-travel target
		//   Day 5  EventTypeFixed     → state: fixed  ← current DB state (excluded by time filter)
		//
		// The DB query returns the vuln with State="fixed" and only the three
		// events that existed before Day 3.
		vulns := []models.DependencyVuln{
			{
				Vulnerability: models.Vulnerability{
					State: dtos.VulnStateFixed, // current persisted state (Day 5)
					Events: []models.VulnEvent{
						{Type: dtos.EventTypeDetected},
						{Type: dtos.EventTypeAccepted},
						{Type: dtos.EventTypeReopened},
						// EventTypeFixed excluded because it was created after the time-travel point
					},
				},
			},
		}

		result := replayHistoricalEvents(vulns)

		assert.Equal(t, dtos.VulnStateOpen, result[0].State)
	})

	t.Run("vuln detected but not yet fixed must be returned as open", func(t *testing.T) {
		// Simple detect-then-fix lifecycle. Time-travel to Day 1.
		// DB state is "fixed"; only the detected event falls before Day 1.
		vulns := []models.DependencyVuln{
			{
				Vulnerability: models.Vulnerability{
					State: dtos.VulnStateFixed,
					Events: []models.VulnEvent{
						{Type: dtos.EventTypeDetected},
					},
				},
			},
		}

		result := replayHistoricalEvents(vulns)

		assert.Equal(t, dtos.VulnStateOpen, result[0].State)
	})

	t.Run("vuln with no events must remain in zero state", func(t *testing.T) {
		vulns := []models.DependencyVuln{
			{
				Vulnerability: models.Vulnerability{
					State: dtos.VulnStateFixed,
				},
			},
		}

		result := replayHistoricalEvents(vulns)

		assert.Equal(t, dtos.VulnState(""), result[0].State)
	})

	t.Run("vuln accepted before time-travel point must be returned as accepted", func(t *testing.T) {
		vulns := []models.DependencyVuln{
			{
				Vulnerability: models.Vulnerability{
					State: dtos.VulnStateOpen, // current DB state changed later
					Events: []models.VulnEvent{
						{Type: dtos.EventTypeDetected},
						{Type: dtos.EventTypeAccepted},
					},
				},
			},
		}

		result := replayHistoricalEvents(vulns)

		assert.Equal(t, dtos.VulnStateAccepted, result[0].State)
	})

	t.Run("multiple vulns are each replayed independently", func(t *testing.T) {
		risk := 5.0
		vulns := []models.DependencyVuln{
			{
				Vulnerability: models.Vulnerability{
					State:  dtos.VulnStateFixed,
					Events: []models.VulnEvent{{Type: dtos.EventTypeDetected}},
				},
				RawRiskAssessment: &risk,
			},
			{
				Vulnerability: models.Vulnerability{
					State: dtos.VulnStateOpen,
					Events: []models.VulnEvent{
						{Type: dtos.EventTypeDetected},
						{Type: dtos.EventTypeFixed},
					},
				},
			},
		}

		result := replayHistoricalEvents(vulns)

		assert.Equal(t, dtos.VulnStateOpen, result[0].State, "first vuln: only detected event → open")
		assert.Equal(t, dtos.VulnStateFixed, result[1].State, "second vuln: detected then fixed → fixed")
	})
}
