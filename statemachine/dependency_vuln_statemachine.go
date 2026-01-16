// Copyright (C) 2025 l3montree GmbH
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

package statemachine

import (
	"log/slog"
	"slices"
	"time"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/utils"
)

type DependencyVulnStateMachine struct {
}

type ScanDiff struct {
	// Newly discovered vulnerabilities (never seen before)
	NewlyDiscovered []models.DependencyVuln

	// Fixed everywhere (no longer detected in any artifact)
	FixedEverywhere []models.DependencyVuln

	// First time detected in this specific artifact (but exists elsewhere)
	NewInArtifact []models.DependencyVuln

	// No longer detected in this artifact (but still exists elsewhere)
	RemovedFromArtifact []models.DependencyVuln

	// Still detected, no changes
	Unchanged []models.DependencyVuln
}

type VulnSet struct {
	byHash map[string]models.DependencyVuln
}

// NewVulnSet creates a new vulnerability set
func NewVulnSet(vulns []models.DependencyVuln) *VulnSet {
	set := &VulnSet{
		byHash: make(map[string]models.DependencyVuln, len(vulns)),
	}
	for _, vuln := range vulns {
		set.Add(vuln)
	}
	return set
}

// Add adds a vulnerability to the set (deduplicates by hash)
func (s *VulnSet) Add(vuln models.DependencyVuln) {
	hash := vuln.CalculateHash()
	if _, exists := s.byHash[hash]; !exists {
		s.byHash[hash] = vuln
	}
}

// Contains checks if a vulnerability exists in the set
func (s *VulnSet) Contains(vuln models.DependencyVuln) bool {
	_, exists := s.byHash[vuln.CalculateHash()]
	return exists
}

// Get retrieves a vulnerability from the set
func (s *VulnSet) Get(vuln models.DependencyVuln) (models.DependencyVuln, bool) {
	v, exists := s.byHash[vuln.CalculateHash()]
	return v, exists
}

// isFoundInArtifact checks if a vulnerability is detected in a specific artifact
func isFoundInArtifact(vuln models.DependencyVuln, artifactName string) bool {
	for _, artifact := range vuln.Artifacts {
		if artifact.ArtifactName == artifactName {
			return true
		}
	}
	return false
}

// isOnlyFoundInArtifact checks if a vulnerability is only detected in a single artifact
func isOnlyFoundInArtifact(vuln models.DependencyVuln, artifactName string) bool {
	return len(vuln.Artifacts) == 1 && vuln.Artifacts[0].ArtifactName == artifactName
}

func DiffScanResults(artifactName string, foundVulns []models.DependencyVuln, existingVulns []models.DependencyVuln) ScanDiff {

	diff := ScanDiff{
		NewlyDiscovered:     make([]models.DependencyVuln, 0),
		FixedEverywhere:     make([]models.DependencyVuln, 0),
		NewInArtifact:       make([]models.DependencyVuln, 0),
		RemovedFromArtifact: make([]models.DependencyVuln, 0),
		Unchanged:           make([]models.DependencyVuln, 0),
	}

	foundSet := NewVulnSet(foundVulns)
	existingSet := NewVulnSet(existingVulns)

	// Process existing vulnerabilities: what disappeared?
	for _, existing := range existingVulns {
		foundVuln, ok := foundSet.Get(existing)
		if !ok {
			// This vulnerability was not found in current scan
			if isOnlyFoundInArtifact(existing, artifactName) {
				// Fixed everywhere (this was the only artifact reporting it)
				diff.FixedEverywhere = append(diff.FixedEverywhere, existing)
			} else {
				// Fixed only in this artifact (still exists in others)
				diff.RemovedFromArtifact = append(diff.RemovedFromArtifact, existing)
			}
		} else {
			// update the existing component_depth using the value from the found vulnerability
			existing.ComponentDepth = foundVuln.ComponentDepth
			// Still exists, nothing changed
			diff.Unchanged = append(diff.Unchanged, existing)
		}
	}

	// Process found vulnerabilities: what's new?
	for _, found := range foundVulns {
		if existing, wasKnown := existingSet.Get(found); !wasKnown {
			// Never seen this vulnerability before
			diff.NewlyDiscovered = append(diff.NewlyDiscovered, found)
		} else {
			// Known vulnerability - check if it's new to this artifact
			if !isFoundInArtifact(existing, artifactName) {
				// First time seeing it in this artifact
				diff.NewInArtifact = append(diff.NewInArtifact, existing)
			}
		}
	}
	return diff
}

type BranchDiff[T models.Vuln] struct {
	// Completely new vulnerabilities (not on any other branch)
	NewToAllBranches []T

	// Vulnerabilities that exist on other branches (need event history copied)
	ExistingOnOtherBranches []BranchVulnMatch[T]
}

// BranchVulnMatch represents a vulnerability found on current branch that exists elsewhere
type BranchVulnMatch[T models.Vuln] struct {
	// The vulnerability as detected on the current branch
	CurrentBranchVuln T

	// The same vulnerability from other branches with their event history
	OtherBranchVulns []T

	// Consolidated events from all other branches (ready to copy)
	EventsToCopy []models.VulnEvent
}

// Compare compares vulnerabilities on current branch with other branches
func DiffVulnsBetweenBranches[T models.Vuln](
	currentBranchVulns []T,
	otherBranchesVulns []T,
) BranchDiff[T] {
	diff := BranchDiff[T]{
		NewToAllBranches:        make([]T, 0),
		ExistingOnOtherBranches: make([]BranchVulnMatch[T], 0),
	}

	// Index other branches' vulnerabilities by hash
	otherBranchIndex := indexByHash(otherBranchesVulns)

	// Check each vulnerability on current branch
	for _, currentVuln := range currentBranchVulns {
		hash := currentVuln.AssetVersionIndependentHash()

		if matchingVulns, existsElsewhere := otherBranchIndex[hash]; existsElsewhere {
			// This vuln exists on other branches - create a match
			// make sure to update the state of the vulnerability accordingly.
			// at least we are in the statemachine here.
			events := extractRelevantEvents(matchingVulns)
			slices.SortStableFunc(events, func(a, b models.VulnEvent) int {
				if a.CreatedAt.Before(b.CreatedAt) {
					return -1
				} else if a.CreatedAt.After(b.CreatedAt) {
					return 1
				}
				return 0
			})

			for _, ev := range events {
				Apply(currentVuln, ev)
			}

			match := BranchVulnMatch[T]{
				CurrentBranchVuln: currentVuln,
				OtherBranchVulns:  matchingVulns,
				EventsToCopy:      events,
			}

			diff.ExistingOnOtherBranches = append(diff.ExistingOnOtherBranches, match)
		} else {
			// Brand new vulnerability
			diff.NewToAllBranches = append(diff.NewToAllBranches, currentVuln)
		}
	}

	return diff
}

// indexByHash creates a map of vulnerabilities grouped by their hash
func indexByHash[T models.Vuln](vulns []T) map[string][]T {
	index := make(map[string][]T)

	for _, vuln := range vulns {
		hash := vuln.AssetVersionIndependentHash()
		index[hash] = append(index[hash], vuln)
	}

	return index
}

// extractRelevantEvents consolidates events from all matching vulnerabilities
func extractRelevantEvents[T models.Vuln](vulns []T) []models.VulnEvent {
	allEvents := make([]models.VulnEvent, 0)

	for _, vuln := range vulns {
		// Filter events: exclude risk assessment updates and already-copied events
		relevantEvents := utils.Filter(vuln.GetEvents(), func(ev models.VulnEvent) bool {
			return ev.OriginalAssetVersionName == nil &&
				ev.Type != dtos.EventTypeRawRiskAssessmentUpdated
		})

		// Tag events with their source branch
		taggedEvents := utils.Map(relevantEvents, func(event models.VulnEvent) models.VulnEvent {
			event.OriginalAssetVersionName = utils.Ptr(vuln.GetAssetVersionName())
			return event
		})

		allEvents = append(allEvents, taggedEvents...)
	}

	return allEvents
}

func Apply(vuln models.Vuln, event models.VulnEvent) {
	if event.Upstream != dtos.UpstreamStateInternal && event.Type == dtos.EventTypeAccepted {
		// its an external accepted event that should not modify state
		return
	}

	switch event.Type {
	case dtos.EventTypeLicenseDecision:
		finalLicenseDecision, ok := (event.GetArbitraryJSONData()["finalLicenseDecision"]).(string)
		if !ok {
			slog.Error("could not parse final license decision", "dependencyVulnID",

				event.VulnID)
			return
		}
		v := vuln.(*models.LicenseRisk)
		v.SetFinalLicenseDecision(finalLicenseDecision)
		v.SetState(dtos.VulnStateFixed)
	case dtos.EventTypeFixed:
		vuln.SetState(dtos.VulnStateFixed)
	case dtos.EventTypeReopened:
		if event.Upstream == dtos.UpstreamStateExternal {
			return
		}
		vuln.SetState(dtos.VulnStateOpen)
	case dtos.EventTypeDetected:
		// event type detected will always be applied!
		f, ok := (event.GetArbitraryJSONData()["risk"]).(float64)
		if !ok {
			f = vuln.GetRawRiskAssessment()
		}
		vuln.SetRawRiskAssessment(f)
		vuln.SetRiskRecalculatedAt(time.Now())
		vuln.SetState(dtos.VulnStateOpen)
	case dtos.EventTypeAccepted:
		vuln.SetState(dtos.VulnStateAccepted)
	case dtos.EventTypeFalsePositive:
		if event.Upstream == dtos.UpstreamStateExternal {
			return
		}
		vuln.SetState(dtos.VulnStateFalsePositive)
	case dtos.EventTypeMarkedForTransfer:
		vuln.SetState(dtos.VulnStateMarkedForTransfer)
	case dtos.EventTypeRawRiskAssessmentUpdated:
		f, ok := (event.GetArbitraryJSONData()["risk"]).(float64)
		if !ok {
			slog.Error("could not parse risk assessment", "dependencyVulnID", event.VulnID)
			return
		}
		vuln.SetRawRiskAssessment(f)
		vuln.SetRiskRecalculatedAt(time.Now())
	}

}

// this helper function checks if a vuln slice already contains the purl + cve-id combination of vuln
func vulnSliceContainsVuln(vulns []models.DependencyVuln, checkVuln models.DependencyVuln) bool {
	checkCVEID := checkVuln.CVEID
	checkPurl := checkVuln.ComponentPurl

	for _, vuln := range vulns {
		vulnCVEID := vuln.CVEID
		if vulnCVEID != "" && vulnCVEID == checkCVEID {
			vulnPurl := vuln.ComponentPurl
			if vulnPurl != "" && vulnPurl == checkPurl {
				return true
			}
		}
	}
	return false
}

func vulnSliceContainsCVEIDWithVuln(vulns []models.DependencyVuln, targetCVEID string) (vuln models.DependencyVuln, ok bool) {
	for _, vuln := range vulns {
		cveID := vuln.CVEID

		if cveID == targetCVEID {
			return vuln, true
		}
	}
	return models.DependencyVuln{}, false
}

func vulnSliceContainsCVEID(vulns []models.DependencyVuln, targetCVEID string) bool {
	for _, vuln := range vulns {
		cveID := vuln.CVEID

		if cveID == targetCVEID {
			return true
		}
	}
	return false
}
