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
	"github.com/l3montree-dev/devguard/normalize"
)

// PathPattern wildcard for VEX rules
const (
	// PathPatternWildcard matches any path element at that position
	PathPatternWildcard = "*"
)

// PathPattern represents a path pattern with wildcards.
// Patterns use suffix matching where "*" can match any number of path elements.
// A wildcard "*" can appear at any position to match zero or more path elements.
// Examples:
//   - ["pkg:golang/lib@v1.0"] matches paths ending with exactly this element
//   - ["*", "pkg:golang/lib@v1.0"] matches paths ending with any elements followed by this element
//   - ["*"] matches any path suffix
type PathPattern []string

// IsWildcard returns true if the element is a wildcard (*).
func IsWildcard(elem string) bool {
	// ROOT is a special element in the path
	// this means, THE CURRENT application does not call the vulnerable code
	// therefore, we can just replace it with a wildcard for matching purposes
	return elem == PathPatternWildcard || elem == normalize.GraphRootNodeID
}

// MatchesSuffix checks if the given path's suffix matches this pattern using suffix matching.
// The pattern is matched against suffixes of the path.
// A wildcard in the pattern matches zero or more path elements.
//
// Example:
//   - Pattern ["pkg:golang/lib"] matches path ["pkg:golang/lib"] or ["a", "b", "pkg:golang/lib"]
//   - Pattern ["*", "lib"] matches ["lib"] or ["a", "lib"] or ["a", "b", "lib"]
//   - Pattern ["a", "*", "b"] matches ["a", "b"] or ["a", "x", "b"] or ["a", "x", "y", "z", "b"]
func (p PathPattern) MatchesSuffix(path []string) bool {

	if len(p) == 0 {
		return true
	}

	// For suffix matching, we try increasingly longer suffixes
	// Count non-wildcard elements to determine minimum suffix length
	minLen := 0
	for _, elem := range p {
		if !IsWildcard(elem) {
			minLen++
		}
	}

	if len(path) < minLen {
		return false
	}

	// Try matching against suffixes of increasing length
	for suffixStart := len(path) - minLen; suffixStart >= 0; suffixStart-- {
		suffix := path[suffixStart:]
		if matchPatternExact(p, suffix) {
			return true
		}
	}
	return false
}

// matchPatternExact checks if the pattern exactly matches the path.
// Wildcards can match zero or more elements.
func matchPatternExact(pattern, path []string) bool {
	if len(pattern) == 0 {
		return len(path) == 0
	}

	pIdx := 0
	pathIdx := 0

	for pIdx < len(pattern) {
		if IsWildcard(pattern[pIdx]) {
			// Wildcard: try to match zero or more elements
			// If this is the last element in pattern, it matches everything remaining
			if pIdx == len(pattern)-1 {
				return true
			}

			// Try to find the next pattern element in the path
			nextPattern := pattern[pIdx+1]

			for i := pathIdx; i < len(path); i++ {
				if nextPattern == path[i] {
					// Found next pattern element, recursively match the rest
					if matchPatternExact(pattern[pIdx+1:], path[i:]) {
						return true
					}
				}
			}

			// Handle the case where we've exhausted the path (i == len(path) in the original loop)
			// Check if remaining pattern is all wildcards or empty
			allWildcards := true
			for j := pIdx + 1; j < len(pattern); j++ {
				if !IsWildcard(pattern[j]) {
					allWildcards = false
					break
				}
			}
			if allWildcards {
				return true
			}
			return pathIdx == len(path)
		}

		// Literal match
		if pathIdx >= len(path) || pattern[pIdx] != path[pathIdx] {
			return false
		}

		pIdx++
		pathIdx++
	}

	return pathIdx == len(path)
}

// ContainsWildcard returns true if the pattern contains a wildcard (*).
func (p PathPattern) ContainsWildcard() bool {
	for _, elem := range p {
		if IsWildcard(elem) {
			return true
		}
	}
	return false
}

type VEXRuleDTO struct {
	// Primary key
	ID string `json:"id"`

	// Composite key components
	AssetID   uuid.UUID `json:"assetId"`
	CVEID     string    `json:"cveId"`
	VexSource string    `json:"vexSource"`

	// Rule data
	Justification           string                      `json:"justification"`
	MechanicalJustification MechanicalJustificationType `json:"mechanicalJustification"`
	EventType               VulnEventType               `json:"eventType"`
	PathPattern             PathPattern                 `json:"pathPattern"`
	CreatedByID             string                      `json:"createdById"`
	CreatedAt               string                      `json:"createdAt"`
	UpdatedAt               string                      `json:"updatedAt"`

	// Metrics
	AppliesToAmountOfDependencyVulns int `json:"appliesToAmountOfDependencyVulns"`
}
