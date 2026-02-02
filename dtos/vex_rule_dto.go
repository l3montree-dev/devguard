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

import "github.com/google/uuid"

// PathPattern wildcards for VEX rules
const (
	// PathPatternWildcardSingle matches any single path element (zero or more)
	PathPatternWildcardSingle = "*"
	// PathPatternWildcardMulti matches any number of path elements (zero or more)
	PathPatternWildcardMulti = "**"
)

// PathPattern represents a path pattern that can contain wildcards.
// Used for matching vulnerability paths in VEX rules.
type PathPattern []string

// IsWildcard returns true if the element is a wildcard (* or **).
func IsWildcard(elem string) bool {
	return elem == PathPatternWildcardSingle || elem == PathPatternWildcardMulti
}

// MatchesSuffix checks if the given path's suffix matches this pattern.
// Supports wildcards:
//   - "*" matches any number of path elements (zero or more)
//   - "**" matches any number of path elements (zero or more)
//
// Example patterns:
//   - ["A", "B"] matches paths ending with [..., "A", "B"]
//   - ["*", "B"] matches paths ending with "B" (with any elements before)
//   - ["**", "B"] matches any path ending with "B"
//   - ["A", "**", "B"] matches paths with "A", then any elements, then "B" at the end
func (p PathPattern) MatchesSuffix(path []string) bool {
	if len(p) == 0 {
		return true
	}
	return matchPatternSuffix(p, path)
}

// matchPatternSuffix implements suffix matching with wildcards using dynamic programming.
// Returns true if the pattern matches a suffix of the path.
func matchPatternSuffix(pattern, path []string) bool {
	// For suffix matching, we try to match the pattern against increasingly larger suffixes
	// of the path, starting from the smallest possible suffix.

	// First, find the minimum path length needed (count non-wildcard elements)
	minLen := 0
	for _, elem := range pattern {
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
		if matchPattern(pattern, suffix) {
			return true
		}
	}
	return false
}

// matchPattern checks if the pattern exactly matches the entire path (not suffix).
func matchPattern(pattern, path []string) bool {
	return matchPatternDP(pattern, path)
}

// matchPatternDP uses dynamic programming for pattern matching with wildcards.
// dp[i][j] = true if pattern[0:i] matches path[0:j]
// Both "*" and "**" match zero or more elements.
func matchPatternDP(pattern, path []string) bool {
	pLen := len(pattern)
	sLen := len(path)

	// dp[i][j] represents whether pattern[0:i] matches path[0:j]
	dp := make([][]bool, pLen+1)
	for i := range dp {
		dp[i] = make([]bool, sLen+1)
	}

	// Empty pattern matches empty path
	dp[0][0] = true

	// Handle patterns starting with wildcards (can match empty)
	for i := 1; i <= pLen; i++ {
		if IsWildcard(pattern[i-1]) {
			dp[i][0] = dp[i-1][0]
		} else {
			break
		}
	}

	for i := 1; i <= pLen; i++ {
		for j := 1; j <= sLen; j++ {
			if IsWildcard(pattern[i-1]) {
				// Both * and ** can match zero elements (dp[i-1][j]) or one+ elements (dp[i][j-1])
				dp[i][j] = dp[i-1][j] || dp[i][j-1]
			} else {
				// Literal match
				dp[i][j] = dp[i-1][j-1] && pattern[i-1] == path[j-1]
			}
		}
	}

	return dp[pLen][sLen]
}

// ContainsWildcard returns true if the pattern contains any wildcard (* or **).
func (p PathPattern) ContainsWildcard() bool {
	for _, elem := range p {
		if IsWildcard(elem) {
			return true
		}
	}
	return false
}

// MinLength returns the minimum number of path elements this pattern can match.
// Wildcards don't contribute to the minimum length since they can match zero elements.
func (p PathPattern) MinLength() int {
	count := 0
	for _, elem := range p {
		if !IsWildcard(elem) {
			count++
		}
	}
	return count
}

type VEXRuleDTO struct {
	// Composite key fields
	AssetID         uuid.UUID `json:"assetId"`
	CVEID           string    `json:"cveId"`
	PathPatternHash string    `json:"pathPatternHash"`
	VexSource       string    `json:"vexSource"`

	// Rule data
	Justification           string                      `json:"justification"`
	MechanicalJustification MechanicalJustificationType `json:"mechanicalJustification"`
	EventType               VulnEventType               `json:"eventType"`
	PathPattern             PathPattern                 `json:"pathPattern"`
	CreatedByID             string                      `json:"createdById"`
	CreatedAt               string                      `json:"createdAt"`
	UpdatedAt               string                      `json:"updatedAt"`
}
