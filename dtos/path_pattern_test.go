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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsWildcard(t *testing.T) {
	tests := []struct {
		name     string
		elem     string
		expected bool
	}{
		{"single wildcard", "*", true},
		{"multi wildcard", "**", true},
		{"literal A", "A", false},
		{"literal pkg:npm/foo", "pkg:npm/foo@1.0.0", false},
		{"empty string", "", false},
		{"triple star", "***", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, IsWildcard(tt.elem))
		})
	}
}

func TestPathPattern_MinLength(t *testing.T) {
	tests := []struct {
		name     string
		pattern  PathPattern
		expected int
	}{
		{"empty pattern", PathPattern{}, 0},
		{"all literals", PathPattern{"A", "B", "C"}, 3},
		{"single wildcard only", PathPattern{"*"}, 0},
		{"multi wildcard only", PathPattern{"**"}, 0},
		{"mixed wildcards and literals", PathPattern{"*", "A", "**", "B"}, 2},
		{"wildcards at start", PathPattern{"**", "A", "B"}, 2},
		{"wildcards at end", PathPattern{"A", "B", "*"}, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.pattern.MinLength())
		})
	}
}

func TestPathPattern_ContainsWildcard(t *testing.T) {
	tests := []struct {
		name     string
		pattern  PathPattern
		expected bool
	}{
		{"empty pattern", PathPattern{}, false},
		{"no wildcards", PathPattern{"A", "B", "C"}, false},
		{"single wildcard", PathPattern{"A", "*", "C"}, true},
		{"multi wildcard", PathPattern{"A", "**", "C"}, true},
		{"only wildcards", PathPattern{"*", "**"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.pattern.ContainsWildcard())
		})
	}
}

func TestPathPattern_MatchesSuffix_ExactMatch(t *testing.T) {
	tests := []struct {
		name     string
		pattern  PathPattern
		path     []string
		expected bool
	}{
		// Empty pattern matches everything
		{"empty pattern matches empty path", PathPattern{}, []string{}, true},
		{"empty pattern matches any path", PathPattern{}, []string{"A", "B", "C"}, true},

		// Exact suffix match (no wildcards)
		{"exact match single element", PathPattern{"C"}, []string{"A", "B", "C"}, true},
		{"exact match two elements", PathPattern{"B", "C"}, []string{"A", "B", "C"}, true},
		{"exact match full path", PathPattern{"A", "B", "C"}, []string{"A", "B", "C"}, true},
		{"no match wrong suffix", PathPattern{"X", "Y"}, []string{"A", "B", "C"}, false},
		{"no match pattern longer than path", PathPattern{"A", "B", "C", "D"}, []string{"A", "B", "C"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.pattern.MatchesSuffix(tt.path))
		})
	}
}

func TestPathPattern_MatchesSuffix_SingleWildcard(t *testing.T) {
	tests := []struct {
		name     string
		pattern  PathPattern
		path     []string
		expected bool
	}{
		// Single wildcard (*) matches zero or more elements
		{"* matches empty path", PathPattern{"*"}, []string{}, true},
		{"* matches single element", PathPattern{"*"}, []string{"A"}, true},
		{"* matches multiple elements", PathPattern{"*"}, []string{"A", "B", "C"}, true},

		// Wildcard at start
		{"* then literal matches suffix", PathPattern{"*", "C"}, []string{"A", "B", "C"}, true},
		{"* then literal matches just literal", PathPattern{"*", "C"}, []string{"C"}, true},
		{"* then literal no match", PathPattern{"*", "X"}, []string{"A", "B", "C"}, false},

		// Wildcard at end
		{"literal then * matches", PathPattern{"B", "*"}, []string{"A", "B", "C"}, true},
		{"literal then * matches just literal", PathPattern{"C", "*"}, []string{"A", "B", "C"}, true},

		// Wildcard in middle
		{"A * C matches A B C", PathPattern{"A", "*", "C"}, []string{"A", "B", "C"}, true},
		{"A * C matches A C (zero elements)", PathPattern{"A", "*", "C"}, []string{"A", "C"}, true},
		{"A * C matches A X Y Z C", PathPattern{"A", "*", "C"}, []string{"A", "X", "Y", "Z", "C"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.pattern.MatchesSuffix(tt.path))
		})
	}
}

func TestPathPattern_MatchesSuffix_MultiWildcard(t *testing.T) {
	tests := []struct {
		name     string
		pattern  PathPattern
		path     []string
		expected bool
	}{
		// Multi wildcard (**) matches zero or more elements
		{"** matches empty path", PathPattern{"**"}, []string{}, true},
		{"** matches single element", PathPattern{"**"}, []string{"A"}, true},
		{"** matches multiple elements", PathPattern{"**"}, []string{"A", "B", "C"}, true},

		// ** at start
		{"** then literal matches any path ending with literal", PathPattern{"**", "C"}, []string{"A", "B", "C"}, true},
		{"** then literal matches just literal", PathPattern{"**", "C"}, []string{"C"}, true},

		// ** at end
		{"literal then ** matches", PathPattern{"A", "**"}, []string{"A", "B", "C"}, true},

		// ** in middle
		{"A ** C matches A B C", PathPattern{"A", "**", "C"}, []string{"A", "B", "C"}, true},
		{"A ** C matches A C", PathPattern{"A", "**", "C"}, []string{"A", "C"}, true},
		{"A ** C matches A X Y Z C", PathPattern{"A", "**", "C"}, []string{"A", "X", "Y", "Z", "C"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.pattern.MatchesSuffix(tt.path))
		})
	}
}

func TestPathPattern_MatchesSuffix_MultipleWildcards(t *testing.T) {
	tests := []struct {
		name     string
		pattern  PathPattern
		path     []string
		expected bool
	}{
		// Multiple wildcards
		{"* * matches anything", PathPattern{"*", "*"}, []string{"A", "B", "C"}, true},
		{"** ** matches anything", PathPattern{"**", "**"}, []string{"A", "B", "C"}, true},
		{"* A * matches X A Y", PathPattern{"*", "A", "*"}, []string{"X", "A", "Y"}, true},
		{"* A * matches A (zero on both sides)", PathPattern{"*", "A", "*"}, []string{"A"}, true},

		// Complex patterns
		{"** A * B matches X Y A Z B", PathPattern{"**", "A", "*", "B"}, []string{"X", "Y", "A", "Z", "B"}, true},
		{"** A * B matches A B (zero elements for both wildcards)", PathPattern{"**", "A", "*", "B"}, []string{"A", "B"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.pattern.MatchesSuffix(tt.path))
		})
	}
}

func TestPathPattern_MatchesSuffix_RealWorldExamples(t *testing.T) {
	// Simulating real vulnerability paths like:
	// ["pkg:npm/app@1.0.0", "pkg:npm/lodash@4.17.0", "pkg:npm/vulnerable@1.0.0"]
	tests := []struct {
		name     string
		pattern  PathPattern
		path     []string
		expected bool
	}{
		{
			"match specific vulnerable package at end",
			PathPattern{"pkg:npm/vulnerable@1.0.0"},
			[]string{"pkg:npm/app@1.0.0", "pkg:npm/lodash@4.17.0", "pkg:npm/vulnerable@1.0.0"},
			true,
		},
		{
			"match any path to vulnerable package",
			PathPattern{"**", "pkg:npm/vulnerable@1.0.0"},
			[]string{"pkg:npm/app@1.0.0", "pkg:npm/lodash@4.17.0", "pkg:npm/vulnerable@1.0.0"},
			true,
		},
		{
			"match lodash leading to vulnerable",
			PathPattern{"pkg:npm/lodash@4.17.0", "pkg:npm/vulnerable@1.0.0"},
			[]string{"pkg:npm/app@1.0.0", "pkg:npm/lodash@4.17.0", "pkg:npm/vulnerable@1.0.0"},
			true,
		},
		{
			"match any intermediate deps to vulnerable",
			PathPattern{"pkg:npm/app@1.0.0", "*", "pkg:npm/vulnerable@1.0.0"},
			[]string{"pkg:npm/app@1.0.0", "pkg:npm/lodash@4.17.0", "pkg:npm/vulnerable@1.0.0"},
			true,
		},
		{
			"no match different root",
			PathPattern{"pkg:npm/other@1.0.0", "**", "pkg:npm/vulnerable@1.0.0"},
			[]string{"pkg:npm/app@1.0.0", "pkg:npm/lodash@4.17.0", "pkg:npm/vulnerable@1.0.0"},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.pattern.MatchesSuffix(tt.path))
		})
	}
}

func TestMatchPatternDP(t *testing.T) {
	// Test the exact matching function directly
	tests := []struct {
		name     string
		pattern  []string
		path     []string
		expected bool
	}{
		{"empty both", []string{}, []string{}, true},
		{"empty pattern non-empty path", []string{}, []string{"A"}, false},
		{"non-empty pattern empty path", []string{"A"}, []string{}, false},
		{"wildcard empty path", []string{"*"}, []string{}, true},
		{"exact match", []string{"A", "B"}, []string{"A", "B"}, true},
		{"no match", []string{"A", "B"}, []string{"A", "C"}, false},
		{"wildcard middle", []string{"A", "*", "C"}, []string{"A", "B", "C"}, true},
		{"wildcard matches zero", []string{"A", "*", "B"}, []string{"A", "B"}, true},
		{"wildcard matches multiple", []string{"A", "*", "C"}, []string{"A", "X", "Y", "C"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, matchPatternDP(tt.pattern, tt.path))
		})
	}
}
