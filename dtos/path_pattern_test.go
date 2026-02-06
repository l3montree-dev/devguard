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

	"github.com/l3montree-dev/devguard/normalize"
	"github.com/stretchr/testify/assert"
)

func TestIsWildcard(t *testing.T) {
	tests := []struct {
		name     string
		elem     string
		expected bool
	}{
		{"single wildcard", "*", true},
		{"multi wildcard", "**", false},
		{"literal A", "A", false},
		{"literal pkg:npm/foo", "pkg:npm/foo@1.0.0", false},
		{"empty string", "", false},
		{"triple star", "***", false},
		{"ROOT is wildcard", normalize.GraphRootNodeID, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, IsWildcard(tt.elem))
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
		{"only wildcard", PathPattern{"*"}, true},
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

func TestRootPathPattern(t *testing.T) {
	tests := []struct {
		name     string
		pattern  PathPattern
		path     []string
		expected bool
	}{
		{"ROOT matches ROOT", PathPattern{normalize.GraphRootNodeID}, []string{normalize.GraphRootNodeID}, true},
		{"ROOT matches any path with ROOT at end", PathPattern{normalize.GraphRootNodeID}, []string{"A", "B", normalize.GraphRootNodeID}, true},
		{"ROOT DOES match path without ROOT", PathPattern{normalize.GraphRootNodeID}, []string{"A", "B", "C"}, true},
		{"ROOT does not lead to all paths matching", PathPattern{normalize.GraphRootNodeID, "X"}, []string{"A", "B", "C"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.pattern.MatchesSuffix(tt.path))
		})
	}
}

func TestPathPattern_MatchesSuffix_Wildcard(t *testing.T) {
	tests := []struct {
		name     string
		pattern  PathPattern
		path     []string
		expected bool
	}{
		// Single wildcard (*) matches zero or more elements
		{"* matches single element", PathPattern{"*"}, []string{"A"}, true},
		{"* matches multiple elements", PathPattern{"*"}, []string{"A", "B", "C"}, true},
		{"* matches empty path", PathPattern{"*"}, []string{}, true},

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

		// Multiple wildcards
		{"* * matches anything", PathPattern{"*", "*"}, []string{"A", "B", "C"}, true},
		{"* A * matches X A Y", PathPattern{"*", "A", "*"}, []string{"X", "A", "Y"}, true},
		{"* A * matches A (zero on both sides)", PathPattern{"*", "A", "*"}, []string{"A"}, true},
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
			PathPattern{"*", "pkg:npm/vulnerable@1.0.0"},
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
			PathPattern{"*", "pkg:npm/vulnerable@1.0.0"},
			[]string{"pkg:npm/app@1.0.0", "pkg:npm/lodash@4.17.0", "pkg:npm/vulnerable@1.0.0"},
			true,
		},
		{
			"no match different root",
			PathPattern{"pkg:npm/other@1.0.0", "*", "pkg:npm/vulnerable@1.0.0"},
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
