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

package dependencyfirewall

import (
	"testing"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/stretchr/testify/assert"
)

func strPtr(s string) *string { return &s }

func TestEcosystemFromString(t *testing.T) {
	cases := []struct {
		name     string
		expected ecosystem
	}{
		{"npm", npmEcosystem{}},
		{"pypi", pypiEcosystem{}},
		{"golang", goEcosystem{}},
		{"oci", ociEcosystem{}},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, EcosystemFromString(tt.name))
		})
	}

	assert.Nil(t, EcosystemFromString("unknown"))
}

func TestSemverMatchesVersion(t *testing.T) {
	cases := []struct {
		name     string
		comp     models.MaliciousAffectedComponent
		version  string
		expected bool
	}{
		{
			name:     "affects all versions",
			comp:     models.MaliciousAffectedComponent{},
			version:  "1.0.0",
			expected: true,
		},
		{
			name:     "exact version match",
			comp:     models.MaliciousAffectedComponent{Version: strPtr("1.0.0")},
			version:  "1.0.0",
			expected: true,
		},
		{
			name:     "exact version mismatch",
			comp:     models.MaliciousAffectedComponent{Version: strPtr("1.0.0")},
			version:  "1.0.1",
			expected: false,
		},
		{
			name:     "version within introduced/fixed range",
			comp:     models.MaliciousAffectedComponent{SemverIntroduced: strPtr("1.0.0"), SemverFixed: strPtr("2.0.0")},
			version:  "1.5.0",
			expected: true,
		},
		{
			name:     "version before introduced",
			comp:     models.MaliciousAffectedComponent{SemverIntroduced: strPtr("1.0.0"), SemverFixed: strPtr("2.0.0")},
			version:  "0.9.0",
			expected: false,
		},
		{
			name:     "version at or after fixed",
			comp:     models.MaliciousAffectedComponent{SemverIntroduced: strPtr("1.0.0"), SemverFixed: strPtr("2.0.0")},
			version:  "2.0.0",
			expected: false,
		},
		{
			name:     "unparsable requested version is treated as affected",
			comp:     models.MaliciousAffectedComponent{SemverIntroduced: strPtr("1.0.0"), SemverFixed: strPtr("2.0.0")},
			version:  "not-a-version-!!!",
			expected: true,
		},
		{
			name:     "v-prefixed exact version matches its plain equivalent",
			comp:     models.MaliciousAffectedComponent{Version: strPtr("v1.0.0")},
			version:  "1.0.0",
			expected: true,
		},
		{

			name:     "empty requested version against an exact version rule is inconclusive, not a match",
			comp:     models.MaliciousAffectedComponent{Version: strPtr("1.0.0")},
			version:  "",
			expected: false,
		},
		{
			name:     "empty requested version against a range rule is treated as affected to be safe",
			comp:     models.MaliciousAffectedComponent{SemverIntroduced: strPtr("1.0.0"), SemverFixed: strPtr("2.0.0")},
			version:  "",
			expected: true,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, semverMatchesVersion(tt.comp, tt.version))
		})
	}
}

func TestPypiMatchesVersion(t *testing.T) {
	cases := []struct {
		name     string
		comp     models.MaliciousAffectedComponent
		version  string
		expected bool
	}{
		{
			name:     "affects all versions",
			comp:     models.MaliciousAffectedComponent{},
			version:  "1.0.0",
			expected: true,
		},
		{
			name:     "exact pep440 version match",
			comp:     models.MaliciousAffectedComponent{Version: strPtr("1.0.0")},
			version:  "1.0.0",
			expected: true,
		},
		{
			name:     "exact pep440 version match with normalization",
			comp:     models.MaliciousAffectedComponent{Version: strPtr("1.0")},
			version:  "1.0.0",
			expected: true,
		},
		{
			name:     "exact pep440 version mismatch",
			comp:     models.MaliciousAffectedComponent{Version: strPtr("1.0.0")},
			version:  "1.0.1",
			expected: false,
		},
		{
			name:     "version within introduced/fixed range",
			comp:     models.MaliciousAffectedComponent{SemverIntroduced: strPtr("1.0.0"), SemverFixed: strPtr("2.0.0")},
			version:  "1.5.0",
			expected: true,
		},
		{
			name:     "pep440 pre-release before introduced",
			comp:     models.MaliciousAffectedComponent{SemverIntroduced: strPtr("1.0.0"), SemverFixed: strPtr("2.0.0")},
			version:  "0.9.0",
			expected: false,
		},
		{
			name:     "version at fixed boundary is not affected",
			comp:     models.MaliciousAffectedComponent{SemverIntroduced: strPtr("1.0.0"), SemverFixed: strPtr("2.0.0")},
			version:  "2.0.0",
			expected: false,
		},
		{
			name:     "unparsable requested version is treated as affected",
			comp:     models.MaliciousAffectedComponent{SemverIntroduced: strPtr("1.0.0"), SemverFixed: strPtr("2.0.0")},
			version:  "not-a-version-!!!",
			expected: true,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, pypi.MatchesVersion(tt.comp, tt.version))
		})
	}
}

// TestPypiMatchesVersionPEP440EquivalentSpellings verifies that version equality
// is computed semantically (per PEP 440), not textually. See:
// https://packaging.python.org/en/latest/specifications/version-specifiers/#version-equality
func TestPypiMatchesVersionPEP440EquivalentSpellings(t *testing.T) {
	// All of these strings denote the exact same PEP 440 version as "1.0".
	equivalentSpellings := []string{
		"1.0",
		"1.0.0",
		"1.0.0.0",
		"1.0.0.0.0",
		"01.0",
		"1.00",
		"v1.0",
		"V1.0",
		"0!1.0",
	}

	for _, spelling := range equivalentSpellings {
		t.Run("stored=1.0/requested="+spelling, func(t *testing.T) {
			comp := models.MaliciousAffectedComponent{Version: strPtr("1.0")}
			assert.True(t, pypi.MatchesVersion(comp, spelling),
				"expected %q to be recognized as equal to the flagged version 1.0", spelling)
		})

		t.Run("stored="+spelling+"/requested=1.0", func(t *testing.T) {
			comp := models.MaliciousAffectedComponent{Version: strPtr(spelling)}
			assert.True(t, pypi.MatchesVersion(comp, "1.0"),
				"expected flagged version %q to be recognized as equal to requested version 1.0", spelling)
		})
	}

	// A version that is genuinely different must not match.
	comp := models.MaliciousAffectedComponent{Version: strPtr("1.0")}
	assert.False(t, pypi.MatchesVersion(comp, "1.0.1"))
	assert.False(t, pypi.MatchesVersion(comp, "2.0"))
}

func TestPypiMatchesVersionRangeIsHalfOpen(t *testing.T) {
	comp := models.MaliciousAffectedComponent{
		SemverIntroduced: strPtr("1.0.0"),
		SemverFixed:      strPtr("2.0.0"),
	}

	cases := []struct {
		version  string
		expected bool
	}{
		{"1.0.0", true},    // introduced boundary: affected
		{"1.0.0.0", true},  // equivalent spelling of the introduced boundary: affected
		{"1.5.0", true},    // strictly inside the range: affected
		{"1.9.9", true},    // just before fixed: affected
		{"2.0.0", false},   // fixed boundary: already patched
		{"2.0.0.0", false}, // equivalent spelling of the fixed boundary: already patched
		{"2.1.0", false},   // past fixed: already patched
		{"0.9.0", false},   // before introduced: not yet affected
	}

	for _, tt := range cases {
		t.Run(tt.version, func(t *testing.T) {
			assert.Equal(t, tt.expected, pypi.MatchesVersion(comp, tt.version))
		})
	}
}

func TestPypiMatchesVersionPreAndPostReleases(t *testing.T) {
	comp := models.MaliciousAffectedComponent{
		SemverIntroduced: strPtr("1.0.0"),
		SemverFixed:      strPtr("2.0.0"),
	}

	cases := []struct {
		name     string
		version  string
		expected bool
	}{
		{"pre-release before introduced is not affected", "1.0.0a1", false},
		{"pre-release of fixed version is not yet patched, still affected", "2.0.0rc1", true},
		{"post-release of fixed version is patched", "2.0.0.post1", false},
		{"post-release within range is affected", "1.5.0.post1", true},
		{"local version segment within range is affected", "1.5.0+build1", true},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, pypi.MatchesVersion(comp, tt.version))
		})
	}
}
