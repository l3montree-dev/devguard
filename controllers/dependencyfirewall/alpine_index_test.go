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
	"time"

	"github.com/stretchr/testify/assert"
)

func TestParseAPKIndex(t *testing.T) {
	curl := "C:Q1abc=\nP:curl\nV:8.14.1-r0\nA:x86_64\nt:1700000000"
	musl := "P:musl\nV:1.2.5-r0\nt:1700000100"

	cases := []struct {
		name     string
		content  string
		expected []apkIndexRecord
	}{
		{
			name:    "two records",
			content: curl + "\n\n" + musl + "\n",
			expected: []apkIndexRecord{
				{name: "curl", version: "8.14.1-r0", builtAt: time.Unix(1700000000, 0), raw: curl},
				{name: "musl", version: "1.2.5-r0", builtAt: time.Unix(1700000100, 0), raw: musl},
			},
		},
		{
			name:    "record missing version is skipped",
			content: "P:broken\nt:1700000000\n\n" + musl + "\n",
			expected: []apkIndexRecord{
				{name: "musl", version: "1.2.5-r0", builtAt: time.Unix(1700000100, 0), raw: musl},
			},
		},
		{
			name:    "trailing and repeated blank lines",
			content: curl + "\n\n\n\n" + musl + "\n\n\n",
			expected: []apkIndexRecord{
				{name: "curl", version: "8.14.1-r0", builtAt: time.Unix(1700000000, 0), raw: curl},
				{name: "musl", version: "1.2.5-r0", builtAt: time.Unix(1700000100, 0), raw: musl},
			},
		},
		{
			name:    "unparsable build time keeps record with zero time",
			content: "P:curl\nV:8.14.1-r0\nt:not-a-number\n",
			expected: []apkIndexRecord{
				{name: "curl", version: "8.14.1-r0", raw: "P:curl\nV:8.14.1-r0\nt:not-a-number"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, parseAPKIndex([]byte(tc.content)))
		})
	}
}

func TestFilterAlpineMetadata(t *testing.T) {
	curl := "C:Q1abc=\nP:curl\nV:8.14.1-r0\nt:1700000000"
	jq := "P:jq\nV:1.7.1-r0\nt:1800000000"
	content := []byte(curl + "\n\n" + jq + "\n\n")

	filtered, removed := filterAlpineMetadata(content, func(name, version string, released time.Time) bool {
		return released.Before(time.Unix(1750000000, 0))
	})

	assert.Equal(t, 1, removed)
	assert.Equal(t, curl+"\n\n", string(filtered))
}

func TestAPKIndexRecordFileName(t *testing.T) {
	rec := apkIndexRecord{name: "curl", version: "8.14.1-r0"}
	assert.Equal(t, "curl-8.14.1-r0.apk", rec.fileName())
}
