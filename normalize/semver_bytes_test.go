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
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package normalize

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/mod/semver"
)

var semverBytesCorpus = []string{
	"0.0.0",
	"0.0.1",
	"0.1.0",
	"1.0.0-0",
	"1.0.0-1",
	"1.0.0-2",
	"1.0.0-10",
	"1.0.0-99999999999999999999",
	"1.0.0-0a",
	"1.0.0--",
	"1.0.0-A",
	"1.0.0-Z",
	"1.0.0-a",
	"1.0.0-alpha",
	"1.0.0-alpha.1",
	"1.0.0-alpha.1.1",
	"1.0.0-alpha.2",
	"1.0.0-alpha.10",
	"1.0.0-alpha.beta",
	"1.0.0-alpha-1",
	"1.0.0-alpha1",
	"1.0.0-alpha10",
	"1.0.0-alpha2",
	"1.0.0-beta",
	"1.0.0-beta.2",
	"1.0.0-beta.11",
	"1.0.0-rc.1",
	"1.0.0",
	"1.0.1",
	"1.0.9",
	"1.0.10",
	"1.1.0",
	"1.9.0",
	"1.10.0",
	"2.0.0-1.el9.8",
	"2.0.0",
	"9.0.0",
	"10.0.0",
	"2147483647.0.0",
}

func TestSemverToBytesPreservesPrecedence(t *testing.T) {
	for _, a := range semverBytesCorpus {
		for _, b := range semverBytesCorpus {
			encA, err := SemverToBytes(a)
			assert.NoError(t, err)
			encB, err := SemverToBytes(b)
			assert.NoError(t, err)

			assert.Equal(t, semver.Compare("v"+a, "v"+b), bytes.Compare(encA, encB), "%s <=> %s", a, b)
		}
	}
}

func TestSemverToBytesRoundTrip(t *testing.T) {
	versions := append([]string{"1.0.0+build.1", "1.0.0-rc.1+build-2", "2.0.0+incompatible"}, semverBytesCorpus...)
	for _, v := range versions {
		enc, err := SemverToBytes(v)
		assert.NoError(t, err)
		dec, err := BytesToSemver(enc)
		assert.NoError(t, err)
		assert.Equal(t, v, dec)
	}
}

func TestSemverToBytesBuildMetadataIsTieBreakerOnly(t *testing.T) {
	// build metadata must never change the order relative to other versions
	withMeta, _ := SemverToBytes("1.0.0-rc.1+zzz")
	next, _ := SemverToBytes("1.0.0-rc.2")
	release, _ := SemverToBytes("1.0.0")
	assert.Equal(t, -1, bytes.Compare(withMeta, next))
	assert.Equal(t, -1, bytes.Compare(withMeta, release))

	releaseWithMeta, _ := SemverToBytes("1.0.0+zzz")
	patch, _ := SemverToBytes("1.0.1-0")
	assert.Equal(t, -1, bytes.Compare(releaseWithMeta, patch))
}

func TestSemverToBytesRejectsInvalid(t *testing.T) {
	for _, v := range []string{"", "v1.0.0", "1.0", "01.0.0", "1.0.0-01", "1.0.0-", "1.0.0+", "1.0.0-a..b"} {
		_, err := SemverToBytes(v)
		assert.Error(t, err, v)
	}

	_, err := SemverToBytes("1.0.0-" + strings.Repeat("1", 256))
	assert.Error(t, err)
}

func TestBytesToSemverRejectsGarbage(t *testing.T) {
	for _, enc := range [][]byte{nil, {1, '1'}, {1, '1', 1, '0', 1, '0'}, {1, '1', 1, '0', 1, '0', 0x02, 'a'}, {1, '1', 1, '0', 1, '0', 0x07, 0x00}, {5, '1'}} {
		_, err := BytesToSemver(enc)
		assert.Error(t, err, enc)
	}
}

func TestSemverValueScanRoundTrip(t *testing.T) {
	value, err := Semver("1.0.0-rc.1+build").Value()
	assert.NoError(t, err)

	var scanned Semver
	assert.NoError(t, scanned.Scan(value))
	assert.Equal(t, Semver("1.0.0-rc.1+build"), scanned)

	_, err = Semver("v1.0.0").Value()
	assert.Error(t, err, "invalid versions must not reach the database")
	assert.Error(t, scanned.Scan("1.0.0"), "only bytea values can be scanned")

	var missing *Semver
	assert.Equal(t, "", missing.String())
	assert.Nil(t, missing.StringPtr())
}

func FuzzSemverToBytes(f *testing.F) {
	for _, v := range semverBytesCorpus {
		f.Add(v, "1.0.0")
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		encA, errA := SemverToBytes(a)
		encB, errB := SemverToBytes(b)
		if errA != nil || errB != nil {
			return
		}
		decA, err := BytesToSemver(encA)
		if err != nil || decA != a {
			t.Fatalf("round trip %q -> %q (%v)", a, decA, err)
		}

		want := semver.Compare("v"+a, "v"+b)
		got := bytes.Compare(encA, encB)
		if want != 0 && want != got {
			t.Fatalf("%q <=> %q: semver %d, bytes %d", a, b, want, got)
		}
	})
}
