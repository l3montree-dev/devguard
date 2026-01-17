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

package normalize

import (
	"testing"

	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
)

func TestBeautifyPURL(t *testing.T) {
	t.Run("empty String should also return an empty string back", func(t *testing.T) {
		inputString := ""
		result, _ := BeautifyPURL(inputString)
		assert.Equal(t, "", result)
	})
	t.Run("invalid purl format should also be returned unchanged", func(t *testing.T) {
		inputString := "this is definitely not a valid purl"
		result, _ := BeautifyPURL(inputString)
		assert.Equal(t, inputString, result)
	})
	t.Run("should return only the namespace and the name of a valid purl and cut the rest", func(t *testing.T) {
		inputString := "pkg:npm/@ory/integrations@v0.0.1"
		result, _ := BeautifyPURL(inputString)
		assert.Equal(t, "@ory/integrations", result)
	})
	t.Run("should return no leading slash if the namespace is empty", func(t *testing.T) {
		inputString := "pkg:npm/integrations@v0.0.1"
		result, _ := BeautifyPURL(inputString)
		assert.Equal(t, "integrations", result)
	})
}

func TestParsePurlForMatching(t *testing.T) {
	t.Run("npm package should use semantic versioning", func(t *testing.T) {
		p, _ := packageurl.FromString("pkg:npm/next@15.4.5")
		ctx := ParsePurlForMatching(p)
		assert.Equal(t, SemanticVersionString, ctx.HowToInterpretVersionString)
	})

	t.Run("debian package without epoch should use version as-is", func(t *testing.T) {
		p, _ := packageurl.FromString("pkg:deb/debian/git@2.47.3-0+deb13u1?arch=amd64")
		ctx := ParsePurlForMatching(p)
		assert.Equal(t, EcosystemSpecificVersion, ctx.HowToInterpretVersionString)
		assert.Equal(t, "2.47.3-0+deb13u1", ctx.NormalizedVersion)
	})

	t.Run("debian package with epoch qualifier should prepend epoch to version", func(t *testing.T) {
		p, _ := packageurl.FromString("pkg:deb/debian/git@2.47.3-0+deb13u1?arch=amd64&epoch=1")
		ctx := ParsePurlForMatching(p)
		assert.Equal(t, EcosystemSpecificVersion, ctx.HowToInterpretVersionString)
		assert.Equal(t, "1:2.47.3-0+deb13u1", ctx.NormalizedVersion)
	})

	t.Run("debian package with epoch 0 should prepend epoch to version", func(t *testing.T) {
		p, _ := packageurl.FromString("pkg:deb/debian/curl@8.0.0-1?epoch=0")
		ctx := ParsePurlForMatching(p)
		assert.Equal(t, EcosystemSpecificVersion, ctx.HowToInterpretVersionString)
		assert.Equal(t, "0:8.0.0-1", ctx.NormalizedVersion)
	})

	t.Run("rpm package should not be affected by epoch qualifier", func(t *testing.T) {
		p, _ := packageurl.FromString("pkg:rpm/centos/bash@5.0.17-2.el8?arch=x86_64&epoch=1")
		ctx := ParsePurlForMatching(p)
		assert.Equal(t, EcosystemSpecificVersion, ctx.HowToInterpretVersionString)
		// RPM epoch handling is different - not implemented here yet
		assert.Equal(t, "5.0.17-2.el8", ctx.NormalizedVersion)
	})
}
