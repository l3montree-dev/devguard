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

	t.Run("debian package with epoch already in version should use version as-is", func(t *testing.T) {
		p, _ := packageurl.FromString("pkg:deb/debian/zlib@1:1.3.dfsg+really1.3.1-1+b1")
		ctx := ParsePurlForMatching(p)
		assert.Equal(t, EcosystemSpecificVersion, ctx.HowToInterpretVersionString)
		assert.Equal(t, "1:1.3.dfsg+really1.3.1-1+b1", ctx.NormalizedVersion)
	})

	t.Run("debian package with epoch qualifier should prepend epoch to version", func(t *testing.T) {
		p, _ := packageurl.FromString("pkg:deb/debian/git@2.47.3-0+deb13u1?arch=amd64&epoch=1")
		ctx := ParsePurlForMatching(p)
		assert.Equal(t, EcosystemSpecificVersion, ctx.HowToInterpretVersionString)
		assert.Equal(t, "1:2.47.3-0+deb13u1", ctx.NormalizedVersion)
	})

	t.Run("rpm package with epoch qualifier should prepend epoch to version", func(t *testing.T) {
		p, _ := packageurl.FromString("pkg:rpm/centos/bash@5.0.17-2.el8?arch=x86_64&epoch=1")
		ctx := ParsePurlForMatching(p)
		assert.Equal(t, EcosystemSpecificVersion, ctx.HowToInterpretVersionString)
		// RPM epoch handling is different - not implemented here yet
		assert.Equal(t, "1:5.0.17-2.el8", ctx.NormalizedVersion)
	})

	t.Run("rpm package without epoch qualifier should use version as-is", func(t *testing.T) {
		p, _ := packageurl.FromString("pkg:rpm/centos/bash@5.0.17-2.el8?arch=x86_64")
		ctx := ParsePurlForMatching(p)
		assert.Equal(t, EcosystemSpecificVersion, ctx.HowToInterpretVersionString)
		assert.Equal(t, "5.0.17-2.el8", ctx.NormalizedVersion)
	})

}

func TestAssetName(t *testing.T) {
	t.Run("should return the asset name as-is when it already has 3 parts", func(t *testing.T) {
		name, err := AssetName("org/project/asset")
		assert.NoError(t, err)
		assert.Equal(t, "org/project/asset", name)
	})

	t.Run("should strip projects/assets segments from a full url-shaped name", func(t *testing.T) {
		name, err := AssetName("org/projects/project/assets/asset")
		assert.NoError(t, err)
		assert.Equal(t, "org/project/asset", name)
	})

	t.Run("should error when the name has fewer than 3 parts", func(t *testing.T) {
		_, err := AssetName("org/project")
		assert.Error(t, err)
	})

	t.Run("should error when the name has more than 3 parts but does not match the projects/assets pattern", func(t *testing.T) {
		_, err := AssetName("org/foo/project/bar/asset")
		assert.Error(t, err)
	})

	t.Run("should error when there are too many parts even matching url shape", func(t *testing.T) {
		_, err := AssetName("org/projects/project/assets/asset/extra")
		assert.Error(t, err)
	})
}

func TestOCIPurlMatching(t *testing.T) {
	t.Run("builds a spec-conform purl from an image reference", func(t *testing.T) {
		p := OCIPurlFromImageReference("docker.io/Fake-Org/Malicious-Image")
		assert.Equal(t, "", p.Namespace)
		assert.Equal(t, "malicious-image", p.Name)
		assert.Equal(t, "docker.io/fake-org/malicious-image", p.Qualifiers.Map()["repository_url"])
	})

	t.Run("keeps repository_url in the matching key", func(t *testing.T) {
		p, err := packageurl.FromString("pkg:oci/nginx@sha256:abc?repository_url=https://Docker.io/library/nginx/&tag=latest&arch=amd64")
		assert.NoError(t, err)

		expected := "pkg:oci/nginx?repository_url=docker.io/library/nginx"
		assert.Equal(t, expected, ParsePurlForMatching(p).SearchPurl)
		assert.Equal(t, expected, ToPurlWithoutVersion(p))
	})

	t.Run("storage and lookup produce the same key", func(t *testing.T) {
		stored, err := packageurl.FromString(func() string {
			p := OCIPurlFromImageReference("docker.io/fake-org/malicious-image")
			return p.ToString()
		}())
		assert.NoError(t, err)
		assert.Equal(t, ToPurlWithoutVersion(stored), ParsePurlForMatching(OCIPurlFromImageReference("docker.io/fake-org/malicious-image")).SearchPurl)
	})

	t.Run("images on other registries or paths get a different key", func(t *testing.T) {
		a := ParsePurlForMatching(OCIPurlFromImageReference("docker.io/fake-org/malicious-image")).SearchPurl
		b := ParsePurlForMatching(OCIPurlFromImageReference("ghcr.io/someone/malicious-image")).SearchPurl
		assert.NotEqual(t, a, b)
	})

	t.Run("oci purl without repository_url matches by name", func(t *testing.T) {
		p, err := packageurl.FromString("pkg:oci/nginx@sha256:abc?tag=latest")
		assert.NoError(t, err)
		assert.Equal(t, "pkg:oci/nginx", ParsePurlForMatching(p).SearchPurl)
	})

	t.Run("other types still drop all qualifiers", func(t *testing.T) {
		p, err := packageurl.FromString("pkg:deb/debian/git@2.47.3?arch=amd64&repository_url=example.com")
		assert.NoError(t, err)
		assert.Equal(t, "pkg:deb/debian/git", ToPurlWithoutVersion(p))
	})
}
