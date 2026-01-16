package normalize

import (
	"testing"

	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
)

func TestApplyToPurl(t *testing.T) {
	t.Run("debian package - libc6 to glibc", func(t *testing.T) {
		purl, _ := packageurl.FromString("pkg:deb/debian/libc6@2.31-1")

		result := applyPackageAliasToPurl(purl)

		assert.Equal(t, "glibc", result.Name)
		assert.Equal(t, "2.31-1", result.Version)
		assert.Equal(t, "deb", result.Type)
	})

	t.Run("debian package - libssl3 to openssl", func(t *testing.T) {
		purl, _ := packageurl.FromString("pkg:deb/debian/libssl3@3.0.0")

		result := applyPackageAliasToPurl(purl)

		mappings := loadPackageMappings()
		if expectedSource, exists := mappings["debian"]["libssl3"]; exists {
			assert.Equal(t, expectedSource, result.Name)
		} else {
			assert.Equal(t, "libssl3", result.Name)
		}
	})

	t.Run("alpine package - musl mapping", func(t *testing.T) {
		purl, _ := packageurl.FromString("pkg:apk/alpine/musl@1.2.3")

		result := applyPackageAliasToPurl(purl)

		mappings := loadPackageMappings()
		if expectedSource, exists := mappings["alpine"]["musl"]; exists {
			assert.Equal(t, expectedSource, result.Name)
		} else {
			assert.Equal(t, "musl", result.Name)
		}
	})

	t.Run("debian package not in mapping - unchanged", func(t *testing.T) {
		purl, _ := packageurl.FromString("pkg:deb/debian/unknown-package@1.0.0")

		result := applyPackageAliasToPurl(purl)

		assert.Equal(t, "unknown-package", result.Name)
	})

	t.Run("npm package - ignored", func(t *testing.T) {
		purl, _ := packageurl.FromString("pkg:npm/express@4.18.0")

		result := applyPackageAliasToPurl(purl)

		assert.Equal(t, "express", result.Name)
		assert.Equal(t, "npm", result.Type)
	})

	t.Run("rpm package - ignored", func(t *testing.T) {
		purl, _ := packageurl.FromString("pkg:rpm/redhat/glibc@2.34")

		result := applyPackageAliasToPurl(purl)

		assert.Equal(t, "glibc", result.Name)
		assert.Equal(t, "rpm", result.Type)
	})
}

func TestLoadPackageMappings(t *testing.T) {
	t.Run("loads embedded mappings successfully", func(t *testing.T) {
		mappings := loadPackageMappings()

		assert.NotNil(t, mappings)
		assert.NotNil(t, mappings["debian"])
		assert.NotNil(t, mappings["alpine"])

		// Check that libc6 maps to glibc in the embedded file
		assert.Equal(t, "glibc", mappings["debian"]["libc6"])
	})
}
