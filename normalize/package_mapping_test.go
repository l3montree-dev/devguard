package normalize

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
)

func TestApplyPackageAlias(t *testing.T) {

	t.Run("debian package - libc6 to glibc", func(t *testing.T) {
		component := &cdx.Component{
			BOMRef:     "pkg:deb/debian/libc6@2.31-1",
			Name:       "libc6",
			Version:    "2.31-1",
			PackageURL: "pkg:deb/debian/libc6@2.31-1",
			Type:       cdx.ComponentTypeLibrary,
		}

		result := applyPackageAlias(component)

		assert.Equal(t, "pkg:deb/debian/glibc@2.31-1", result.PackageURL)
		assert.Equal(t, "libc6", result.Name) // Name should not change
	})

	t.Run("debian package - libssl3 to openssl", func(t *testing.T) {
		component := &cdx.Component{
			BOMRef:     "pkg:deb/debian/libssl3@3.0.0",
			Name:       "libssl3",
			Version:    "3.0.0",
			PackageURL: "pkg:deb/debian/libssl3@3.0.0",
			Type:       cdx.ComponentTypeLibrary,
		}

		result := applyPackageAlias(component)

		// Check if mapping exists in the embedded file
		mappings := loadPackageMappings()
		if expectedSource, exists := mappings["debian"]["libssl3"]; exists {
			assert.Contains(t, result.PackageURL, expectedSource)
		} else {
			// If not in mapping, should remain unchanged
			assert.Equal(t, "pkg:deb/debian/libssl3@3.0.0", result.PackageURL)
		}
	})

	t.Run("alpine package - musl mapping", func(t *testing.T) {
		component := &cdx.Component{
			BOMRef:     "pkg:apk/alpine/musl@1.2.3",
			Name:       "musl",
			Version:    "1.2.3",
			PackageURL: "pkg:apk/alpine/musl@1.2.3",
			Type:       cdx.ComponentTypeLibrary,
		}

		result := applyPackageAlias(component)

		// Check if mapping exists in the embedded file
		mappings := loadPackageMappings()
		if expectedSource, exists := mappings["alpine"]["musl"]; exists {
			assert.Contains(t, result.PackageURL, expectedSource)
		} else {
			assert.Equal(t, "pkg:apk/alpine/musl@1.2.3", result.PackageURL)
		}
	})

	t.Run("debian package not in mapping - unchanged", func(t *testing.T) {
		component := &cdx.Component{
			BOMRef:     "pkg:deb/debian/unknown-package@1.0.0",
			Name:       "unknown-package",
			Version:    "1.0.0",
			PackageURL: "pkg:deb/debian/unknown-package@1.0.0",
			Type:       cdx.ComponentTypeLibrary,
		}

		result := applyPackageAlias(component)

		assert.Equal(t, "pkg:deb/debian/unknown-package@1.0.0", result.PackageURL)
	})

	t.Run("npm package - ignored", func(t *testing.T) {
		component := &cdx.Component{
			BOMRef:     "pkg:npm/express@4.18.0",
			Name:       "express",
			Version:    "4.18.0",
			PackageURL: "pkg:npm/express@4.18.0",
			Type:       cdx.ComponentTypeLibrary,
		}

		result := applyPackageAlias(component)

		assert.Equal(t, "pkg:npm/express@4.18.0", result.PackageURL)
	})

	t.Run("rpm package - ignored", func(t *testing.T) {
		component := &cdx.Component{
			BOMRef:     "pkg:rpm/redhat/glibc@2.34",
			Name:       "glibc",
			Version:    "2.34",
			PackageURL: "pkg:rpm/redhat/glibc@2.34",
			Type:       cdx.ComponentTypeLibrary,
		}

		result := applyPackageAlias(component)

		assert.Equal(t, "pkg:rpm/redhat/glibc@2.34", result.PackageURL)
	})

	t.Run("empty package url", func(t *testing.T) {
		component := &cdx.Component{
			BOMRef:     "some-ref",
			Name:       "some-component",
			Version:    "1.0.0",
			PackageURL: "",
			Type:       cdx.ComponentTypeLibrary,
		}

		result := applyPackageAlias(component)

		assert.Equal(t, "", result.PackageURL)
	})

	t.Run("invalid purl", func(t *testing.T) {
		component := &cdx.Component{
			BOMRef:     "invalid-purl",
			Name:       "test",
			Version:    "1.0.0",
			PackageURL: "not-a-valid-purl",
			Type:       cdx.ComponentTypeLibrary,
		}

		result := applyPackageAlias(component)

		assert.Equal(t, "not-a-valid-purl", result.PackageURL)
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

func TestApplyPackageAliasIntegration(t *testing.T) {
	t.Run("integration with newCdxBomNode", func(t *testing.T) {
		component := &cdx.Component{
			BOMRef:     "pkg:deb/debian/libc6@2.31-1",
			Name:       "libc6",
			Version:    "2.31-1",
			PackageURL: "pkg:deb/debian/libc6@2.31-1",
			Type:       cdx.ComponentTypeLibrary,
		}

		// This calls applyPackageAlias internally
		node := newCdxBomNode(component)

		assert.Contains(t, node.PackageURL, "glibc")
		assert.Equal(t, NodeTypeComponent, node.nodeType)
	})
}
