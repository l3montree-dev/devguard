package normalize_test

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/l3montree-dev/devguard/internal/core/normalize"
	"github.com/stretchr/testify/assert"
)

func TestFromCdxBom(t *testing.T) {
	t.Run("basic component without properties", func(t *testing.T) {
		bom := &cdx.BOM{
			Components: &[]cdx.Component{{
				Name:       "test-component",
				Version:    "1.0.0",
				PackageURL: "pkg:npm/test-component@1.0.0",
				Type:       cdx.ComponentTypeLibrary,
			}},
		}

		result := normalize.FromCdxBom(bom, false)
		component := (*result.GetComponents())[0]

		assert.Equal(t, "test-component", component.Name)
		assert.Equal(t, "1.0.0", component.Version)
		assert.Contains(t, component.PackageURL, "test-component")
	})

	t.Run("component with trivy properties", func(t *testing.T) {
		testCases := []struct {
			name           string
			srcName        string
			srcVersion     string
			pkgID          string
			expectUpdate   bool
			expectContains string
		}{
			{"all properties present", "actual-source-name", "2.1.0", "old-pkg-id", true, "actual-source-name@2.1.0"},
			{"linux srcName ignored", "linux", "2.1.0", "old-pkg-id", false, "old-pkg-id"},
			{"missing srcName", "", "2.1.0", "old-pkg-id", false, "old-pkg-id"},
			{"missing srcVersion", "actual-source-name", "", "old-pkg-id", false, "old-pkg-id"},
			{"missing pkgID", "actual-source-name", "2.1.0", "", false, "old-pkg-id"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				properties := []cdx.Property{}
				if tc.srcName != "" {
					properties = append(properties, cdx.Property{Name: "aquasecurity:trivy:SrcName", Value: tc.srcName})
				}
				if tc.srcVersion != "" {
					properties = append(properties, cdx.Property{Name: "aquasecurity:trivy:SrcVersion", Value: tc.srcVersion})
				}
				if tc.pkgID != "" {
					properties = append(properties, cdx.Property{Name: "aquasecurity:trivy:PkgID", Value: tc.pkgID})
				}

				bom := &cdx.BOM{
					Components: &[]cdx.Component{{
						Name:       "test-component",
						PackageURL: "pkg:npm/old-pkg-id@1.0.0",
						Type:       cdx.ComponentTypeLibrary,
						Properties: &properties,
					}},
				}

				result := normalize.FromCdxBom(bom, false)
				component := (*result.GetComponents())[0]

				assert.Contains(t, component.PackageURL, tc.expectContains)
				if !tc.expectUpdate {
					assert.NotContains(t, component.PackageURL, "actual-source-name@2.1.0")
				}
			})
		}
	})

	t.Run("convertComponentType flag", func(t *testing.T) {
		testCases := []struct {
			name                 string
			convertComponentType bool
			expectedType         cdx.ComponentType
		}{
			{"false - type unchanged", false, cdx.ComponentTypeApplication},
			{"true - type updated", true, cdx.ComponentTypeLibrary},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				bom := &cdx.BOM{
					Components: &[]cdx.Component{{
						Name:       "test-component",
						PackageURL: "pkg:npm/test-component@1.0.0",
						Type:       cdx.ComponentTypeApplication,
					}},
				}

				result := normalize.FromCdxBom(bom, tc.convertComponentType)
				component := (*result.GetComponents())[0]

				assert.Equal(t, tc.expectedType, component.Type)
			})
		}
	})

	t.Run("multiple components", func(t *testing.T) {
		bom := &cdx.BOM{
			Components: &[]cdx.Component{
				{
					Name:       "component-1",
					PackageURL: "pkg:npm/pkg-id-1@1.0.0",
					Properties: &[]cdx.Property{
						{Name: "aquasecurity:trivy:SrcName", Value: "source-name-1"},
						{Name: "aquasecurity:trivy:SrcVersion", Value: "1.0.0"},
						{Name: "aquasecurity:trivy:PkgID", Value: "pkg-id-1"},
					},
				},
				{
					Name:       "component-2",
					PackageURL: "pkg:npm/pkg-id-2@2.0.0",
					Properties: &[]cdx.Property{
						{Name: "aquasecurity:trivy:SrcName", Value: "source-name-2"},
						{Name: "aquasecurity:trivy:SrcVersion", Value: "2.0.0"},
						{Name: "aquasecurity:trivy:PkgID", Value: "pkg-id-2"},
					},
				},
				{
					Name:       "component-3",
					PackageURL: "pkg:npm/component-3@3.0.0",
				},
			},
		}

		result := normalize.FromCdxBom(bom, false)
		components := *result.GetComponents()

		assert.Len(t, components, 3)
		assert.Contains(t, components[0].PackageURL, "source-name-1@1.0.0")
		assert.Contains(t, components[1].PackageURL, "source-name-2@2.0.0")
		assert.Contains(t, components[2].PackageURL, "component-3")
	})

	t.Run("edge cases", func(t *testing.T) {
		t.Run("empty components", func(t *testing.T) {
			bom := &cdx.BOM{Components: &[]cdx.Component{}}
			result := normalize.FromCdxBom(bom, false)
			assert.Len(t, *result.GetComponents(), 0)
		})

		t.Run("nil components panics", func(t *testing.T) {
			bom := &cdx.BOM{Components: nil}
			assert.Panics(t, func() { normalize.FromCdxBom(bom, false) })
		})
	})

	t.Run("component with mixed properties", func(t *testing.T) {
		bom := &cdx.BOM{
			Components: &[]cdx.Component{{
				Name:       "test-component",
				PackageURL: "pkg:npm/old-pkg-id@1.0.0",
				Properties: &[]cdx.Property{
					{Name: "aquasecurity:trivy:SrcName", Value: "actual-source-name"},
					{Name: "aquasecurity:trivy:SrcVersion", Value: "2.1.0"},
					{Name: "aquasecurity:trivy:PkgID", Value: "old-pkg-id"},
					{Name: "aquasecurity:trivy:Other", Value: "some-other-value"},
					{Name: "some:other:property", Value: "not-trivy-property"},
				},
			}},
		}

		result := normalize.FromCdxBom(bom, false)
		component := (*result.GetComponents())[0]

		assert.Contains(t, component.PackageURL, "actual-source-name@2.1.0")
		assert.NotContains(t, component.PackageURL, "old-pkg-id")
	})
}

func TestCdxBomMethods(t *testing.T) {
	t.Run("getter methods", func(t *testing.T) {
		dependencies := []cdx.Dependency{{Ref: "test-ref"}}
		metadata := &cdx.Metadata{Component: &cdx.Component{Name: "test-metadata-component"}}
		components := []cdx.Component{{Name: "test-component"}}

		bom := &cdx.BOM{
			Components:   &components,
			Dependencies: &dependencies,
			Metadata:     metadata,
		}

		result := normalize.FromCdxBom(bom, false)

		assert.Equal(t, &dependencies, result.GetDependencies())
		assert.Equal(t, metadata, result.GetMetadata())
		assert.Equal(t, bom, result.GetCdxBom())
		assert.NotNil(t, result.GetComponents())
	})
}
