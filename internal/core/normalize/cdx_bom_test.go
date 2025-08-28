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

func TestMergeCdxBoms(t *testing.T) {
	t.Run("merge two BOMs with different components", func(t *testing.T) {
		bom1 := &cdx.BOM{
			Components: &[]cdx.Component{
				{
					Name:       "component-1",
					Version:    "1.0.0",
					PackageURL: "pkg:npm/component-1@1.0.0",
					Type:       cdx.ComponentTypeLibrary,
				},
			},
			Dependencies: &[]cdx.Dependency{
				{Ref: "component-1-ref"},
			},
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{Name: "metadata-component-1"},
			},
		}

		bom2 := &cdx.BOM{
			Components: &[]cdx.Component{
				{
					Name:       "component-2",
					Version:    "2.0.0",
					PackageURL: "pkg:npm/component-2@2.0.0",
					Type:       cdx.ComponentTypeLibrary,
				},
			},
			Dependencies: &[]cdx.Dependency{
				{Ref: "component-2-ref"},
			},
		}

		result := normalize.MergeCdxBoms(nil, bom1, bom2)

		assert.NotNil(t, result.Components)
		assert.Len(t, *result.Components, 2)

		componentNames := make([]string, 0)
		for _, comp := range *result.Components {
			componentNames = append(componentNames, comp.Name)
		}
		assert.Contains(t, componentNames, "component-1")
		assert.Contains(t, componentNames, "component-2")

		assert.NotNil(t, result.Dependencies)
		assert.Len(t, *result.Dependencies, 2)

		dependencyRefs := make([]string, 0)
		for _, dep := range *result.Dependencies {
			dependencyRefs = append(dependencyRefs, dep.Ref)
		}
		assert.Contains(t, dependencyRefs, "component-1-ref")
		assert.Contains(t, dependencyRefs, "component-2-ref")

		assert.Equal(t, bom1.Metadata, result.Metadata)
	})

	t.Run("merge BOMs with duplicate components", func(t *testing.T) {
		bom1 := &cdx.BOM{
			Components: &[]cdx.Component{
				{
					Name:       "duplicate-component",
					Version:    "1.0.0",
					PackageURL: "pkg:npm/duplicate-component@1.0.0",
					Type:       cdx.ComponentTypeLibrary,
				},
			},
		}

		bom2 := &cdx.BOM{
			Components: &[]cdx.Component{
				{
					Name:       "duplicate-component",
					Version:    "2.0.0", // Different version but same PackageURL
					PackageURL: "pkg:npm/duplicate-component@1.0.0",
					Type:       cdx.ComponentTypeApplication,
				},
			},
		}

		result := normalize.MergeCdxBoms(nil, bom1, bom2)

		assert.NotNil(t, result.Components)
		assert.Len(t, *result.Components, 1) // Should deduplicate based on PackageURL

		component := (*result.Components)[0]
		// Should keep the last one encountered (bom2's version)
		assert.Equal(t, "2.0.0", component.Version)
		assert.Equal(t, cdx.ComponentTypeApplication, component.Type)
	})

	t.Run("merge BOMs with duplicate dependencies", func(t *testing.T) {
		bom1 := &cdx.BOM{
			Dependencies: &[]cdx.Dependency{
				{Ref: "duplicate-ref", Dependencies: &[]string{"dep1"}},
			},
		}

		bom2 := &cdx.BOM{
			Dependencies: &[]cdx.Dependency{
				{Ref: "duplicate-ref", Dependencies: &[]string{"dep2"}},
			},
		}

		result := normalize.MergeCdxBoms(nil, bom1, bom2)

		assert.NotNil(t, result.Dependencies)
		assert.Len(t, *result.Dependencies, 1) // Should deduplicate based on Ref

		dependency := (*result.Dependencies)[0]
		assert.Equal(t, "duplicate-ref", dependency.Ref)
		// Should keep the last one encountered (bom2's dependencies)
		assert.Equal(t, []string{"dep2"}, *dependency.Dependencies)
	})

	t.Run("merge with nil BOMs", func(t *testing.T) {
		bom1 := &cdx.BOM{
			Components: &[]cdx.Component{
				{
					Name:       "component-1",
					PackageURL: "pkg:npm/component-1@1.0.0",
				},
			},
		}

		result := normalize.MergeCdxBoms(nil, bom1, nil, bom1)

		assert.NotNil(t, result.Components)
		assert.Len(t, *result.Components, 1) // Should handle nil BOMs and deduplicate
		assert.Equal(t, "component-1", (*result.Components)[0].Name)
	})

	t.Run("merge with empty BOMs", func(t *testing.T) {
		bom1 := &cdx.BOM{}
		bom2 := &cdx.BOM{
			Components:   &[]cdx.Component{},
			Dependencies: &[]cdx.Dependency{},
		}

		result := normalize.MergeCdxBoms(nil, bom1, bom2)

		assert.NotNil(t, result.Components)
		assert.Len(t, *result.Components, 0)
		assert.NotNil(t, result.Dependencies)
		assert.Len(t, *result.Dependencies, 0)
	})

	t.Run("merge with nil components and dependencies", func(t *testing.T) {
		bom1 := &cdx.BOM{
			Components:   nil,
			Dependencies: nil,
		}

		bom2 := &cdx.BOM{
			Components: &[]cdx.Component{
				{Name: "test-component", PackageURL: "pkg:npm/test@1.0.0"},
			},
			Dependencies: &[]cdx.Dependency{
				{Ref: "test-ref"},
			},
		}

		result := normalize.MergeCdxBoms(nil, bom1, bom2)

		assert.NotNil(t, result.Components)
		assert.Len(t, *result.Components, 1)
		assert.Equal(t, "test-component", (*result.Components)[0].Name)

		assert.NotNil(t, result.Dependencies)
		assert.Len(t, *result.Dependencies, 1)
		assert.Equal(t, "test-ref", (*result.Dependencies)[0].Ref)
	})

	t.Run("merge no BOMs", func(t *testing.T) {
		result := normalize.MergeCdxBoms(nil)

		assert.NotNil(t, result.Components)
		assert.Len(t, *result.Components, 0)
		assert.NotNil(t, result.Dependencies)
		assert.Len(t, *result.Dependencies, 0)
		assert.Nil(t, result.Metadata)
	})

	t.Run("metadata handling", func(t *testing.T) {
		bom1 := &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{Name: "first-metadata"},
			},
		}

		bom2 := &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{Name: "second-metadata"},
			},
		}

		bom3 := &cdx.BOM{} // No metadata

		// Test with explicit metadata parameter
		explicitMetadata := &cdx.Metadata{
			Component: &cdx.Component{Name: "explicit-metadata"},
		}
		
		result := normalize.MergeCdxBoms(explicitMetadata, bom1, bom2, bom3)

		// Should use the explicitly passed metadata
		assert.NotNil(t, result.Metadata)
		assert.Equal(t, "explicit-metadata", result.Metadata.Component.Name)
		
		// Test with nil metadata parameter - should use first BOM's metadata
		result2 := normalize.MergeCdxBoms(nil, bom1, bom2, bom3)
		assert.NotNil(t, result2.Metadata)
		assert.Equal(t, "first-metadata", result2.Metadata.Component.Name)
	})

	t.Run("complex merge scenario", func(t *testing.T) {
		bom1 := &cdx.BOM{
			Components: &[]cdx.Component{
				{Name: "comp1", PackageURL: "pkg:npm/comp1@1.0.0"},
				{Name: "comp2", PackageURL: "pkg:npm/comp2@1.0.0"},
			},
			Dependencies: &[]cdx.Dependency{
				{Ref: "dep1"},
				{Ref: "dep2"},
			},
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{Name: "metadata-comp"},
			},
		}

		bom2 := &cdx.BOM{
			Components: &[]cdx.Component{
				{Name: "comp2", PackageURL: "pkg:npm/comp2@1.0.0"}, // Duplicate
				{Name: "comp3", PackageURL: "pkg:npm/comp3@1.0.0"},
			},
			Dependencies: &[]cdx.Dependency{
				{Ref: "dep2"}, // Duplicate
				{Ref: "dep3"},
			},
		}

		bom3 := &cdx.BOM{
			Components: &[]cdx.Component{
				{Name: "comp4", PackageURL: "pkg:npm/comp4@1.0.0"},
			},
		}

		result := normalize.MergeCdxBoms(nil, bom1, bom2, bom3)

		assert.NotNil(t, result.Components)
		assert.Len(t, *result.Components, 4) // comp1, comp2, comp3, comp4 (deduplicated)

		assert.NotNil(t, result.Dependencies)
		assert.Len(t, *result.Dependencies, 3) // dep1, dep2, dep3 (deduplicated)

		assert.NotNil(t, result.Metadata)
		assert.Equal(t, "metadata-comp", result.Metadata.Component.Name)
	})
}
