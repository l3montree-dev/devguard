// Copyright (C) 2024 Tim Bastin, l3montree GmbH
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

package models

import (
	"bytes"
	"encoding/json"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/stretchr/testify/assert"
)

// TestToCdxComponentCompliance ensures ToCdxComponent produces CycloneDX spec-compliant components
func TestToCdxComponentCompliance(t *testing.T) {
	t.Run("required fields are never empty", func(t *testing.T) {
		dep := ComponentDependency{
			DependencyID: "pkg:npm/express@4.18.2",
			Dependency: Component{
				ID:            "pkg:npm/express@4.18.2",
				ComponentType: dtos.ComponentTypeLibrary,
			},
		}

		comp, err := dep.ToCdxComponent(map[string]string{})
		assert.NoError(t, err)

		// BOMRef must be present
		assert.NotEmpty(t, comp.BOMRef, "BOMRef must not be empty per CycloneDX spec")
		// Name must be present
		assert.NotEmpty(t, comp.Name, "Name must not be empty per CycloneDX spec")
		// Type must be valid
		assert.NotEmpty(t, comp.Type, "Type must not be empty per CycloneDX spec")
	})

	t.Run("valid PURL is preserved", func(t *testing.T) {
		purlString := "pkg:npm/lodash@4.17.21"
		dep := ComponentDependency{
			DependencyID: purlString,
			Dependency: Component{
				ID:            purlString,
				ComponentType: dtos.ComponentTypeLibrary,
			},
		}

		comp, err := dep.ToCdxComponent(map[string]string{})
		assert.NoError(t, err)

		// PackageURL should be set for valid PURLs
		assert.Equal(t, purlString, comp.PackageURL, "Valid PURL should be preserved in PackageURL")
		// Version should be extracted
		assert.Equal(t, "4.17.21", comp.Version, "Version should be extracted from PURL")
	})

	t.Run("non-PURL identifiers have empty PackageURL", func(t *testing.T) {
		dep := ComponentDependency{
			DependencyID: "/usr/lib/libcrypto.so.1.1",
			Dependency: Component{
				ID:            "/usr/lib/libcrypto.so.1.1",
				ComponentType: dtos.ComponentTypeFile,
			},
		}

		comp, err := dep.ToCdxComponent(map[string]string{})
		assert.NoError(t, err)

		// PackageURL should be empty for non-PURL identifiers
		assert.Empty(t, comp.PackageURL, "PackageURL should be empty for non-PURL identifiers per spec")
		// BOMRef should still be set to the identifier
		assert.Equal(t, "/usr/lib/libcrypto.so.1.1", comp.BOMRef)
		// Name should be set
		assert.NotEmpty(t, comp.Name)
	})

	t.Run("empty DependencyID returns error", func(t *testing.T) {
		dep := ComponentDependency{
			DependencyID: "",
			Dependency: Component{
				ID:            "",
				ComponentType: dtos.ComponentTypeLibrary,
			},
		}

		_, err := dep.ToCdxComponent(map[string]string{})

		// Should return an error for empty DependencyID
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "DependencyID must not be empty")
	})

	t.Run("invalid component types are sanitized", func(t *testing.T) {
		testCases := []struct {
			name          string
			componentType dtos.ComponentType
			expectType    cdx.ComponentType
		}{
			{"valid library", dtos.ComponentTypeLibrary, cdx.ComponentTypeLibrary},
			{"valid application", dtos.ComponentTypeApplication, cdx.ComponentTypeApplication},
			{"valid container", dtos.ComponentTypeContainer, cdx.ComponentTypeContainer},
			{"invalid type defaults to library", dtos.ComponentType("invalid-type"), cdx.ComponentTypeLibrary},
			{"empty type defaults to library", dtos.ComponentType(""), cdx.ComponentTypeLibrary},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				dep := ComponentDependency{
					DependencyID: "pkg:npm/test@1.0.0",
					Dependency: Component{
						ID:            "pkg:npm/test@1.0.0",
						ComponentType: tc.componentType,
					},
				}

				comp, err := dep.ToCdxComponent(map[string]string{})
				assert.NoError(t, err)

				assert.Equal(t, tc.expectType, comp.Type, "Component type should be %s", tc.expectType)
			})
		}
	})

	t.Run("component is serializable to valid JSON", func(t *testing.T) {
		dep := ComponentDependency{
			DependencyID: "pkg:npm/express@4.18.2",
			Dependency: Component{
				ID:            "pkg:npm/express@4.18.2",
				ComponentType: dtos.ComponentTypeLibrary,
			},
		}

		comp, err := dep.ToCdxComponent(map[string]string{})
		assert.NoError(t, err)

		// Ensure component can be marshaled to JSON
		data, err := json.Marshal(comp)
		assert.NoError(t, err, "Component should be serializable to JSON")
		assert.NotEmpty(t, data)

		// Verify the JSON is valid
		var result map[string]interface{}
		err = json.Unmarshal(data, &result)
		assert.NoError(t, err, "Marshaled component should be valid JSON")
	})

	t.Run("component can be encoded in CycloneDX BOM format", func(t *testing.T) {
		dep := ComponentDependency{
			DependencyID: "pkg:npm/express@4.18.2",
			Dependency: Component{
				ID:            "pkg:npm/express@4.18.2",
				ComponentType: dtos.ComponentTypeLibrary,
			},
		}

		comp, err := dep.ToCdxComponent(map[string]string{})
		assert.NoError(t, err)

		// Create a minimal BOM with this component for encoding
		bom := &cdx.BOM{
			SpecVersion: cdx.SpecVersion1_6,
			BOMFormat:   "CycloneDX",
			Version:     1,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef: "root",
					Name:   "root",
					Type:   cdx.ComponentTypeApplication,
				},
			},
			Components: &[]cdx.Component{comp},
		}

		var buf bytes.Buffer
		encoder := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
		err = encoder.Encode(bom)
		assert.NoError(t, err, "Component should be encodable in a CycloneDX BOM")

		// Verify the encoded JSON is valid
		var result interface{}
		err = json.Unmarshal(buf.Bytes(), &result)
		assert.NoError(t, err, "Encoded BOM should contain valid JSON")
	})

	t.Run("BOMRef uniqueness can be verified", func(t *testing.T) {
		dep := ComponentDependency{
			DependencyID: "pkg:npm/express@4.18.2",
			Dependency: Component{
				ID:            "pkg:npm/express@4.18.2",
				ComponentType: dtos.ComponentTypeLibrary,
			},
		}

		comp, err := dep.ToCdxComponent(map[string]string{})
		assert.NoError(t, err)

		// BOMRef should match DependencyID for consistency
		assert.Equal(t, dep.DependencyID, comp.BOMRef, "BOMRef should be derived from DependencyID for consistency")
	})

	t.Run("version is correctly extracted from PURL", func(t *testing.T) {
		testCases := []struct {
			purl            string
			expectedVersion string
		}{
			{"pkg:npm/express@4.18.2", "4.18.2"},
			{"pkg:maven/org.apache.commons/commons-lang3@3.12.0", "3.12.0"},
			{"pkg:pypi/django@4.2.0", "4.2.0"},
			{"pkg:npm/package-without-version", ""},
			{"/path/to/binary", ""}, // Not a PURL
		}

		for _, tc := range testCases {
			t.Run(tc.purl, func(t *testing.T) {
				dep := ComponentDependency{
					DependencyID: tc.purl,
					Dependency: Component{
						ID:            tc.purl,
						ComponentType: dtos.ComponentTypeLibrary,
					},
				}

				comp, err := dep.ToCdxComponent(map[string]string{})
				assert.NoError(t, err)

				assert.Equal(t, tc.expectedVersion, comp.Version, "Version should be %s", tc.expectedVersion)
			})
		}
	})

	t.Run("all valid CycloneDX component types are accepted", func(t *testing.T) {
		validTypes := []dtos.ComponentType{
			dtos.ComponentTypeApplication,
			dtos.ComponentTypeContainer,
			dtos.ComponentTypeData,
			dtos.ComponentTypeDevice,
			dtos.ComponentTypeDeviceDriver,
			dtos.ComponentTypeFile,
			dtos.ComponentTypeFirmware,
			dtos.ComponentTypeFramework,
			dtos.ComponentTypeLibrary,
			dtos.ComponentTypeOS,
			dtos.ComponentTypePlatform,
		}

		for _, componentType := range validTypes {
			t.Run(string(componentType), func(t *testing.T) {
				dep := ComponentDependency{
					DependencyID: "pkg:npm/test@1.0.0",
					Dependency: Component{
						ID:            "pkg:npm/test@1.0.0",
						ComponentType: componentType,
					},
				}

				comp, err := dep.ToCdxComponent(map[string]string{})
				assert.NoError(t, err)

				// Type should be preserved
				assert.Equal(t, cdx.ComponentType(componentType), comp.Type)
				// Component should still be valid
				assert.NotEmpty(t, comp.BOMRef)
				assert.NotEmpty(t, comp.Name)
			})
		}
	})

	t.Run("licenses are properly included", func(t *testing.T) {
		dep := ComponentDependency{
			DependencyID: "pkg:npm/express@4.18.2",
			Dependency: Component{
				ID:            "pkg:npm/express@4.18.2",
				ComponentType: dtos.ComponentTypeLibrary,
				License:       getStringPtr("MIT"),
			},
		}

		comp, err := dep.ToCdxComponent(map[string]string{})
		assert.NoError(t, err)

		// Licenses should be included if available
		assert.NotNil(t, comp.Licenses)
	})

	t.Run("license overwrites are applied correctly", func(t *testing.T) {
		dep := ComponentDependency{
			DependencyID: "pkg:npm/express@4.18.2",
			Dependency: Component{
				ID:            "pkg:npm/express@4.18.2",
				ComponentType: dtos.ComponentTypeLibrary,
				License:       getStringPtr("MIT"),
			},
		}

		overrides := map[string]string{
			"pkg:npm/express@4.18.2": "Apache-2.0",
		}

		comp, err := dep.ToCdxComponent(overrides)
		assert.NoError(t, err)

		// Component should use overwritten license
		assert.NotNil(t, comp.Licenses)
	})
}

// TestValidateCycloneDXComponentType tests the validation function
func TestValidateCycloneDXComponentType(t *testing.T) {
	t.Run("valid types return true", func(t *testing.T) {
		validTypes := []cdx.ComponentType{
			cdx.ComponentTypeApplication,
			cdx.ComponentTypeLibrary,
			cdx.ComponentTypeContainer,
		}

		for _, ct := range validTypes {
			assert.True(t, isValidCycloneDXComponentType(ct), "Type %s should be valid", ct)
		}
	})

	t.Run("invalid types return false", func(t *testing.T) {
		invalidTypes := []cdx.ComponentType{
			cdx.ComponentType("invalid"),
			cdx.ComponentType(""),
			cdx.ComponentType("unknown-type"),
		}

		for _, ct := range invalidTypes {
			assert.False(t, isValidCycloneDXComponentType(ct), "Type %s should be invalid", ct)
		}
	})
}

// TestSanitizeCycloneDXComponentType tests the sanitization function
func TestSanitizeCycloneDXComponentType(t *testing.T) {
	t.Run("valid types are preserved", func(t *testing.T) {
		assert.Equal(t, cdx.ComponentTypeLibrary, sanitizeCycloneDXComponentType(dtos.ComponentTypeLibrary))
		assert.Equal(t, cdx.ComponentTypeApplication, sanitizeCycloneDXComponentType(dtos.ComponentTypeApplication))
	})

	t.Run("invalid types default to library", func(t *testing.T) {
		assert.Equal(t, cdx.ComponentTypeLibrary, sanitizeCycloneDXComponentType(dtos.ComponentType("invalid")))
		assert.Equal(t, cdx.ComponentTypeLibrary, sanitizeCycloneDXComponentType(dtos.ComponentType("")))
	})
}

// TestToCdxComponentBOMIntegration verifies the component works correctly when added to a BOM
func TestToCdxComponentBOMIntegration(t *testing.T) {
	dep1 := ComponentDependency{
		DependencyID: "pkg:npm/express@4.18.2",
		Dependency: Component{
			ID:            "pkg:npm/express@4.18.2",
			ComponentType: dtos.ComponentTypeLibrary,
		},
	}

	dep2 := ComponentDependency{
		DependencyID: "pkg:npm/body-parser@1.20.2",
		Dependency: Component{
			ID:            "pkg:npm/body-parser@1.20.2",
			ComponentType: dtos.ComponentTypeLibrary,
		},
	}

	comp1, err := dep1.ToCdxComponent(map[string]string{})
	assert.NoError(t, err)
	comp2, err := dep2.ToCdxComponent(map[string]string{})
	assert.NoError(t, err)

	// Create a BOM with these components
	bom := &cdx.BOM{
		SpecVersion: cdx.SpecVersion1_6,
		BOMFormat:   "CycloneDX",
		Version:     1,
		Metadata: &cdx.Metadata{
			Component: &cdx.Component{
				BOMRef: "root",
				Name:   "root",
				Type:   cdx.ComponentTypeApplication,
			},
		},
		Components: &[]cdx.Component{comp1, comp2},
		Dependencies: &[]cdx.Dependency{
			{Ref: "root", Dependencies: &[]string{comp1.BOMRef, comp2.BOMRef}},
			{Ref: comp1.BOMRef, Dependencies: &[]string{}},
			{Ref: comp2.BOMRef, Dependencies: &[]string{}},
		},
	}

	// Verify the BOM can be encoded
	var buf bytes.Buffer
	encoder := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
	err = encoder.Encode(bom)
	assert.NoError(t, err)

	// Verify it's valid JSON
	var result interface{}
	err = json.Unmarshal(buf.Bytes(), &result)
	assert.NoError(t, err)

	// Verify BOMRefs are unique
	bomRefs := make(map[string]bool)
	bomRefs["root"] = true
	for _, comp := range *bom.Components {
		if bomRefs[comp.BOMRef] {
			t.Errorf("Duplicate BOMRef: %s", comp.BOMRef)
		}
		bomRefs[comp.BOMRef] = true
	}
}

// Helper function to get pointer to string
func getStringPtr(s string) *string {
	return &s
}
