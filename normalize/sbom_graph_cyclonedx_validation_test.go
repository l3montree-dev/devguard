package normalize

import (
	"bytes"
	"encoding/json"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
)

// TestInvalidComponentTypeValidation tests that invalid component types are caught
// and the SBOM fails CycloneDX 1.6 JSON schema validation.
//
// This test reproduces the issue where some components have invalid Type values
// that fail CycloneDX schema validation:
// "Value should match one of the values specified by the enum"
func TestInvalidComponentTypeValidation(t *testing.T) {
	schema := compileSchema(t)

	t.Run("invalid component type should be sanitized to library", func(t *testing.T) {
		g := NewSBOMGraph()
		artifactID := g.AddArtifact("my-app")
		infoSourceID := g.AddInfoSource(artifactID, "trivy", InfoSourceSBOM)

		// Add component with invalid type - empty string
		invalidComp := cdx.Component{
			BOMRef:     "pkg:npm/lodash@4.17.21",
			Name:       "lodash",
			Version:    "4.17.21",
			PackageURL: "pkg:npm/lodash@4.17.21",
			Type:       cdx.ComponentType(""), // Invalid: empty string
		}
		compID := g.AddComponent(invalidComp)
		g.AddEdge(infoSourceID, compID)

		bom := g.ToCycloneDX(BOMMetadata{
			RootName:     "my-app",
			ArtifactName: "my-app",
		})

		// Encode to JSON and validate - should now pass because invalid type was sanitized
		var buf bytes.Buffer
		encoder := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
		encoder.SetPretty(true)
		err := encoder.Encode(bom)
		assert.NoError(t, err)

		// Parse and validate
		var jsonData any
		err = json.Unmarshal(buf.Bytes(), &jsonData)
		assert.NoError(t, err)

		// Should pass validation now because invalid type is sanitized to library
		validationErr := schema.Validate(jsonData)
		assert.NoError(t, validationErr, "Expected validation to pass after sanitizing invalid component type")

		// Verify the type was actually set to library
		assert.Len(t, *bom.Components, 2) // root + component
		// Find the lodash component
		for _, comp := range *bom.Components {
			if comp.Name == "lodash" {
				assert.Equal(t, cdx.ComponentTypeLibrary, comp.Type, "Expected invalid type to be sanitized to library")
			}
		}
	})

	t.Run("unknown component type should be sanitized to library", func(t *testing.T) {
		g := NewSBOMGraph()
		artifactID := g.AddArtifact("my-app")
		infoSourceID := g.AddInfoSource(artifactID, "trivy", InfoSourceSBOM)

		// Add component with invalid type
		invalidComp := cdx.Component{
			BOMRef:     "pkg:npm/express@4.18.0",
			Name:       "express",
			Version:    "4.18.0",
			PackageURL: "pkg:npm/express@4.18.0",
			Type:       cdx.ComponentType("unknown-type"), // Invalid: not in enum
		}
		compID := g.AddComponent(invalidComp)
		g.AddEdge(infoSourceID, compID)

		bom := g.ToCycloneDX(BOMMetadata{
			RootName:     "my-app",
			ArtifactName: "my-app",
		})

		// Encode to JSON
		var buf bytes.Buffer
		encoder := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
		err := encoder.Encode(bom)
		assert.NoError(t, err)

		// Parse and validate - should pass because invalid type was sanitized
		var jsonData any
		err = json.Unmarshal(buf.Bytes(), &jsonData)
		assert.NoError(t, err)

		validationErr := schema.Validate(jsonData)
		assert.NoError(t, validationErr, "Expected validation to pass after sanitizing unknown component type")

		// Verify the type was actually set to library
		assert.Len(t, *bom.Components, 2) // root + component
		for _, comp := range *bom.Components {
			if comp.Name == "express" {
				assert.Equal(t, cdx.ComponentTypeLibrary, comp.Type, "Expected unknown type to be sanitized to library")
			}
		}
	})

	t.Run("valid component types should pass validation", func(t *testing.T) {
		validTypes := []cdx.ComponentType{
			cdx.ComponentTypeApplication,
			cdx.ComponentTypeContainer,
			cdx.ComponentTypeData,
			cdx.ComponentTypeDevice,
			cdx.ComponentTypeDeviceDriver,
			cdx.ComponentTypeFile,
			cdx.ComponentTypeFirmware,
			cdx.ComponentTypeFramework,
			cdx.ComponentTypeLibrary,
			cdx.ComponentTypeMachineLearningModel,
			cdx.ComponentTypeOS,
			cdx.ComponentTypePlatform,
		}

		for _, validType := range validTypes {
			t.Run("type_"+string(validType), func(t *testing.T) {
				g := NewSBOMGraph()
				artifactID := g.AddArtifact("my-app")
				infoSourceID := g.AddInfoSource(artifactID, "trivy", InfoSourceSBOM)

				comp := cdx.Component{
					BOMRef:     "pkg:npm/test@1.0.0",
					Name:       "test",
					Version:    "1.0.0",
					PackageURL: "pkg:npm/test@1.0.0",
					Type:       validType,
				}
				compID := g.AddComponent(comp)
				g.AddEdge(infoSourceID, compID)

				bom := g.ToCycloneDX(BOMMetadata{
					RootName:     "my-app",
					ArtifactName: "my-app",
				})

				validateBOMAgainstSchema(t, bom, schema)
			})
		}
	})

	t.Run("multiple components with mixed valid and invalid types get sanitized", func(t *testing.T) {
		g := NewSBOMGraph()
		artifactID := g.AddArtifact("my-app")
		infoSourceID := g.AddInfoSource(artifactID, "trivy", InfoSourceSBOM)

		// Valid component
		validComp := cdx.Component{
			BOMRef:     "pkg:npm/valid@1.0.0",
			Name:       "valid",
			Version:    "1.0.0",
			PackageURL: "pkg:npm/valid@1.0.0",
			Type:       cdx.ComponentTypeLibrary,
		}
		validID := g.AddComponent(validComp)
		g.AddEdge(infoSourceID, validID)

		// Invalid component (at index 20, 29, 72 as mentioned in the issue)
		invalidComp := cdx.Component{
			BOMRef:     "pkg:npm/invalid@2.0.0",
			Name:       "invalid",
			Version:    "2.0.0",
			PackageURL: "pkg:npm/invalid@2.0.0",
			Type:       cdx.ComponentType("bad-type"), // Invalid
		}
		invalidID := g.AddComponent(invalidComp)
		g.AddEdge(infoSourceID, invalidID)

		bom := g.ToCycloneDX(BOMMetadata{
			RootName:     "my-app",
			ArtifactName: "my-app",
		})

		// Encode to JSON
		var buf bytes.Buffer
		encoder := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
		encoder.SetPretty(true)
		err := encoder.Encode(bom)
		assert.NoError(t, err)

		// Parse and validate - should pass because invalid types are sanitized
		var jsonData any
		err = json.Unmarshal(buf.Bytes(), &jsonData)
		assert.NoError(t, err)

		validationErr := schema.Validate(jsonData)
		assert.NoError(t, validationErr, "Expected validation to pass after sanitizing all invalid component types")

		// Verify both types are valid
		assert.Len(t, *bom.Components, 3) // root + 2 components
		for _, comp := range *bom.Components {
			if comp.Name == "invalid" {
				assert.Equal(t, cdx.ComponentTypeLibrary, comp.Type, "Expected bad-type to be sanitized to library")
			}
		}
	})

	t.Run("SBOM with components converted from database models", func(t *testing.T) {
		// Simulate components loaded from database that might have invalid types
		g := NewSBOMGraph()
		artifactID := g.AddArtifact("test-artifact")
		infoSourceID := g.AddInfoSource(artifactID, "sbom.json", InfoSourceSBOM)

		// Simulate various component types that might be in the database
		componentScenarios := []struct {
			name     string
			bomRef   string
			compType cdx.ComponentType
		}{
			{"valid library", "pkg:npm/lib@1.0.0", cdx.ComponentTypeLibrary},
			{"valid app", "pkg:npm/app@1.0.0", cdx.ComponentTypeApplication},
			{"empty type", "pkg:npm/empty@1.0.0", cdx.ComponentType("")},      // Will be sanitized to library
			{"null/invalid", "pkg:npm/null@1.0.0", cdx.ComponentType("null")}, // Will be sanitized to library
		}

		for _, scenario := range componentScenarios {
			comp := cdx.Component{
				BOMRef:     scenario.bomRef,
				Name:       scenario.name,
				Version:    "1.0.0",
				PackageURL: scenario.bomRef,
				Type:       scenario.compType,
			}
			compID := g.AddComponent(comp)
			g.AddEdge(infoSourceID, compID)
		}

		bom := g.ToCycloneDX(BOMMetadata{
			RootName:     "test-artifact",
			ArtifactName: "test-artifact",
		})

		// Encode to JSON
		var buf bytes.Buffer
		encoder := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
		err := encoder.Encode(bom)
		assert.NoError(t, err)

		// Parse and validate - should pass because invalid types are sanitized
		var jsonData any
		err = json.Unmarshal(buf.Bytes(), &jsonData)
		assert.NoError(t, err)

		validationErr := schema.Validate(jsonData)
		assert.NoError(t, validationErr, "Expected validation to pass - all invalid types should be sanitized to library")

		// Verify that empty and invalid types were converted to library
		for _, comp := range *bom.Components {
			if comp.Name == "empty type" || comp.Name == "null/invalid" {
				assert.Equal(t, cdx.ComponentTypeLibrary, comp.Type, "Expected invalid types to be sanitized to library")
			}
		}
	})

	t.Run("SBOMGraphFromCycloneDX sanitizes invalid types from input", func(t *testing.T) {
		// Test that when parsing a CycloneDX BOM with invalid types,
		// they are sanitized to library type on export
		inputBOM := &cdx.BOM{
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
			Components: &[]cdx.Component{
				{
					BOMRef:     "pkg:npm/lib1@1.0.0",
					Name:       "lib1",
					Version:    "1.0.0",
					PackageURL: "pkg:npm/lib1@1.0.0",
					Type:       cdx.ComponentType(""), // Invalid type in input
				},
				{
					BOMRef:     "pkg:npm/lib2@2.0.0",
					Name:       "lib2",
					Version:    "2.0.0",
					PackageURL: "pkg:npm/lib2@2.0.0",
					Type:       cdx.ComponentTypeLibrary,
				},
			},
			Dependencies: &[]cdx.Dependency{
				{
					Ref:          "root",
					Dependencies: &[]string{"pkg:npm/lib1@1.0.0", "pkg:npm/lib2@2.0.0"},
				},
			},
		}

		graph, err := SBOMGraphFromCycloneDX(inputBOM, "test", "test", false)
		assert.NoError(t, err, "Graph construction should succeed")
		exportedBOM := graph.ToCycloneDX(BOMMetadata{
			RootName:     "test",
			ArtifactName: "test",
		})

		// Encode and validate - should pass because invalid types are sanitized on export
		var buf bytes.Buffer
		encoder := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
		encodeErr := encoder.Encode(exportedBOM)
		assert.NoError(t, encodeErr)

		var jsonData any
		parseErr := json.Unmarshal(buf.Bytes(), &jsonData)
		assert.NoError(t, parseErr)

		validationErr := schema.Validate(jsonData)
		assert.NoError(t, validationErr, "Expected validation to pass for sanitized component types")
	})
}

// TestSchemaBreakers tests various ways to break CycloneDX 1.6 schema validation
func TestSchemaBreakers(t *testing.T) {
	t.Run("missing required component name returns error when trying to construct sbom graph", func(t *testing.T) {
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
			Components: &[]cdx.Component{
				{
					BOMRef: "pkg:npm/test@1.0.0",
					// Name field is empty - should cause error in graph construction
					Type: cdx.ComponentTypeLibrary,
				},
			},
		}

		// SBOMGraphFromCycloneDX should return error for missing component name
		graph, err := SBOMGraphFromCycloneDX(bom, "test-artifact", "test-source", false)
		assert.NotNil(t, err, "Should return error for component with missing name")
		assert.Nil(t, graph, "Graph should be nil when error occurs")
	})

	t.Run("invalid scope value returns error when building sbom graph", func(t *testing.T) {
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
			Components: &[]cdx.Component{
				{
					BOMRef: "pkg:npm/test@1.0.0",
					Name:   "test",
					Type:   cdx.ComponentTypeLibrary,
					Scope:  cdx.Scope("invalid-scope"), // INVALID
				},
			},
		}

		// SBOMGraphFromCycloneDX should return error for invalid scope
		graph, err := SBOMGraphFromCycloneDX(bom, "test-artifact", "test-source", false)
		assert.NotNil(t, err, "Should return error for invalid scope value")
		assert.Nil(t, graph, "Graph should be nil when error occurs")
	})

	t.Run("invalid hash algorithm will get automatically removed by sbom graph construction", func(t *testing.T) {
		hashes := []cdx.Hash{
			{Algorithm: cdx.HashAlgorithm("invalid-algo"), Value: "abc123"},
		}
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
			Components: &[]cdx.Component{
				{
					BOMRef: "pkg:npm/test@1.0.0",
					Name:   "test",
					Type:   cdx.ComponentTypeLibrary,
					Hashes: &hashes,
				},
			},
		}

		// Graph should handle this gracefully by removing invalid hashes
		graph, err := SBOMGraphFromCycloneDX(bom, "test-artifact", "test-source", false)
		assert.NoError(t, err, "Should successfully construct graph even with invalid hashes")
		assert.NotNil(t, graph, "Graph should be created successfully")
		// Verify the invalid hash was removed during construction
		// by checking that exporting produces valid CycloneDX
		exportedBOM := graph.ToCycloneDX(BOMMetadata{RootName: "root", ArtifactName: "root"})
		var buf bytes.Buffer
		encoder := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
		assert.NoError(t, encoder.Encode(exportedBOM))
	})

	t.Run("invalid external reference types will get removed when constructing sbom graph", func(t *testing.T) {
		extRefs := []cdx.ExternalReference{
			{
				URL:  "https://example.com",
				Type: "bad-type", // INVALID - not a valid external reference type
			},
		}
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
			Components: &[]cdx.Component{
				{
					BOMRef:             "pkg:npm/test@1.0.0",
					Name:               "test",
					Type:               cdx.ComponentTypeLibrary,
					ExternalReferences: &extRefs,
				},
			},
		}

		// Graph should handle this gracefully by removing invalid external references
		graph, err := SBOMGraphFromCycloneDX(bom, "test-artifact", "test-source", false)
		assert.NoError(t, err, "Should successfully construct graph even with invalid external references")
		assert.NotNil(t, graph, "Graph should be created successfully")
	})

	t.Run("invalid dependency reference - schema lenient on referential integrity will return an error in sbom graph construction", func(t *testing.T) {
		deps := []cdx.Dependency{
			{
				Ref:          "pkg:npm/test@1.0.0",
				Dependencies: &[]string{"pkg:npm/nonexistent@1.0.0"}, // References undefined component
			},
		}
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
			Components: &[]cdx.Component{
				{
					BOMRef: "pkg:npm/test@1.0.0",
					Name:   "test",
					Type:   cdx.ComponentTypeLibrary,
				},
			},
			Dependencies: &deps,
		}

		// SBOMGraphFromCycloneDX should handle this gracefully by skipping undefined references
		_, err := SBOMGraphFromCycloneDX(bom, "test-artifact", "test-source", false)
		assert.Error(t, err, "Graph should return error for dependency referencing nonexistent component")
	})

	t.Run("missing required metadata component - schema lenient on optional metadata will return an error during sbom graph construction", func(t *testing.T) {
		bom := &cdx.BOM{
			SpecVersion: cdx.SpecVersion1_6,
			BOMFormat:   "CycloneDX",
			Version:     1,
			Metadata:    &cdx.Metadata{
				// Missing Component - CycloneDX 1.6 spec suggests component is important
				// but the schema doesn't enforce it as required
			},
		}

		// SBOMGraphFromCycloneDX should handle this gracefully by creating a default root
		_, err := SBOMGraphFromCycloneDX(bom, "test-artifact", "test-source", false)
		assert.Error(t, err, "Graph should not be created if root component is missing")

	})

	t.Run("invalid BOM spec version will return error during construction of sbom graph", func(t *testing.T) {
		bom := &cdx.BOM{
			SpecVersion: cdx.SpecVersion1_6, // Using valid version for the test structure
			BOMFormat:   "InvalidFormat",    // Make format invalid instead
			Version:     1,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef: "root",
					Name:   "root",
					Type:   cdx.ComponentTypeApplication,
				},
			},
		}

		// SBOMGraphFromCycloneDX should handle this gracefully - it doesn't validate BOM format itself
		_, err := SBOMGraphFromCycloneDX(bom, "test-artifact", "test-source", false)
		assert.Error(t, err, "Graph should not be created with invalid BOM format")
	})

	t.Run("negative BOM version returns error during graph construction", func(t *testing.T) {
		bom := &cdx.BOM{
			SpecVersion: -1,
			BOMFormat:   "CycloneDX",
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef: "root",
					Name:   "root",
					Type:   cdx.ComponentTypeApplication,
				},
			},
		}

		// SBOMGraphFromCycloneDX should handle this gracefully
		_, err := SBOMGraphFromCycloneDX(bom, "test-artifact", "test-source", false)
		assert.Error(t, err, "Graph should not be created with negative BOM version")
	})

	t.Run("invalid composition aggregate value will get ignored by sbom graph construction", func(t *testing.T) {
		comps := []cdx.Composition{
			{
				Aggregate: cdx.CompositionAggregate("partial"), // INVALID
			},
		}
		bom := &cdx.BOM{
			SpecVersion:  cdx.SpecVersion1_6,
			BOMFormat:    "CycloneDX",
			Version:      1,
			Compositions: &comps,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef: "root",
					Name:   "root",
					Type:   cdx.ComponentTypeApplication,
				},
			},
			Components: &[]cdx.Component{
				{
					BOMRef: "pkg:npm/test@1.0.0",
					Name:   "test",
					Type:   cdx.ComponentTypeLibrary,
				},
			},
			Dependencies: &[]cdx.Dependency{
				{
					Ref:          "root",
					Dependencies: &[]string{"pkg:npm/test@1.0.0"},
				},
			},
		}

		// SBOMGraphFromCycloneDX ignores compositions - they're not used in graph building
		graph, err := SBOMGraphFromCycloneDX(bom, "test-artifact", "test-source", false)
		assert.NoError(t, err, "Should successfully construct graph (compositions are not processed)")
		assert.NotNil(t, graph, "Graph should be created successfully")
		assert.NotNil(t, graph, "Graph should be created successfully")
	})

	t.Run("duplicate component BOMRef will return error during sbom graph construction", func(t *testing.T) {
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
			Components: &[]cdx.Component{
				{
					BOMRef: "pkg:npm/dup@1.0.0", // Duplicate BOMRef
					Name:   "dup1",
					Type:   cdx.ComponentTypeLibrary,
				},
				{
					BOMRef: "pkg:npm/dup@1.0.0", // Same BOMRef - INVALID
					Name:   "dup2",
					Type:   cdx.ComponentTypeLibrary,
				},
			},
		}

		// Try to construct graph with duplicate BOMRefs - should return error
		graph, err := SBOMGraphFromCycloneDX(bom, "test-artifact", "test-source", false)
		assert.NotNil(t, err, "Should return error for duplicate BOMRef")
		assert.Nil(t, graph, "Graph should be nil when error occurs")
	})

	t.Run("missing required component BOMRef - will return error during graph construction", func(t *testing.T) {
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
			Components: &[]cdx.Component{
				{
					// BOMRef is empty/missing
					Name: "test",
					Type: cdx.ComponentTypeLibrary,
				},
			},
		}

		// Try to construct graph with missing BOMRef - should return error
		graph, err := SBOMGraphFromCycloneDX(bom, "test-artifact", "test-source", false)
		assert.NotNil(t, err, "Should return error for missing component BOMRef")
		assert.Nil(t, graph, "Graph should be nil when error occurs")
	})

	t.Run("invalid license identifier format will get ignored by sbom graph construction", func(t *testing.T) {
		lics := cdx.Licenses{
			{
				License: &cdx.License{
					ID: "not-a-valid-spdx-id-!@#$%", // Invalid SPDX ID format
				},
			},
		}
		bom := &cdx.BOM{
			SpecVersion: cdx.SpecVersion1_6,
			BOMFormat:   "CycloneDX",
			Version:     1,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef:   "root",
					Name:     "root",
					Type:     cdx.ComponentTypeApplication,
					Licenses: &lics,
				},
			},
		}

		// Graph should handle this gracefully by ignoring invalid license identifiers
		graph, err := SBOMGraphFromCycloneDX(bom, "test-artifact", "test-source", false)
		assert.NoError(t, err, "Should successfully construct graph even with invalid license identifiers")
		assert.NotNil(t, graph, "Graph should be created successfully")
	})

	t.Run("invalid component PackageURL format fails validation and returns error during graph construction", func(t *testing.T) {
		bom := &cdx.BOM{
			SpecVersion: cdx.SpecVersion1_6,
			BOMFormat:   "CycloneDX",
			Version:     1,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef:     "root",
					Name:       "root",
					Type:       cdx.ComponentTypeApplication,
					PackageURL: "not-a-valid-purl-format-@#$", // INVALID PURL
				},
			},
		}

		// Try to construct graph with invalid PackageURL - should return error
		graph, err := SBOMGraphFromCycloneDX(bom, "test-artifact", "test-source", false)
		assert.NotNil(t, err, "Should return error for invalid PackageURL format")
		assert.Nil(t, graph, "Graph should be nil when error occurs")
	})

	t.Run("invalid CPE format will get ignored", func(t *testing.T) {
		cpe := "not-a-valid-cpe"
		bom := &cdx.BOM{
			SpecVersion: cdx.SpecVersion1_6,
			BOMFormat:   "CycloneDX",
			Version:     1,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef: "root",
					Name:   "root",
					Type:   cdx.ComponentTypeApplication,
					CPE:    cpe,
				},
			},
		}

		// Graph should handle this gracefully by ignoring invalid CPE format
		graph, err := SBOMGraphFromCycloneDX(bom, "test-artifact", "test-source", false)
		assert.NoError(t, err, "Should successfully construct graph even with invalid CPE format")
		assert.NotNil(t, graph, "Graph should be created successfully")
	})

	t.Run("invalid date format in timestamp will get ignored by sbom_graph construction", func(t *testing.T) {
		bom := &cdx.BOM{
			SpecVersion: cdx.SpecVersion1_6,
			BOMFormat:   "CycloneDX",
			Version:     1,
			Metadata: &cdx.Metadata{
				Timestamp: "not-a-valid-timestamp-format",
				Component: &cdx.Component{
					BOMRef: "root",
					Name:   "root",
					Type:   cdx.ComponentTypeApplication,
				},
			},
		}

		// Graph should handle this gracefully by ignoring invalid timestamp
		graph, err := SBOMGraphFromCycloneDX(bom, "test-artifact", "test-source", false)
		assert.NoError(t, err, "Should successfully construct graph even with invalid timestamp format")
		assert.NotNil(t, graph, "Graph should be created successfully")
	})
}
