package normalize

import (
	"bytes"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInvalidComponentTypeValidation tests that invalid component types are caught
// and sanitized so the exported SBOM passes CycloneDX 1.6 JSON schema validation.
//
// This test reproduces the issue where some components have invalid Type values
// that fail CycloneDX schema validation:
// "Value should match one of the values specified by the enum"
func TestInvalidComponentTypeValidation(t *testing.T) {
	schema := compileSchema(t)

	bomWithComponent := func(comp cdx.Component) *cdx.BOM {
		return &cdx.BOM{
			BOMFormat:   "CycloneDX",
			SpecVersion: cdx.SpecVersion1_6,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "root", Name: "my-app"},
			},
			Components: &[]cdx.Component{comp},
			Dependencies: &[]cdx.Dependency{
				{Ref: "root", Dependencies: &[]string{comp.BOMRef}},
			},
		}
	}

	t.Run("invalid component type should be sanitized to library", func(t *testing.T) {
		parsed, err := MerkleTreeFromCycloneDX(bomWithComponent(cdx.Component{
			BOMRef:     "pkg:npm/lodash@4.17.21",
			Name:       "lodash",
			Version:    "4.17.21",
			PackageURL: "pkg:npm/lodash@4.17.21",
			Type:       cdx.ComponentType(""), // Invalid: empty string
		}), "my-app")
		require.NoError(t, err)

		bom := parsed.Tree.ToCycloneDX(BOMMetadata{RootName: "my-app", ArtifactName: "my-app"}, parsed.Components)

		validateBOMAgainstSchema(t, bom, schema)

		require.Len(t, *bom.Components, 2) // root + component
		for _, comp := range *bom.Components {
			if comp.Name == "lodash" {
				assert.Equal(t, cdx.ComponentTypeLibrary, comp.Type, "Expected invalid type to be sanitized to library")
			}
		}
	})

	t.Run("unknown component type should be sanitized to library", func(t *testing.T) {
		parsed, err := MerkleTreeFromCycloneDX(bomWithComponent(cdx.Component{
			BOMRef:     "pkg:npm/express@4.18.0",
			Name:       "express",
			Version:    "4.18.0",
			PackageURL: "pkg:npm/express@4.18.0",
			Type:       cdx.ComponentType("unknown-type"), // Invalid: not in enum
		}), "my-app")
		require.NoError(t, err)

		bom := parsed.Tree.ToCycloneDX(BOMMetadata{RootName: "my-app", ArtifactName: "my-app"}, parsed.Components)

		validateBOMAgainstSchema(t, bom, schema)

		require.Len(t, *bom.Components, 2) // root + component
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
				parsed, err := MerkleTreeFromCycloneDX(bomWithComponent(cdx.Component{
					BOMRef:     "pkg:npm/test@1.0.0",
					Name:       "test",
					Version:    "1.0.0",
					PackageURL: "pkg:npm/test@1.0.0",
					Type:       validType,
				}), "my-app")
				require.NoError(t, err)

				bom := parsed.Tree.ToCycloneDX(BOMMetadata{RootName: "my-app", ArtifactName: "my-app"}, parsed.Components)

				validateBOMAgainstSchema(t, bom, schema)
			})
		}
	})

	t.Run("multiple components with mixed valid and invalid types get sanitized", func(t *testing.T) {
		bom := &cdx.BOM{
			BOMFormat:   "CycloneDX",
			SpecVersion: cdx.SpecVersion1_6,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "root", Name: "my-app"},
			},
			Components: &[]cdx.Component{
				{BOMRef: "pkg:npm/valid@1.0.0", Name: "valid", Version: "1.0.0", PackageURL: "pkg:npm/valid@1.0.0", Type: cdx.ComponentTypeLibrary},
				{BOMRef: "pkg:npm/invalid@2.0.0", Name: "invalid", Version: "2.0.0", PackageURL: "pkg:npm/invalid@2.0.0", Type: cdx.ComponentType("bad-type")}, // Invalid
			},
			Dependencies: &[]cdx.Dependency{
				{Ref: "root", Dependencies: &[]string{"pkg:npm/valid@1.0.0", "pkg:npm/invalid@2.0.0"}},
			},
		}

		parsed, err := MerkleTreeFromCycloneDX(bom, "my-app")
		require.NoError(t, err)

		exported := parsed.Tree.ToCycloneDX(BOMMetadata{RootName: "my-app", ArtifactName: "my-app"}, parsed.Components)

		validateBOMAgainstSchema(t, exported, schema)

		require.Len(t, *exported.Components, 3) // root + 2 components
		for _, comp := range *exported.Components {
			if comp.Name == "invalid" {
				assert.Equal(t, cdx.ComponentTypeLibrary, comp.Type, "Expected bad-type to be sanitized to library")
			}
		}
	})

	t.Run("components simulating ones loaded from the database with invalid types get sanitized", func(t *testing.T) {
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

		comps := make([]cdx.Component, 0, len(componentScenarios))
		refs := make([]string, 0, len(componentScenarios))
		for _, scenario := range componentScenarios {
			comps = append(comps, cdx.Component{
				BOMRef:     scenario.bomRef,
				Name:       scenario.name,
				Version:    "1.0.0",
				PackageURL: scenario.bomRef,
				Type:       scenario.compType,
			})
			refs = append(refs, scenario.bomRef)
		}

		bom := &cdx.BOM{
			BOMFormat:   "CycloneDX",
			SpecVersion: cdx.SpecVersion1_6,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "root", Name: "test-artifact"},
			},
			Components:   &comps,
			Dependencies: &[]cdx.Dependency{{Ref: "root", Dependencies: &refs}},
		}

		parsed, err := MerkleTreeFromCycloneDX(bom, "test-artifact")
		require.NoError(t, err)

		exported := parsed.Tree.ToCycloneDX(BOMMetadata{RootName: "test-artifact", ArtifactName: "test-artifact"}, parsed.Components)

		validateBOMAgainstSchema(t, exported, schema)

		for _, comp := range *exported.Components {
			if comp.Name == "empty type" || comp.Name == "null/invalid" {
				assert.Equal(t, cdx.ComponentTypeLibrary, comp.Type, "Expected invalid types to be sanitized to library")
			}
		}
	})
}

// TestSchemaBreakers tests various ways to break CycloneDX 1.6 schema validation
func TestSchemaBreakers(t *testing.T) {
	t.Run("missing component name defaults to bomRef and does not break parsing", func(t *testing.T) {
		bom := &cdx.BOM{
			SpecVersion: cdx.SpecVersion1_6,
			BOMFormat:   "CycloneDX",
			Version:     1,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "root", Name: "root", Type: cdx.ComponentTypeApplication},
			},
			Components: &[]cdx.Component{
				{
					BOMRef: "pkg:npm/test@1.0.0",
					// Name field is empty, so name would be bomRef
					Type:       cdx.ComponentTypeLibrary,
					Version:    "1.0.0",
					PackageURL: "pkg:npm/test@1.0.0",
				},
			},
			Dependencies: &[]cdx.Dependency{
				{Ref: "root", Dependencies: &[]string{"pkg:npm/test@1.0.0"}},
			},
		}

		// MerkleTreeFromCycloneDX should handle this gracefully by using bomRef as the name if name is missing
		parsed, err := MerkleTreeFromCycloneDX(bom, "test-artifact")
		require.NoError(t, err)

		comp, ok := parsed.Components["pkg:npm/test@1.0.0"]
		require.True(t, ok)
		assert.Equal(t, "pkg:npm/test@1.0.0", comp.Name, "Component name should default to bomRef when name is missing")
	})

	t.Run("invalid scope value returns error when parsing", func(t *testing.T) {
		bom := &cdx.BOM{
			SpecVersion: cdx.SpecVersion1_6,
			BOMFormat:   "CycloneDX",
			Version:     1,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "root", Name: "root", Type: cdx.ComponentTypeApplication},
			},
			Components: &[]cdx.Component{
				{BOMRef: "pkg:npm/test@1.0.0", Name: "test", Type: cdx.ComponentTypeLibrary, Scope: cdx.Scope("invalid-scope")}, // INVALID
			},
		}

		parsed, err := MerkleTreeFromCycloneDX(bom, "test-artifact")
		assert.Error(t, err, "Should return error for invalid scope value")
		assert.Nil(t, parsed)
	})

	t.Run("invalid hash algorithm gets automatically removed during parsing", func(t *testing.T) {
		hashes := []cdx.Hash{{Algorithm: cdx.HashAlgorithm("invalid-algo"), Value: "abc123"}}
		bom := &cdx.BOM{
			SpecVersion: cdx.SpecVersion1_6,
			BOMFormat:   "CycloneDX",
			Version:     1,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "root", Name: "root", Type: cdx.ComponentTypeApplication},
			},
			Components: &[]cdx.Component{
				{BOMRef: "pkg:npm/test@1.0.0", Name: "test", Type: cdx.ComponentTypeLibrary, PackageURL: "pkg:npm/test@1.0.0", Hashes: &hashes},
			},
		}

		parsed, err := MerkleTreeFromCycloneDX(bom, "test-artifact")
		require.NoError(t, err, "Should successfully parse even with invalid hashes")

		exported := parsed.Tree.ToCycloneDX(BOMMetadata{RootName: "root", ArtifactName: "root"}, parsed.Components)
		var buf bytes.Buffer
		encoder := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON)
		assert.NoError(t, encoder.Encode(exported))
	})

	t.Run("invalid external reference types get removed during parsing", func(t *testing.T) {
		extRefs := []cdx.ExternalReference{{URL: "https://example.com", Type: "bad-type"}} // INVALID
		bom := &cdx.BOM{
			SpecVersion: cdx.SpecVersion1_6,
			BOMFormat:   "CycloneDX",
			Version:     1,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "root", Name: "root", Type: cdx.ComponentTypeApplication},
			},
			Components: &[]cdx.Component{
				{BOMRef: "pkg:npm/test@1.0.0", Name: "test", Type: cdx.ComponentTypeLibrary, ExternalReferences: &extRefs},
			},
		}

		parsed, err := MerkleTreeFromCycloneDX(bom, "test-artifact")
		require.NoError(t, err, "Should successfully parse even with invalid external references")
		assert.NotNil(t, parsed)
	})

	t.Run("invalid dependency reference - undefined refs are dropped, not an error", func(t *testing.T) {
		deps := []cdx.Dependency{
			{Ref: "pkg:npm/test@1.0.0", Dependencies: &[]string{"pkg:npm/nonexistent@1.0.0"}}, // References undefined component
		}
		bom := &cdx.BOM{
			SpecVersion: cdx.SpecVersion1_6,
			BOMFormat:   "CycloneDX",
			Version:     1,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "root", Name: "root", Type: cdx.ComponentTypeApplication},
			},
			Components: &[]cdx.Component{
				{BOMRef: "pkg:npm/test@1.0.0", Name: "test", Type: cdx.ComponentTypeLibrary},
			},
			Dependencies: &deps,
		}

		// MerkleTreeFromCycloneDX should handle this gracefully by eliminating undefined references
		_, err := MerkleTreeFromCycloneDX(bom, "test-artifact")
		assert.NoError(t, err, "Undefined dependency references should be dropped, not error")
	})

	t.Run("missing required metadata component returns an error", func(t *testing.T) {
		bom := &cdx.BOM{
			SpecVersion: cdx.SpecVersion1_6,
			BOMFormat:   "CycloneDX",
			Version:     1,
			Metadata:    &cdx.Metadata{
				// Missing Component
			},
		}

		_, err := MerkleTreeFromCycloneDX(bom, "test-artifact")
		assert.Error(t, err, "Should error if root component is missing")
	})

	t.Run("invalid BOM format returns an error", func(t *testing.T) {
		bom := &cdx.BOM{
			SpecVersion: cdx.SpecVersion1_6,
			BOMFormat:   "InvalidFormat",
			Version:     1,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "root", Name: "root", Type: cdx.ComponentTypeApplication},
			},
		}

		_, err := MerkleTreeFromCycloneDX(bom, "test-artifact")
		assert.Error(t, err, "Should error with invalid BOM format")
	})

	t.Run("negative BOM spec version returns an error", func(t *testing.T) {
		bom := &cdx.BOM{
			SpecVersion: -1,
			BOMFormat:   "CycloneDX",
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "root", Name: "root", Type: cdx.ComponentTypeApplication},
			},
		}

		_, err := MerkleTreeFromCycloneDX(bom, "test-artifact")
		assert.Error(t, err, "Should error with negative BOM spec version")
	})

	t.Run("invalid composition aggregate value is ignored during parsing", func(t *testing.T) {
		comps := []cdx.Composition{{Aggregate: cdx.CompositionAggregate("partial")}} // INVALID
		bom := &cdx.BOM{
			SpecVersion:  cdx.SpecVersion1_6,
			BOMFormat:    "CycloneDX",
			Version:      1,
			Compositions: &comps,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "root", Name: "root", Type: cdx.ComponentTypeApplication},
			},
			Components: &[]cdx.Component{
				{BOMRef: "pkg:npm/test@1.0.0", Name: "test", Type: cdx.ComponentTypeLibrary},
			},
			Dependencies: &[]cdx.Dependency{
				{Ref: "root", Dependencies: &[]string{"pkg:npm/test@1.0.0"}},
			},
		}

		// compositions are not processed at all, so they cannot break parsing
		parsed, err := MerkleTreeFromCycloneDX(bom, "test-artifact")
		assert.NoError(t, err, "Should successfully parse (compositions are not processed)")
		assert.NotNil(t, parsed)
	})

	t.Run("duplicate component BOMRef is skipped gracefully", func(t *testing.T) {
		bom := &cdx.BOM{
			SpecVersion: cdx.SpecVersion1_6,
			BOMFormat:   "CycloneDX",
			Version:     1,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "root", Name: "root", Type: cdx.ComponentTypeApplication},
			},
			Components: &[]cdx.Component{
				{BOMRef: "pkg:npm/dup@1.0.0", Name: "dup1", Type: cdx.ComponentTypeLibrary},
				{BOMRef: "pkg:npm/dup@1.0.0", Name: "dup2", Type: cdx.ComponentTypeLibrary}, // Same BOMRef - skipped
			},
		}

		parsed, err := MerkleTreeFromCycloneDX(bom, "test-artifact")
		assert.NoError(t, err, "Should not error for duplicate BOMRef")
		assert.NotNil(t, parsed)
	})

	t.Run("missing required component BOMRef returns an error", func(t *testing.T) {
		bom := &cdx.BOM{
			SpecVersion: cdx.SpecVersion1_6,
			BOMFormat:   "CycloneDX",
			Version:     1,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "root", Name: "root", Type: cdx.ComponentTypeApplication},
			},
			Components: &[]cdx.Component{
				{ /* BOMRef is empty/missing */ Name: "test", Type: cdx.ComponentTypeLibrary},
			},
		}

		parsed, err := MerkleTreeFromCycloneDX(bom, "test-artifact")
		assert.Error(t, err, "Should error for missing component BOMRef")
		assert.Nil(t, parsed)
	})

	t.Run("invalid license identifier format is ignored during parsing", func(t *testing.T) {
		lics := cdx.Licenses{{License: &cdx.License{ID: "not-a-valid-spdx-id-!@#$%"}}} // Invalid SPDX ID format
		bom := &cdx.BOM{
			SpecVersion: cdx.SpecVersion1_6,
			BOMFormat:   "CycloneDX",
			Version:     1,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "root", Name: "root", Type: cdx.ComponentTypeApplication, Licenses: &lics},
			},
		}

		parsed, err := MerkleTreeFromCycloneDX(bom, "test-artifact")
		assert.NoError(t, err, "Should successfully parse even with invalid license identifiers")
		assert.NotNil(t, parsed)
	})

	t.Run("invalid component PackageURL format on the root returns an error", func(t *testing.T) {
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

		parsed, err := MerkleTreeFromCycloneDX(bom, "test-artifact")
		assert.Error(t, err, "Should error for invalid root PackageURL format")
		assert.Nil(t, parsed)
	})

	t.Run("invalid CPE format is ignored during parsing", func(t *testing.T) {
		bom := &cdx.BOM{
			SpecVersion: cdx.SpecVersion1_6,
			BOMFormat:   "CycloneDX",
			Version:     1,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "root", Name: "root", Type: cdx.ComponentTypeApplication, CPE: "not-a-valid-cpe"},
			},
		}

		parsed, err := MerkleTreeFromCycloneDX(bom, "test-artifact")
		assert.NoError(t, err, "Should successfully parse even with invalid CPE format")
		assert.NotNil(t, parsed)
	})

	t.Run("invalid date format in timestamp is ignored during parsing", func(t *testing.T) {
		bom := &cdx.BOM{
			SpecVersion: cdx.SpecVersion1_6,
			BOMFormat:   "CycloneDX",
			Version:     1,
			Metadata: &cdx.Metadata{
				Timestamp: "not-a-valid-timestamp-format",
				Component: &cdx.Component{BOMRef: "root", Name: "root", Type: cdx.ComponentTypeApplication},
			},
		}

		parsed, err := MerkleTreeFromCycloneDX(bom, "test-artifact")
		assert.NoError(t, err, "Should successfully parse even with invalid timestamp format")
		assert.NotNil(t, parsed)
	})
}
