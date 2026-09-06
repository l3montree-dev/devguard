package normalize

import (
	"os"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseCycloneDXReachability(t *testing.T) {
	artifactName := "test-artifact"

	t.Run("basic component without properties parses with its metadata intact", func(t *testing.T) {
		bom := &cdx.BOM{
			BOMFormat:   "CycloneDX",
			SpecVersion: cdx.SpecVersion1_6,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "root", Name: artifactName},
			},
			Components: &[]cdx.Component{{
				BOMRef:     "pkg:npm/test-component@1.0.0",
				Name:       "test-component",
				Version:    "1.0.0",
				PackageURL: "pkg:npm/test-component@1.0.0",
				Type:       cdx.ComponentTypeLibrary,
			}},
			Dependencies: &[]cdx.Dependency{
				{Ref: "root", Dependencies: &[]string{"pkg:npm/test-component@1.0.0"}},
			},
		}

		parsed, err := MerkleTreeFromCycloneDX(bom, artifactName)
		require.NoError(t, err)

		comp, ok := parsed.Components["pkg:npm/test-component@1.0.0"]
		require.True(t, ok)
		assert.Equal(t, "test-component", comp.Name)
		assert.Equal(t, "1.0.0", comp.Version)
		assert.Contains(t, comp.PackageURL, "test-component")
		assert.Contains(t, parsed.Tree.ComponentIDs(), "pkg:npm/test-component@1.0.0")
	})

	t.Run("root ref not in dependencies - single top-level component becomes a direct dependency", func(t *testing.T) {
		bom := &cdx.BOM{
			BOMFormat:   "CycloneDX",
			SpecVersion: cdx.SpecVersion1_6,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "root", Name: artifactName},
			},
			Components: &[]cdx.Component{{
				BOMRef:     "pkg:npm/component-a@1.0.0",
				Name:       "component-a",
				Version:    "1.0.0",
				PackageURL: "pkg:npm/component-a@1.0.0",
				Type:       cdx.ComponentTypeLibrary,
			}},
			// Note: "root" is not in dependencies, only component-a has an entry
			Dependencies: &[]cdx.Dependency{
				{Ref: "pkg:npm/component-a@1.0.0", Dependencies: &[]string{}},
			},
		}

		parsed, err := MerkleTreeFromCycloneDX(bom, artifactName)
		require.NoError(t, err)

		assert.Contains(t, parsed.Tree.ComponentIDs(), "pkg:npm/component-a@1.0.0",
			"component-a should be reachable even though nothing declares root as its parent")
		assert.Contains(t, parsed.Tree.DirectDependencies(), "pkg:npm/component-a@1.0.0")
	})

	t.Run("root ref not in dependencies - multiple top-level components all become direct dependencies", func(t *testing.T) {
		bom := &cdx.BOM{
			BOMFormat:   "CycloneDX",
			SpecVersion: cdx.SpecVersion1_6,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "root", Name: artifactName},
			},
			Components: &[]cdx.Component{
				{BOMRef: "pkg:npm/component-a@1.0.0", Name: "component-a", PackageURL: "pkg:npm/component-a@1.0.0", Type: cdx.ComponentTypeLibrary},
				{BOMRef: "pkg:npm/component-b@2.0.0", Name: "component-b", PackageURL: "pkg:npm/component-b@2.0.0", Type: cdx.ComponentTypeLibrary},
			},
			Dependencies: &[]cdx.Dependency{
				{Ref: "pkg:npm/component-a@1.0.0", Dependencies: &[]string{}},
				{Ref: "pkg:npm/component-b@2.0.0", Dependencies: &[]string{}},
			},
		}

		parsed, err := MerkleTreeFromCycloneDX(bom, artifactName)
		require.NoError(t, err)

		assert.ElementsMatch(t, []string{"pkg:npm/component-a@1.0.0", "pkg:npm/component-b@2.0.0"},
			parsed.Tree.DirectDependencies())
	})

	t.Run("root ref not in dependencies - a nested tree stays connected through its own top", func(t *testing.T) {
		bom := &cdx.BOM{
			BOMFormat:   "CycloneDX",
			SpecVersion: cdx.SpecVersion1_6,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "root", Name: artifactName},
			},
			Components: &[]cdx.Component{
				{BOMRef: "pkg:npm/parent@1.0.0", Name: "parent", PackageURL: "pkg:npm/parent@1.0.0", Type: cdx.ComponentTypeLibrary},
				{BOMRef: "pkg:npm/child@1.0.0", Name: "child", PackageURL: "pkg:npm/child@1.0.0", Type: cdx.ComponentTypeLibrary},
				{BOMRef: "pkg:npm/grandchild@1.0.0", Name: "grandchild", PackageURL: "pkg:npm/grandchild@1.0.0", Type: cdx.ComponentTypeLibrary},
			},
			// parent -> child -> grandchild, but root is not connected to any of them
			Dependencies: &[]cdx.Dependency{
				{Ref: "pkg:npm/parent@1.0.0", Dependencies: &[]string{"pkg:npm/child@1.0.0"}},
				{Ref: "pkg:npm/child@1.0.0", Dependencies: &[]string{"pkg:npm/grandchild@1.0.0"}},
				{Ref: "pkg:npm/grandchild@1.0.0", Dependencies: &[]string{}},
			},
		}

		parsed, err := MerkleTreeFromCycloneDX(bom, artifactName)
		require.NoError(t, err)

		assert.Equal(t, []string{"pkg:npm/parent@1.0.0"}, parsed.Tree.DirectDependencies(),
			"only parent (nobody's child) should become a direct dependency of the artifact")
		assert.Contains(t, parsed.Tree.ComponentIDs(), "pkg:npm/child@1.0.0")
		assert.Contains(t, parsed.Tree.ComponentIDs(), "pkg:npm/grandchild@1.0.0")
	})

	t.Run("root component with no PackageURL is pruned, its children become direct dependencies", func(t *testing.T) {
		bom := &cdx.BOM{
			BOMFormat:   "CycloneDX",
			SpecVersion: cdx.SpecVersion1_6,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "no-purl-root", Name: artifactName},
			},
			Components: &[]cdx.Component{{
				BOMRef:     "pkg:npm/component-a@1.0.0",
				Name:       "component-a",
				PackageURL: "pkg:npm/component-a@1.0.0",
				Type:       cdx.ComponentTypeLibrary,
			}},
			Dependencies: &[]cdx.Dependency{
				{Ref: "no-purl-root", Dependencies: &[]string{"pkg:npm/component-a@1.0.0"}},
			},
		}

		parsed, err := MerkleTreeFromCycloneDX(bom, artifactName)
		require.NoError(t, err)

		// The root component has no PackageURL, so it cannot be identified as a
		// real package: component-a becomes a direct dependency of the artifact,
		// rather than a dependency of an unidentifiable intermediate node.
		assert.Equal(t, []string{"pkg:npm/component-a@1.0.0"}, parsed.Tree.DirectDependencies())
	})

	t.Run("root component with a valid PackageURL is preserved as an intermediate node", func(t *testing.T) {
		bom := &cdx.BOM{
			BOMFormat:   "CycloneDX",
			SpecVersion: cdx.SpecVersion1_6,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef:     "root",
					Name:       artifactName,
					PackageURL: "pkg:npm/test-artifact@1.0.0",
				},
			},
			Components: &[]cdx.Component{{
				BOMRef:     "pkg:npm/component-a@1.0.0",
				Name:       "component-a",
				PackageURL: "pkg:npm/component-a@1.0.0",
				Type:       cdx.ComponentTypeLibrary,
			}},
			Dependencies: &[]cdx.Dependency{
				{Ref: "root", Dependencies: &[]string{"pkg:npm/component-a@1.0.0"}},
			},
		}

		parsed, err := MerkleTreeFromCycloneDX(bom, artifactName)
		require.NoError(t, err)

		// The root component's own purl is not the artifact's identity, so it
		// stays as a real, distinct node between the artifact and component-a.
		assert.Equal(t, []string{"pkg:npm/test-artifact@1.0.0"}, parsed.Tree.DirectDependencies())
		paths := parsed.Tree.PathsToPURL("pkg:npm/component-a@1.0.0", 0)
		require.Len(t, paths, 1)
		assert.Equal(t, "pkg:npm/test-artifact@1.0.0,pkg:npm/component-a@1.0.0", paths[0].String())
	})

	t.Run("root component with multiple children", func(t *testing.T) {
		bom := &cdx.BOM{
			BOMFormat:   "CycloneDX",
			SpecVersion: cdx.SpecVersion1_6,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "root", Name: artifactName, PackageURL: "pkg:npm/artifactName@1.0.0"},
			},
			Components: &[]cdx.Component{
				{BOMRef: "pkg:npm/component-a@1.0.0", Name: "component-a", PackageURL: "pkg:npm/component-a@1.0.0", Type: cdx.ComponentTypeLibrary},
				{BOMRef: "pkg:npm/component-b@2.0.0", Name: "component-b", PackageURL: "pkg:npm/component-b@2.0.0", Type: cdx.ComponentTypeLibrary},
			},
			Dependencies: &[]cdx.Dependency{
				{Ref: "root", Dependencies: &[]string{"pkg:npm/component-a@1.0.0", "pkg:npm/component-b@2.0.0"}},
			},
		}

		parsed, err := MerkleTreeFromCycloneDX(bom, artifactName)
		require.NoError(t, err)

		// the root's own PackageURL differs from the artifact identity, so it
		// stays as a real intermediate node and both components hang off it
		assert.Equal(t, []string{"pkg:npm/artifactName@1.0.0"}, parsed.Tree.DirectDependencies())
		pathsA := parsed.Tree.PathsToPURL("pkg:npm/component-a@1.0.0", 0)
		require.Len(t, pathsA, 1)
		assert.Equal(t, "pkg:npm/artifactName@1.0.0,pkg:npm/component-a@1.0.0", pathsA[0].String())
		pathsB := parsed.Tree.PathsToPURL("pkg:npm/component-b@2.0.0", 0)
		require.Len(t, pathsB, 1)
		assert.Equal(t, "pkg:npm/artifactName@1.0.0,pkg:npm/component-b@2.0.0", pathsB[0].String())
	})

	t.Run("orphan components not declared as anyone's dependency are still reachable from the artifact", func(t *testing.T) {
		bom := &cdx.BOM{
			BOMFormat:   "CycloneDX",
			SpecVersion: cdx.SpecVersion1_6,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "root", Name: artifactName, PackageURL: "pkg:npm/artifactName@1.0.0"},
			},
			Components: &[]cdx.Component{{
				BOMRef:     "pkg:npm/orphan-component@1.0.0",
				Name:       "orphan-component",
				PackageURL: "pkg:npm/orphan-component@1.0.0",
				Type:       cdx.ComponentTypeLibrary,
			}},
			Dependencies: &[]cdx.Dependency{
				{Ref: "pkg:npm/orphan-component@1.0.0", Dependencies: &[]string{}},
			},
		}

		parsed, err := MerkleTreeFromCycloneDX(bom, artifactName)
		require.NoError(t, err)

		// root's own PackageURL differs from the artifact identity, so it stays
		// as an intermediate node; the orphan hangs off it, one level deeper
		// than a direct dependency of the artifact.
		assert.Equal(t, []string{"pkg:npm/artifactName@1.0.0"}, parsed.Tree.DirectDependencies())
		paths := parsed.Tree.PathsToPURL("pkg:npm/orphan-component@1.0.0", 0)
		require.Len(t, paths, 1)
		assert.Equal(t, "pkg:npm/artifactName@1.0.0,pkg:npm/orphan-component@1.0.0", paths[0].String())
	})

	t.Run("root component is preserved along with a deeper dependency chain", func(t *testing.T) {
		rootRef := "pkg:npm/my-app@1.0.0"
		bom := &cdx.BOM{
			BOMFormat:   cdx.BOMFormat,
			SpecVersion: cdx.SpecVersion1_6,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: rootRef, Name: "my-app", Version: "1.0.0", PackageURL: rootRef, Type: cdx.ComponentTypeApplication},
			},
			Components: &[]cdx.Component{
				{BOMRef: rootRef, Name: "my-app", Version: "1.0.0", PackageURL: rootRef, Type: cdx.ComponentTypeApplication},
				{BOMRef: "pkg:npm/component-a@1.0.0", Name: "component-a", Version: "1.0.0", PackageURL: "pkg:npm/component-a@1.0.0", Type: cdx.ComponentTypeLibrary},
				{BOMRef: "pkg:npm/component-b@2.0.0", Name: "component-b", Version: "2.0.0", PackageURL: "pkg:npm/component-b@2.0.0", Type: cdx.ComponentTypeLibrary},
				{BOMRef: "pkg:npm/component-c@3.0.0", Name: "component-c", Version: "3.0.0", PackageURL: "pkg:npm/component-c@3.0.0", Type: cdx.ComponentTypeLibrary},
			},
			Dependencies: &[]cdx.Dependency{
				{Ref: rootRef, Dependencies: &[]string{"pkg:npm/component-a@1.0.0"}},
				{Ref: "pkg:npm/component-a@1.0.0", Dependencies: &[]string{"pkg:npm/component-b@2.0.0"}},
				{Ref: "pkg:npm/component-b@2.0.0", Dependencies: &[]string{"pkg:npm/component-c@3.0.0"}},
				{Ref: "pkg:npm/component-c@3.0.0", Dependencies: &[]string{}},
			},
		}

		// rootRef's purl differs from the artifact identity "test-artifact", so
		// it is kept as its own node rather than reparented.
		parsed, err := MerkleTreeFromCycloneDX(bom, "test-artifact")
		require.NoError(t, err)

		assert.Equal(t, []string{rootRef}, parsed.Tree.DirectDependencies())
		paths := parsed.Tree.PathsToPURL("pkg:npm/component-c@3.0.0", 0)
		require.Len(t, paths, 1)
		assert.Equal(t, rootRef+",pkg:npm/component-a@1.0.0,pkg:npm/component-b@2.0.0,pkg:npm/component-c@3.0.0", paths[0].String())
	})
}

// TestReuploadIdempotency covers the scenario isArtifactRootComponent exists
// for: a previously-downloaded devguard SBOM (whose root component PURL is
// derived from the artifact's own identity, see ToCycloneDX) gets
// re-uploaded. The root must not be wired in as a dependency of the artifact
// it already represents - otherwise the artifact would end up depending on
// itself.
func TestReuploadIdempotency(t *testing.T) {
	t.Run("root component sharing the artifact's own PURL identity does not appear as a component", func(t *testing.T) {
		artifactName := "pkg:oci/my-app@1.0.0"

		bom := &cdx.BOM{
			BOMFormat:   "CycloneDX",
			SpecVersion: cdx.SpecVersion1_6,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					// Same type/namespace/name as artifactName, just a
					// different version - exactly what ToCycloneDX would
					// have produced when this SBOM was first exported.
					BOMRef:     "pkg:oci/my-app@2.0.0",
					Name:       "my-app",
					PackageURL: "pkg:oci/my-app@2.0.0",
					Type:       cdx.ComponentTypeApplication,
				},
			},
			Components: &[]cdx.Component{{
				BOMRef:     "pkg:npm/component-a@1.0.0",
				Name:       "component-a",
				PackageURL: "pkg:npm/component-a@1.0.0",
				Type:       cdx.ComponentTypeLibrary,
			}},
			Dependencies: &[]cdx.Dependency{
				{Ref: "pkg:oci/my-app@2.0.0", Dependencies: &[]string{"pkg:npm/component-a@1.0.0"}},
			},
		}

		parsed, err := MerkleTreeFromCycloneDX(bom, artifactName)
		require.NoError(t, err)

		assert.NotContains(t, parsed.Tree.ComponentIDs(), "pkg:oci/my-app@2.0.0",
			"the root component should not be wired in as a dependency of the artifact it already represents")
		assert.Equal(t, []string{"pkg:npm/component-a@1.0.0"}, parsed.Tree.DirectDependencies())
	})

	t.Run("root component with an unrelated PURL still gets wired in as a normal dependency", func(t *testing.T) {
		artifactName := "pkg:oci/my-app@1.0.0"

		bom := &cdx.BOM{
			BOMFormat:   "CycloneDX",
			SpecVersion: cdx.SpecVersion1_6,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef:     "pkg:oci/some-other-image@2.0.0",
					Name:       "some-other-image",
					PackageURL: "pkg:oci/some-other-image@2.0.0",
					Type:       cdx.ComponentTypeApplication,
				},
			},
			Components: &[]cdx.Component{},
		}

		parsed, err := MerkleTreeFromCycloneDX(bom, artifactName)
		require.NoError(t, err)

		assert.Equal(t, []string{"pkg:oci/some-other-image@2.0.0"}, parsed.Tree.DirectDependencies(),
			"root component with an unrelated identity should still be wired in as a direct dependency")
	})

	t.Run("full round trip: exporting and re-importing the same artifact's SBOM stays idempotent", func(t *testing.T) {
		artifactName := "my-app"

		original := &cdx.BOM{
			BOMFormat:   "CycloneDX",
			SpecVersion: cdx.SpecVersion1_6,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "original-root", Name: artifactName},
			},
			Components: &[]cdx.Component{{
				BOMRef:     "pkg:npm/component-a@1.0.0",
				Name:       "component-a",
				PackageURL: "pkg:npm/component-a@1.0.0",
				Type:       cdx.ComponentTypeLibrary,
			}},
			Dependencies: &[]cdx.Dependency{
				{Ref: "original-root", Dependencies: &[]string{"pkg:npm/component-a@1.0.0"}},
			},
		}

		parsed, err := MerkleTreeFromCycloneDX(original, artifactName)
		require.NoError(t, err)

		exported := parsed.Tree.ToCycloneDX(BOMMetadata{ArtifactName: artifactName, AssetVersionName: "1.0.0"}, parsed.Components)

		// Re-import the exported BOM under the same artifact name, simulating a
		// download-then-reupload round trip.
		reimported, err := MerkleTreeFromCycloneDX(exported, artifactName)
		require.NoError(t, err)

		assert.Contains(t, reimported.Tree.ComponentIDs(), "pkg:npm/component-a@1.0.0",
			"component-a should survive the round trip")
		assert.NotContains(t, reimported.Tree.ComponentIDs(), "my-app@1.0.0",
			"the re-imported root, which is the artifact's own exported identity, must not become a dependency of itself")
	})
}

func TestSanitizeComponentURLUnescaping(t *testing.T) {
	t.Run("unescapes a URL-encoded plus sign in the PackageURL", func(t *testing.T) {
		encodedPurl := "pkg:deb/debian/libpam0g@1.4.0-9%2Bdeb11u2?arch=amd64&distro=debian-11.11"
		expectedPurl := "pkg:deb/debian/libpam0g@1.4.0-9+deb11u2?arch=amd64&distro=debian-11.11"

		bom := &cdx.BOM{
			BOMFormat:   "CycloneDX",
			SpecVersion: cdx.SpecVersion1_6,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "root", Name: "test-artifact"},
			},
			Components: &[]cdx.Component{{
				BOMRef:     encodedPurl,
				Name:       "libpam0g",
				Version:    "1.4.0-9+deb11u2",
				PackageURL: encodedPurl,
				Type:       cdx.ComponentTypeLibrary,
			}},
			Dependencies: &[]cdx.Dependency{
				{Ref: "root", Dependencies: &[]string{encodedPurl}},
			},
		}

		parsed, err := MerkleTreeFromCycloneDX(bom, "test-artifact")
		require.NoError(t, err)

		comp, ok := parsed.Components[expectedPurl]
		require.True(t, ok, "component should be stored under its unescaped PackageURL")
		assert.Equal(t, expectedPurl, comp.PackageURL)
		assert.Contains(t, parsed.Tree.ComponentIDs(), expectedPurl)
	})

	t.Run("preserves an already-unescaped plus sign", func(t *testing.T) {
		purl := "pkg:deb/debian/libpam0g@1.4.0-9+deb11u2?arch=amd64&distro=debian-11.11"

		bom := &cdx.BOM{
			BOMFormat:   "CycloneDX",
			SpecVersion: cdx.SpecVersion1_6,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "root", Name: "test-artifact"},
			},
			Components: &[]cdx.Component{{
				BOMRef:     purl,
				Name:       "libpam0g",
				Version:    "1.4.0-9+deb11u2",
				PackageURL: purl,
				Type:       cdx.ComponentTypeLibrary,
			}},
			Dependencies: &[]cdx.Dependency{
				{Ref: "root", Dependencies: &[]string{purl}},
			},
		}

		parsed, err := MerkleTreeFromCycloneDX(bom, "test-artifact")
		require.NoError(t, err)

		comp, ok := parsed.Components[purl]
		require.True(t, ok)
		assert.Equal(t, purl, comp.PackageURL)
	})
}

func TestToCycloneDXExternalReferencesArtifactEncoding(t *testing.T) {
	t.Run("artifact name with special characters should be properly URL encoded", func(t *testing.T) {
		testCases := []struct {
			name          string
			artifactName  string
			expectedInURL string
			description   string
		}{
			{
				name:          "simple artifact name",
				artifactName:  "my-app",
				expectedInURL: "my-app",
				description:   "simple alphanumeric with dashes",
			},
			{
				name:          "artifact with slashes",
				artifactName:  "pkg:devguard/second-level",
				expectedInURL: "pkg%3Adevguard%2Fsecond-level",
				description:   "artifact name with colon and slash - fully encoded with QueryEscape",
			},
			{
				name:          "artifact with spaces",
				artifactName:  "my artifact name",
				expectedInURL: "my+artifact+name",
				description:   "spaces encoded as + by QueryEscape",
			},
			{
				name:          "artifact with special URL characters",
				artifactName:  "artifact?with&special=chars",
				expectedInURL: "artifact%3Fwith%26special%3Dchars",
				description:   "query string characters fully encoded by QueryEscape",
			},
			{
				name:          "PURL with qualifiers",
				artifactName:  "pkg:oci/devguard?repository_url=ghcr.io/l3montree-dev/devguard",
				expectedInURL: "pkg%3Aoci%2Fdevguard%3Frepository_url%3Dghcr.io%2Fl3montree-dev%2Fdevguard",
				description:   "full PURL with qualifiers is fully encoded",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.description, func(t *testing.T) {
				tree := buildTree(map[string][]string{}, tc.artifactName)

				metadata := BOMMetadata{
					ArtifactName:          tc.artifactName,
					AssetVersionName:      "main",
					AssetVersionSlug:      "main",
					AssetSlug:             "my-asset",
					OrgSlug:               "my-org",
					ProjectSlug:           "my-project",
					AssetID:               uuid.UUID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
					AddExternalReferences: true,
					FrontendURL:           "http://localhost:3000",
				}
				t.Setenv("API_URL", "http://localhost:8080")

				bom := tree.ToCycloneDX(metadata, nil)

				require.NotNil(t, bom.ExternalReferences)
				assert.GreaterOrEqual(t, len(*bom.ExternalReferences), 2, "should have at least VEX and SBOM URLs")

				var vexRef, sbomRef, dashboardRef *cdx.ExternalReference
				for i := range *bom.ExternalReferences {
					switch (*bom.ExternalReferences)[i].Type {
					case cdx.ERTypeExploitabilityStatement:
						vexRef = &(*bom.ExternalReferences)[i]
					case cdx.ERTypeBOM:
						sbomRef = &(*bom.ExternalReferences)[i]
					case cdx.ERTypeDynamicAnalysisReport:
						dashboardRef = &(*bom.ExternalReferences)[i]
					}
				}
				require.NotNil(t, vexRef, "should have VEX reference")
				require.NotNil(t, sbomRef, "should have SBOM reference")
				require.NotNil(t, dashboardRef, "should have Dashboard reference")
				assert.Contains(t, vexRef.URL, "/refs/main/artifacts/"+tc.expectedInURL+"/vex.json/")
				assert.Contains(t, sbomRef.URL, "/refs/main/artifacts/"+tc.expectedInURL+"/sbom.json/")
				assert.Contains(t, dashboardRef.URL, "/refs/main?artifact="+tc.expectedInURL)
			})
		}
	})

	t.Run("external reference URLs should contain correct ref paths based on metadata", func(t *testing.T) {
		tree := buildTree(map[string][]string{}, "my-app")

		metadata := BOMMetadata{
			ArtifactName:          "my-app",
			AssetVersionName:      "dev-branch",
			AssetVersionSlug:      "dev-branch",
			AssetSlug:             "my-asset",
			OrgSlug:               "my-org",
			ProjectSlug:           "my-project",
			AssetID:               uuid.UUID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			AddExternalReferences: true,
			FrontendURL:           "http://localhost:3000",
		}
		t.Setenv("API_URL", "http://localhost:8080")

		bom := tree.ToCycloneDX(metadata, nil)

		require.NotNil(t, bom.ExternalReferences)
		assert.GreaterOrEqual(t, len(*bom.ExternalReferences), 3)

		for _, ref := range *bom.ExternalReferences {
			switch ref.Type {
			case cdx.ERTypeExploitabilityStatement:
				assert.Contains(t, ref.URL, "/refs/dev-branch/artifacts/my-app/vex.json/")
			case cdx.ERTypeBOM:
				assert.Contains(t, ref.URL, "/refs/dev-branch/artifacts/my-app/sbom.json/")
			case cdx.ERTypeDynamicAnalysisReport:
				assert.Contains(t, ref.URL, "/refs/dev-branch?artifact=my-app")
			}
		}
	})

	t.Run("all external reference URLs should be present exactly once", func(t *testing.T) {
		tree := buildTree(map[string][]string{}, "my-app")

		metadata := BOMMetadata{
			ArtifactName:          "my-app",
			AssetVersionName:      "main",
			AssetVersionSlug:      "main",
			AssetSlug:             "my-asset",
			OrgSlug:               "my-org",
			ProjectSlug:           "my-project",
			AssetID:               uuid.UUID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			AddExternalReferences: true,
			FrontendURL:           "http://localhost:3000",
		}
		t.Setenv("API_URL", "http://localhost:8080")

		bom := tree.ToCycloneDX(metadata, nil)

		require.NotNil(t, bom.ExternalReferences)
		typeCount := make(map[cdx.ExternalReferenceType]int)
		for _, ref := range *bom.ExternalReferences {
			typeCount[ref.Type]++
			switch ref.Type {
			case cdx.ERTypeExploitabilityStatement:
				assert.Contains(t, ref.URL, "/vex.json/")
			case cdx.ERTypeBOM:
				assert.Contains(t, ref.URL, "/sbom.json/")
			case cdx.ERTypeDynamicAnalysisReport:
				assert.Contains(t, ref.URL, "/assets/my-asset/refs/main")
			}
		}
		assert.Equal(t, 1, typeCount[cdx.ERTypeExploitabilityStatement], "should have exactly one VEX URL")
		assert.Equal(t, 1, typeCount[cdx.ERTypeBOM], "should have exactly one SBOM URL")
		assert.Equal(t, 1, typeCount[cdx.ERTypeDynamicAnalysisReport], "should have exactly one Dashboard URL")
	})
}

// TestDependencyGraphDirectDeps ports the "loading the sbom-dependency-tree.json
// should have only two direct dependencies" regression: buildMerkleDependencyMap
// (the successor of the old dependency-map construction it exercised) must
// still resolve the fixture to exactly two top-level dependencies.
func TestDependencyGraphDirectDeps(t *testing.T) {
	b, err := os.Open("testdata/sbom-dependency-tree.json")
	require.NoError(t, err)
	defer b.Close()

	var sbom cdx.BOM
	require.NoError(t, cdx.NewBOMDecoder(b, cdx.BOMFileFormatJSON).Decode(&sbom))

	parsed, err := MerkleTreeFromCycloneDX(&sbom, "artifact")
	require.NoError(t, err)

	directDeps := parsed.Tree.DirectDependencies()
	assert.Len(t, directDeps, 2)
	// the encoded "%40" in the fixture's purl is unescaped by
	// sanitizeCycloneDXComponent, unlike the old graph's raw BOMRef keys
	assert.Contains(t, directDeps, "pkg:npm/@l3montree/service-app@1.0.0")
	assert.Contains(t, directDeps, "pkg:npm/express@4.22.1")
}
