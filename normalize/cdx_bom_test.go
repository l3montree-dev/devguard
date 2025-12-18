package normalize_test

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/stretchr/testify/assert"
)

var rootMetadata = &cdx.Metadata{
	Component: &cdx.Component{
		BOMRef: "root",
	},
}

func TestFromCdxBom(t *testing.T) {
	artifactName := "test-artifact"
	origin := "test-origin"

	t.Run("basic component without properties", func(t *testing.T) {
		bom := &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef: "root",
				},
			},
			Components: &[]cdx.Component{{
				BOMRef:     "pkg:npm/test-component@1.0.0",
				Name:       "test-component",
				Version:    "1.0.0",
				PackageURL: "pkg:npm/test-component@1.0.0",
				Type:       cdx.ComponentTypeLibrary,
			}},
			Dependencies: &[]cdx.Dependency{
				{Ref: "root", Dependencies: &[]string{
					"pkg:npm/test-component@1.0.0",
				}},
			},
		}

		result := normalize.FromCdxBom(bom, artifactName, origin, "sbom")
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
					Metadata: &cdx.Metadata{
						Component: &cdx.Component{
							BOMRef: "root",
						},
					},
					Components: &[]cdx.Component{{
						BOMRef:     "pkg:npm/old-pkg-id@1.0.0",
						Name:       "test-component",
						Version:    "1.0.0",
						PackageURL: "pkg:npm/old-pkg-id@1.0.0",
						Type:       cdx.ComponentTypeLibrary,
						Properties: &properties,
					}},
					Dependencies: &[]cdx.Dependency{
						{Ref: "root", Dependencies: &[]string{
							"pkg:npm/old-pkg-id@1.0.0",
						}},
					},
				}

				result := normalize.FromCdxBom(bom, artifactName, origin, "sbom")
				component := (*result.GetComponents())[0]

				assert.Contains(t, component.PackageURL, tc.expectContains)
				if !tc.expectUpdate {
					assert.NotContains(t, component.PackageURL, "actual-source-name@2.1.0")
				}
			})
		}
	})

	t.Run("multiple components", func(t *testing.T) {
		bom := &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef: "root",
				},
			},
			Components: &[]cdx.Component{
				{
					Name:       "component-1",
					Version:    "1.0.0",
					PackageURL: "pkg:npm/pkg-id-1@1.0.0",
					BOMRef:     "pkg:npm/pkg-id-1@1.0.0",
					Properties: &[]cdx.Property{
						{Name: "aquasecurity:trivy:SrcName", Value: "source-name-1"},
						{Name: "aquasecurity:trivy:SrcVersion", Value: "1.0.0"},
						{Name: "aquasecurity:trivy:PkgID", Value: "pkg-id-1"},
					},
				},
				{
					Name:       "component-2",
					Version:    "2.0.0",
					BOMRef:     "pkg:npm/pkg-id-2@2.0.0",
					PackageURL: "pkg:npm/pkg-id-2@2.0.0",
					Properties: &[]cdx.Property{
						{Name: "aquasecurity:trivy:SrcName", Value: "source-name-2"},
						{Name: "aquasecurity:trivy:SrcVersion", Value: "2.0.0"},
						{Name: "aquasecurity:trivy:PkgID", Value: "pkg-id-2"},
					},
				},
				{
					Name:       "component-3",
					Version:    "3.0.0",
					PackageURL: "pkg:npm/component-3@3.0.0",
					BOMRef:     "pkg:npm/component-3@3.0.0",
				},
			},
			Dependencies: &[]cdx.Dependency{
				{
					Ref: "root",
					Dependencies: &[]string{
						"pkg:npm/pkg-id-1@1.0.0",
						"pkg:npm/pkg-id-2@2.0.0",
						"pkg:npm/component-3@3.0.0",
					},
				},
			},
		}

		result := normalize.FromCdxBom(bom, artifactName, origin, "sbom")
		components := *result.GetComponents()

		assert.Len(t, components, len(*bom.Components)+1) // +1 for artifact
		assert.Contains(t, components[0].PackageURL, "source-name-1@1.0.0")
		assert.Contains(t, components[1].PackageURL, "source-name-2@2.0.0")
		assert.Contains(t, components[2].PackageURL, "component-3")
	})

	t.Run("empty components", func(t *testing.T) {
		bom := &cdx.BOM{Components: &[]cdx.Component{}}
		bom.Dependencies = &[]cdx.Dependency{}
		bom.Components = &[]cdx.Component{}
		bom.Metadata = &cdx.Metadata{
			Component: &cdx.Component{
				BOMRef:     "root",
				PackageURL: "root",
			},
		}
		result := normalize.FromCdxBom(bom, artifactName, origin, "sbom")
		assert.Len(t, *result.GetComponents(), 1) // there is only the root artifactName
	})

	t.Run("component with mixed properties", func(t *testing.T) {
		bom := &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef: "root",
				},
			},
			Components: &[]cdx.Component{{
				Name:       "test-component",
				Version:    "1.0.0",
				PackageURL: "pkg:npm/old-pkg-id@1.0.0",
				BOMRef:     "pkg:npm/old-pkg-id@1.0.0",
				Properties: &[]cdx.Property{
					{Name: "aquasecurity:trivy:SrcName", Value: "actual-source-name"},
					{Name: "aquasecurity:trivy:SrcVersion", Value: "2.1.0"},
					{Name: "aquasecurity:trivy:PkgID", Value: "old-pkg-id"},
					{Name: "aquasecurity:trivy:Other", Value: "some-other-value"},
					{Name: "some:other:property", Value: "not-trivy-property"},
				},
			}},
			Dependencies: &[]cdx.Dependency{{
				Ref: "root", Dependencies: &[]string{
					"pkg:npm/old-pkg-id@1.0.0",
				},
			},
			},
		}

		result := normalize.FromCdxBom(bom, artifactName, origin, "sbom")
		component := (*result.GetComponents())[0]

		assert.Contains(t, component.PackageURL, "actual-source-name@2.1.0")
		assert.NotContains(t, component.PackageURL, "old-pkg-id")
	})
}

func TestMergeCdxBoms(t *testing.T) {
	t.Run("merge two BOMs with different components", func(t *testing.T) {
		bom1 := &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "root-bom-1"},
			},
			Components: &[]cdx.Component{
				{
					Name:       "component-1",
					Version:    "1.0.0",
					PackageURL: "pkg:npm/component-1@1.0.0",
					BOMRef:     "pkg:npm/component-1@1.0.0",
					Type:       cdx.ComponentTypeLibrary,
				},
			},
			Dependencies: &[]cdx.Dependency{
				{Ref: "root-bom-1", Dependencies: &[]string{"pkg:npm/component-1@1.0.0"}},
			},
		}

		bom2 := &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "root-bom-2"},
			},
			Components: &[]cdx.Component{
				{
					Name:       "component-2",
					Version:    "2.0.0",
					PackageURL: "pkg:npm/component-2@2.0.0",
					BOMRef:     "pkg:npm/component-2@2.0.0",
					Type:       cdx.ComponentTypeLibrary,
				},
			},
			Dependencies: &[]cdx.Dependency{
				{Ref: "root-bom-2", Dependencies: &[]string{"pkg:npm/component-2@2.0.0"}},
			},
		}

		result := normalize.MergeCdxBoms(rootMetadata, "merged-artifact", normalize.FromCdxBom(bom1, "artifact-1", "test", "sbom"), normalize.FromCdxBom(bom2, "artifact-2", "test", "sbom"))

		expected := &cdx.BOM{
			Metadata: rootMetadata,
			Components: &[]cdx.Component{
				{
					BOMRef: "root",
				},
				{
					BOMRef: "pkg:npm/component-2@2.0.0",
				},
				{
					BOMRef: "pkg:npm/component-1@1.0.0",
				},
			},
			Dependencies: &[]cdx.Dependency{
				{Ref: "root", Dependencies: &[]string{"pkg:npm/component-1@1.0.0", "pkg:npm/component-2@2.0.0"}},
				{Ref: "pkg:npm/component-1@1.0.0", Dependencies: &[]string{}},
				{Ref: "pkg:npm/component-2@2.0.0", Dependencies: &[]string{}},
			},
		}

		assert.Nil(t, normalize.StructuralCompareCdxBoms(result.EjectSBOM(nil), expected))

	})

	t.Run("merge BOMs with duplicate components", func(t *testing.T) {
		bom1 := &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "root-bom-1"},
			},
			Components: &[]cdx.Component{
				{
					Name:       "component-1",
					Version:    "1.0.0",
					PackageURL: "pkg:npm/component-1@1.0.0",
					BOMRef:     "pkg:npm/component-1@1.0.0",
					Type:       cdx.ComponentTypeLibrary,
				},
			},
			Dependencies: &[]cdx.Dependency{
				{Ref: "root-bom-1", Dependencies: &[]string{"pkg:npm/component-1@1.0.0"}},
			},
		}

		bom2 := &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "root-bom-2"},
			},
			Components: &[]cdx.Component{
				{
					Name:       "component-2",
					Version:    "1.0.0",
					PackageURL: "pkg:npm/component-1@1.0.0",
					BOMRef:     "pkg:npm/component-1@1.0.0",
					Type:       cdx.ComponentTypeLibrary,
				},
			},
			Dependencies: &[]cdx.Dependency{
				{Ref: "root-bom-2", Dependencies: &[]string{"pkg:npm/component-1@1.0.0"}},
			},
		}

		result := normalize.MergeCdxBoms(rootMetadata, "merged-artifact", normalize.FromCdxBom(bom1, "artifact-1", "test", "sbom"), normalize.FromCdxBom(bom2, "artifact-2", "test", "sbom"))

		expected := &cdx.BOM{
			Metadata: rootMetadata,
			Components: &[]cdx.Component{
				{
					BOMRef: "root",
				},
				{
					BOMRef: "pkg:npm/component-1@1.0.0",
				},
			},
			Dependencies: &[]cdx.Dependency{
				{Ref: "root", Dependencies: &[]string{"pkg:npm/component-1@1.0.0"}},
				{Ref: "pkg:npm/component-1@1.0.0", Dependencies: &[]string{}},
			},
		}

		assert.Nil(t, normalize.StructuralCompareCdxBoms(result.EjectSBOM(nil), expected))
	})
}

func TestShouldNotCrashWithEmptyMetadataComponent(t *testing.T) {
	b1 := &cdx.BOM{
		Metadata: &cdx.Metadata{},
		Components: &[]cdx.Component{{
			Name:       "comp-a",
			PackageURL: "pkg:maven/org.example/comp-a@1.0.0",
		}},
	}

	normalized := normalize.FromCdxBom(b1, "test", "test", "sbom")
	assert.NotNil(t, normalized)
}

func TestMergeCdxBomsSimple(t *testing.T) {
	b1 := &cdx.BOM{
		Metadata: rootMetadata,
		Components: &[]cdx.Component{{
			Name:       "comp-a",
			PackageURL: "pkg:maven/org.example/comp-a@1.0.0",
		}},
	}
	b2 := &cdx.BOM{
		Metadata: rootMetadata,
		Components: &[]cdx.Component{{
			Name:       "comp-b",
			PackageURL: "pkg:maven/org.example/comp-b@2.0.0",
		}},
		Vulnerabilities: &[]cdx.Vulnerability{{
			ID: "CVE-XYZ",
		}},
	}

	merged := normalize.MergeCdxBoms(rootMetadata, "merged-artifact", normalize.FromCdxBom(b1, "artifact-1", "test", "sbom"), normalize.FromCdxBom(b2, "artifact-2", "test", "sbom")).EjectVex(nil)

	assert.Len(t, *merged.Vulnerabilities, 1)
}

func TestReplaceSubtree(t *testing.T) {
	artifactName := "test-artifact"

	t.Run("should add the subtree if it does not exist", func(t *testing.T) {
		currentSbom := &cdx.BOM{
			Metadata: rootMetadata,
			Components: &[]cdx.Component{
				{
					BOMRef: "root",
				},
				{
					BOMRef: "pkg:container",
				},
			},
			Dependencies: &[]cdx.Dependency{
				{
					Ref: "root",
					Dependencies: &[]string{
						"pkg:container",
					},
				},
			},
		}
		newSubtree := &cdx.BOM{
			Metadata: rootMetadata,
			Components: &[]cdx.Component{
				{
					BOMRef: "root",
				},
				{
					BOMRef: "pkg:source",
				},
			},
			Dependencies: &[]cdx.Dependency{
				{
					Ref: "root",
					Dependencies: &[]string{
						"pkg:source",
					},
				},
			},
		}

		rootCdx := normalize.FromCdxBom(currentSbom, artifactName, "test", "container-scan")
		subtree := normalize.FromCdxBom(newSubtree, artifactName, "test", "source-scan")
		for _, informationSourceNode := range subtree.GetInformationSourceNodes() {
			rootCdx.ReplaceOrAddInformationSourceNode(informationSourceNode)
		}

		expected := &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef: artifactName,
				},
			},
			Components: &[]cdx.Component{
				{
					BOMRef: artifactName,
				},
				{
					BOMRef: "pkg:container",
				},
				{
					BOMRef: "pkg:source",
				},
			},
			Dependencies: &[]cdx.Dependency{
				{
					Ref: artifactName,
					Dependencies: &[]string{
						"pkg:container",
						"pkg:source",
					},
				},
				{
					Ref:          "pkg:container",
					Dependencies: &[]string{},
				},
				{
					Ref:          "pkg:source",
					Dependencies: &[]string{},
				},
			},
		}

		assert.Nil(t, normalize.StructuralCompareCdxBoms(rootCdx.EjectSBOM(nil), expected))
	})

	t.Run("should update the subtree if it does already exist", func(t *testing.T) {
		currentSbom := &cdx.BOM{
			Metadata: rootMetadata,
			Components: &[]cdx.Component{
				{
					BOMRef: "root",
				},
				{
					BOMRef: "pkg:container@1.0.0",
				},
			},
			Dependencies: &[]cdx.Dependency{
				{
					Ref: "root",
					Dependencies: &[]string{
						"pkg:container@1.0.0",
					},
				},
			},
		}
		newSubtree := &cdx.BOM{
			Metadata: rootMetadata,
			Components: &[]cdx.Component{
				{
					BOMRef: "root",
				},
				{
					BOMRef: "pkg:container@2.0.0",
				},
			},
			Dependencies: &[]cdx.Dependency{
				{
					Ref: "root",
					Dependencies: &[]string{
						"pkg:container@2.0.0",
					},
				},
			},
		}

		rootCdx := normalize.FromCdxBom(currentSbom, artifactName, "test", "container-scan")
		subtree := normalize.FromCdxBom(newSubtree, artifactName, "test", "container-scan")
		for _, informationSourceNode := range subtree.GetInformationSourceNodes() {
			rootCdx.ReplaceOrAddInformationSourceNode(informationSourceNode)
		}

		expected := &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef: artifactName,
				},
			},
			Components: &[]cdx.Component{
				{
					BOMRef: artifactName,
				},
				{
					BOMRef: "pkg:container@2.0.0",
				},
			},
			Dependencies: &[]cdx.Dependency{
				{
					Ref: artifactName,
					Dependencies: &[]string{
						"pkg:container@2.0.0",
					},
				},
				{
					Ref:          "pkg:container@2.0.0",
					Dependencies: &[]string{},
				},
			},
		}

		assert.Nil(t, normalize.StructuralCompareCdxBoms(rootCdx.EjectSBOM(nil), expected))
	})

	t.Run("should replace ONLY the passed subtree", func(t *testing.T) {
		currentSbom := &cdx.BOM{
			Metadata: rootMetadata,
			Components: &[]cdx.Component{
				{
					BOMRef: "root",
				},
				{
					BOMRef: "pkg:container@1.0.0",
				},
			},
			Dependencies: &[]cdx.Dependency{
				{
					Ref: "root",
					Dependencies: &[]string{
						"pkg:container@1.0.0",
					},
				},
			},
		}

		sourceTree := &cdx.BOM{
			Metadata: rootMetadata,
			Components: &[]cdx.Component{
				{
					BOMRef: "root",
				},
				{
					BOMRef: "pkg:source@1.0.0",
				},
			},
			Dependencies: &[]cdx.Dependency{
				{
					Ref: "root",
					Dependencies: &[]string{
						"pkg:source@1.0.0",
					},
				},
			},
		}

		// add the source tree first
		rootCdx := normalize.FromCdxBom(currentSbom, artifactName, "test", "container-scan")
		sourceSubtree := normalize.FromCdxBom(sourceTree, artifactName, "test", "source-scan")
		for _, informationSourceNode := range sourceSubtree.GetInformationSourceNodes() {
			rootCdx.ReplaceOrAddInformationSourceNode(informationSourceNode)
		}

		newSubtree := &cdx.BOM{
			Metadata: rootMetadata,
			Components: &[]cdx.Component{
				{
					BOMRef: "root",
				},
				{
					BOMRef: "pkg:container@2.0.0",
				},
			},
			Dependencies: &[]cdx.Dependency{
				{
					Ref: "root",
					Dependencies: &[]string{
						"pkg:container@2.0.0",
					},
				},
			},
		}

		subtree := normalize.FromCdxBom(newSubtree, artifactName, "test", "container-scan")
		for _, informationSourceNode := range subtree.GetInformationSourceNodes() {
			rootCdx.ReplaceOrAddInformationSourceNode(informationSourceNode)
		}

		expected := &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef: artifactName,
				},
			},
			Components: &[]cdx.Component{
				{
					BOMRef: artifactName,
				},
				{
					BOMRef: "pkg:container@2.0.0",
				},
				{
					BOMRef: "pkg:source@1.0.0",
				},
			},
			Dependencies: &[]cdx.Dependency{
				{
					Ref: artifactName,
					Dependencies: &[]string{
						"pkg:container@2.0.0",
						"pkg:source@1.0.0",
					},
				},
				{
					Ref:          "pkg:source@1.0.0",
					Dependencies: &[]string{},
				},
				{
					Ref:          "pkg:container@2.0.0",
					Dependencies: &[]string{},
				},
			},
		}

		assert.Nil(t, normalize.StructuralCompareCdxBoms(rootCdx.EjectSBOM(nil), expected))
	})
}

func TestCalculateDepth(t *testing.T) {
	t.Run("calculateDepth with valid tree", func(t *testing.T) {
		bom := normalize.FromCdxBom(&cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef: "root",
				},
			},
			Components: &[]cdx.Component{
				{
					BOMRef: "pkg:golang/a",
				},
				{
					BOMRef: "pkg:golang/b",
				},
				{
					BOMRef: "pkg:golang/c",
				},
				{
					BOMRef: "pkg:golang/d",
				},
			},
			Dependencies: &[]cdx.Dependency{
				{
					Ref: "root",
					Dependencies: &[]string{
						"pkg:golang/a",
					},
				},
				{
					Ref: "pkg:golang/a",
					Dependencies: &[]string{
						"pkg:golang/b",
						"pkg:golang/c",
					},
				},
				{
					Ref: "pkg:golang/b",
					Dependencies: &[]string{
						"pkg:golang/d",
					},
				},
			},
		}, "artifact", "test", "origin")

		actual := bom.CalculateDepth()

		expectedDepths := map[string]int{
			"pkg:golang/a": 1,
			"pkg:golang/b": 2,
			"pkg:golang/c": 2,
			"pkg:golang/d": 3,
		}

		for node, expectedDepth := range expectedDepths {
			if actual[node] != expectedDepth {
				t.Errorf("expected depth of %s to be %d, got %d", node, expectedDepth, actual[node])
			}
		}
	})

	t.Run("calculateDepth with invalid PURL", func(t *testing.T) {
		bom := normalize.FromCdxBom(&cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef: "root",
				},
			},
			Components: &[]cdx.Component{
				{
					BOMRef: "root",
				},
				{
					BOMRef: "go.mod",
				},
				{
					BOMRef: "tmp",
				},
				{
					BOMRef: "pkg:golang/github.com/gorilla/websocket",
				},
			},
			Dependencies: &[]cdx.Dependency{
				{
					Ref: "root",
					Dependencies: &[]string{
						"go.mod",
					},
				},
				{
					Ref: "go.mod",
					Dependencies: &[]string{
						"tmp",
					},
				},
				{
					Ref: "tmp",
					Dependencies: &[]string{
						"pkg:golang/github.com/gorilla/websocket",
					},
				},
			},
		}, "artifact", "test", "origin")

		actual := bom.CalculateDepth()

		expectedDepths := map[string]int{
			"go.mod": 1,
			"tmp":    1,
			"pkg:golang/github.com/gorilla/websocket": 1,
		}

		for node, expectedDepth := range expectedDepths {
			if actual[node] != expectedDepth {
				t.Errorf("expected depth of %s to be %d, got %d", node, expectedDepth, actual[node])
			}
		}
	})

	t.Run("calculateDepth with empty tree", func(t *testing.T) {
		bom := normalize.FromCdxBom(&cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef: "root",
				},
			},
			Components:   &[]cdx.Component{},
			Dependencies: &[]cdx.Dependency{},
		}, "artifact", "test", "origin")

		actual := bom.CalculateDepth()

		if len(actual) != 3 || actual["artifact"] != 1 && actual["test"] != 1 && actual["root"] != 1 {
			t.Errorf("expected depth map to contain only artifact and origin with depth 1, got %v", actual)
		}
	})

	t.Run("calculate depth with vex AND sbom path", func(t *testing.T) {
		bom := normalize.FromCdxBom(&cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef: "root",
				},
			},
			Components: &[]cdx.Component{
				{
					BOMRef: "root",
				},
				{
					BOMRef: "pkg:golang/a",
				},
				{
					BOMRef: "pkg:golang/b",
				},
				{
					BOMRef: "pkg:golang/c",
				},
			},
			Dependencies: &[]cdx.Dependency{
				{
					Ref: "root",
					Dependencies: &[]string{
						"pkg:golang/a",
					},
				},
				{
					Ref: "pkg:golang/a",
					Dependencies: &[]string{
						"pkg:golang/b",
					},
				},
				{
					Ref: "pkg:golang/b",
					Dependencies: &[]string{
						"pkg:golang/c",
					},
				},
				{
					Ref:          "pkg:golang/c",
					Dependencies: &[]string{},
				},
			},
		}, "artifact", "test", "sbom")

		// lets merge a vex that adds a false positive to golang/c
		vex := normalize.FromCdxBom(&cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef: "root",
				},
			},
			Vulnerabilities: &[]cdx.Vulnerability{
				{
					ID: "CVE-2021",
					Affects: &[]cdx.Affects{
						{
							Ref: "pkg:golang/c",
						},
					},
				},
			},
		}, "artifact", "test", "vex")
		bom = normalize.MergeCdxBoms(rootMetadata, "artifact", bom, vex)
		actual := bom.CalculateDepth()

		expectedDepths := map[string]int{
			// the depth should remain the same even after merging the vex
			"pkg:golang/c": 3,
		}

		for node, expectedDepth := range expectedDepths {
			if actual[node] != expectedDepth {
				t.Errorf("expected depth of %s to be %d, got %d", node, expectedDepth, actual[node])
			}
		}
	})
}

func TestAddFakeMetadataRootComponent(t *testing.T) {
	t.Run("all unreferenced components become root dependencies", func(t *testing.T) {
		bom := &cdx.BOM{
			Metadata: &cdx.Metadata{},
			Components: &[]cdx.Component{
				{BOMRef: "pkg:npm/a@1.0.0", PackageURL: "pkg:npm/a@1.0.0"},
				{BOMRef: "pkg:npm/b@1.0.0", PackageURL: "pkg:npm/b@1.0.0"},
			},
			Dependencies: &[]cdx.Dependency{},
		}

		result := normalize.FromNormalizedCdxBom(bom, "app", "app", "test")
		deps := result.GetDependencies()

		var rootDep *cdx.Dependency
		for _, dep := range *deps {
			if dep.Ref == "app" {
				rootDep = &dep
				break
			}
		}

		assert.NotNil(t, rootDep)
		assert.ElementsMatch(t, []string{"pkg:npm/a@1.0.0", "pkg:npm/b@1.0.0"}, *rootDep.Dependencies)
	})

	t.Run("only top-level unreferenced components become root dependencies", func(t *testing.T) {
		bom := &cdx.BOM{
			Metadata: &cdx.Metadata{},
			Components: &[]cdx.Component{
				{BOMRef: "pkg:npm/parent@1.0.0", PackageURL: "pkg:npm/parent@1.0.0"},
				{BOMRef: "pkg:npm/child@1.0.0", PackageURL: "pkg:npm/child@1.0.0"},
			},
			Dependencies: &[]cdx.Dependency{
				{Ref: "pkg:npm/parent@1.0.0", Dependencies: &[]string{"pkg:npm/child@1.0.0"}},
			},
		}

		result := normalize.FromNormalizedCdxBom(bom, "app", "app", "test")
		deps := result.GetDependencies()

		var rootDep *cdx.Dependency
		for _, dep := range *deps {
			if dep.Ref == "app" {
				rootDep = &dep
				break
			}
		}

		assert.NotNil(t, rootDep)
		assert.Equal(t, []string{"pkg:npm/parent@1.0.0"}, *rootDep.Dependencies)
	})

	t.Run("empty BOM creates root with no dependencies", func(t *testing.T) {
		bom := &cdx.BOM{
			Metadata:     &cdx.Metadata{},
			Components:   &[]cdx.Component{},
			Dependencies: &[]cdx.Dependency{},
		}

		result := normalize.FromNormalizedCdxBom(bom, "app", "app", "test")
		metadata := result.GetMetadata()

		assert.NotNil(t, metadata.Component)
		assert.Equal(t, "app", metadata.Component.BOMRef)
		assert.Equal(t, cdx.ComponentType("application"), metadata.Component.Type)
	})
}
