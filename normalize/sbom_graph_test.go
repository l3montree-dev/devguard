package normalize

import (
	"slices"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
)

var GraphRootNodeIDMetadata = &cdx.Metadata{
	Component: &cdx.Component{
		BOMRef: GraphRootNodeID,
	},
}

func TestSBOMGraphFromCycloneDX(t *testing.T) {
	artifactName := "test-artifact"
	origin := "test-origin"

	t.Run("basic component without properties", func(t *testing.T) {
		bom := &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef: GraphRootNodeID,
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
				{Ref: GraphRootNodeID, Dependencies: &[]string{
					"pkg:npm/test-component@1.0.0",
				}},
			},
		}

		result := SBOMGraphFromCycloneDX(bom, artifactName, origin)
		component := slices.Collect(result.Components())[0] // index 0 is the artifact name

		assert.Equal(t, "test-component", component.Component.Name)
		assert.Equal(t, "1.0.0", component.Component.Version)
		assert.Contains(t, component.Component.PackageURL, "test-component")
	})

	t.Run("GraphRootNodeID ref not in dependencies - single top-level component", func(t *testing.T) {
		// This tests the case where the GraphRootNodeID BOMRef is NOT part of any dependency entry
		// The function should find all components not referenced by any other dependency
		// and add them as direct children of GraphRootNodeID
		bom := &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef: GraphRootNodeID,
				},
			},
			Components: &[]cdx.Component{
				{
					BOMRef:     "pkg:npm/component-a@1.0.0",
					Name:       "component-a",
					Version:    "1.0.0",
					PackageURL: "pkg:npm/component-a@1.0.0",
					Type:       cdx.ComponentTypeLibrary,
				},
			},
			// Note: GraphRootNodeID is NOT in dependencies, only component-a has an entry
			Dependencies: &[]cdx.Dependency{
				{Ref: "pkg:npm/component-a@1.0.0", Dependencies: &[]string{}},
			},
		}

		result := SBOMGraphFromCycloneDX(bom, artifactName, origin)

		// Verify the component is reachable from GraphRootNodeID
		components := result.Components()
		assert.NotNil(t, components)

		// Check that component-a is included
		found := false
		for comp := range components {
			if comp.Component.BOMRef == "pkg:npm/component-a@1.0.0" {
				found = true
				break
			}
		}
		assert.True(t, found, "component-a should be reachable from GraphRootNodeID")
	})

	t.Run("GraphRootNodeID ref not in dependencies - multiple top-level components", func(t *testing.T) {
		// Tests case where multiple components are not referenced by any other dependency
		// All should become direct children of GraphRootNodeID
		bom := &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef: GraphRootNodeID,
				},
			},
			Components: &[]cdx.Component{
				{
					BOMRef:     "pkg:npm/component-a@1.0.0",
					Name:       "component-a",
					Version:    "1.0.0",
					PackageURL: "pkg:npm/component-a@1.0.0",
					Type:       cdx.ComponentTypeLibrary,
				},
				{
					BOMRef:     "pkg:npm/component-b@2.0.0",
					Name:       "component-b",
					Version:    "2.0.0",
					PackageURL: "pkg:npm/component-b@2.0.0",
					Type:       cdx.ComponentTypeLibrary,
				},
			},
			// Neither component is referenced by any other - both should become GraphRootNodeID children
			Dependencies: &[]cdx.Dependency{
				{Ref: "pkg:npm/component-a@1.0.0", Dependencies: &[]string{}},
				{Ref: "pkg:npm/component-b@2.0.0", Dependencies: &[]string{}},
			},
		}

		result := SBOMGraphFromCycloneDX(bom, artifactName, origin)
		components := result.Components()
		assert.NotNil(t, components)

		// Both components should be reachable
		componentRefs := make(map[string]bool)
		for comp := range components {
			componentRefs[comp.Component.BOMRef] = true
		}
		assert.True(t, componentRefs["pkg:npm/component-a@1.0.0"], "component-a should be included")
		assert.True(t, componentRefs["pkg:npm/component-b@2.0.0"], "component-b should be included")
	})

	t.Run("GraphRootNodeID ref not in dependencies - nested dependency tree", func(t *testing.T) {
		// Tests case where there's a dependency tree but GraphRootNodeID is not connected
		// Only top-level components (not referenced by others) should become GraphRootNodeID children
		bom := &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef: GraphRootNodeID,
				},
			},
			Components: &[]cdx.Component{
				{
					BOMRef:     "pkg:npm/parent@1.0.0",
					Name:       "parent",
					Version:    "1.0.0",
					PackageURL: "pkg:npm/parent@1.0.0",
					Type:       cdx.ComponentTypeLibrary,
				},
				{
					BOMRef:     "pkg:npm/child@1.0.0",
					Name:       "child",
					Version:    "1.0.0",
					PackageURL: "pkg:npm/child@1.0.0",
					Type:       cdx.ComponentTypeLibrary,
				},
				{
					BOMRef:     "pkg:npm/grandchild@1.0.0",
					Name:       "grandchild",
					Version:    "1.0.0",
					PackageURL: "pkg:npm/grandchild@1.0.0",
					Type:       cdx.ComponentTypeLibrary,
				},
			},
			// parent -> child -> grandchild, but GraphRootNodeID is not connected
			Dependencies: &[]cdx.Dependency{
				{Ref: "pkg:npm/parent@1.0.0", Dependencies: &[]string{"pkg:npm/child@1.0.0"}},
				{Ref: "pkg:npm/child@1.0.0", Dependencies: &[]string{"pkg:npm/grandchild@1.0.0"}},
				{Ref: "pkg:npm/grandchild@1.0.0", Dependencies: &[]string{}},
			},
		}

		result := SBOMGraphFromCycloneDX(bom, artifactName, origin)
		components := result.Components()
		assert.NotNil(t, components)

		// All components should be reachable (parent becomes GraphRootNodeID child, others through parent)
		componentRefs := make(map[string]bool)
		for comp := range components {
			componentRefs[comp.Component.BOMRef] = true
		}
		assert.True(t, componentRefs["pkg:npm/parent@1.0.0"], "parent should be included")
		assert.True(t, componentRefs["pkg:npm/child@1.0.0"], "child should be included")
		assert.True(t, componentRefs["pkg:npm/grandchild@1.0.0"], "grandchild should be included")
	})

	t.Run("GraphRootNodeID ref not in dependencies - mixed top-level and nested", func(t *testing.T) {
		// Tests case with multiple separate subtrees - each top-level should become GraphRootNodeID child
		bom := &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef: GraphRootNodeID,
				},
			},
			Components: &[]cdx.Component{
				{
					BOMRef:     "pkg:npm/tree1-GraphRootNodeID@1.0.0",
					Name:       "tree1-GraphRootNodeID",
					Version:    "1.0.0",
					PackageURL: "pkg:npm/tree1-GraphRootNodeID@1.0.0",
					Type:       cdx.ComponentTypeLibrary,
				},
				{
					BOMRef:     "pkg:npm/tree1-child@1.0.0",
					Name:       "tree1-child",
					Version:    "1.0.0",
					PackageURL: "pkg:npm/tree1-child@1.0.0",
					Type:       cdx.ComponentTypeLibrary,
				},
				{
					BOMRef:     "pkg:npm/tree2-GraphRootNodeID@1.0.0",
					Name:       "tree2-GraphRootNodeID",
					Version:    "1.0.0",
					PackageURL: "pkg:npm/tree2-GraphRootNodeID@1.0.0",
					Type:       cdx.ComponentTypeLibrary,
				},
			},
			// Two separate subtrees, neither connected to GraphRootNodeID
			Dependencies: &[]cdx.Dependency{
				{Ref: "pkg:npm/tree1-GraphRootNodeID@1.0.0", Dependencies: &[]string{"pkg:npm/tree1-child@1.0.0"}},
				{Ref: "pkg:npm/tree1-child@1.0.0", Dependencies: &[]string{}},
				{Ref: "pkg:npm/tree2-GraphRootNodeID@1.0.0", Dependencies: &[]string{}},
			},
		}

		result := SBOMGraphFromCycloneDX(bom, artifactName, origin)
		components := result.Components()
		assert.NotNil(t, components)

		// All three components should be reachable
		componentRefs := make(map[string]bool)
		for comp := range components {
			componentRefs[comp.Component.BOMRef] = true
		}
		assert.True(t, componentRefs["pkg:npm/tree1-GraphRootNodeID@1.0.0"], "tree1-GraphRootNodeID should be included")
		assert.True(t, componentRefs["pkg:npm/tree1-child@1.0.0"], "tree1-child should be included")
		assert.True(t, componentRefs["pkg:npm/tree2-GraphRootNodeID@1.0.0"], "tree2-GraphRootNodeID should be included")
	})

}

func TestMergeCdxBoms(t *testing.T) {
	t.Run("merge two BOMs with different components", func(t *testing.T) {
		bom1 := &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "GraphRootNodeID-bom-1"},
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
				{Ref: "GraphRootNodeID-bom-1", Dependencies: &[]string{"pkg:npm/component-1@1.0.0"}},
			},
		}

		bom2 := &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "GraphRootNodeID-bom-2"},
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
				{Ref: "GraphRootNodeID-bom-2", Dependencies: &[]string{"pkg:npm/component-2@2.0.0"}},
			},
		}

		result := NewSBOMGraph()
		result.MergeGraph(SBOMGraphFromCycloneDX(bom1, "artifact-1", "sbom-1"))
		result.MergeGraph(SBOMGraphFromCycloneDX(bom2, "artifact-2", "sbom-2"))

		expected := &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef: "merged-artifact",
				},
			},
			Components: &[]cdx.Component{
				{
					BOMRef: "merged-artifact",
				},
				{
					BOMRef: "pkg:npm/component-2@2.0.0",
				},
				{
					BOMRef: "pkg:npm/component-1@1.0.0",
				},
			},
			Dependencies: &[]cdx.Dependency{
				{Ref: "merged-artifact", Dependencies: &[]string{"pkg:npm/component-1@1.0.0", "pkg:npm/component-2@2.0.0"}},
				{Ref: "pkg:npm/component-1@1.0.0", Dependencies: &[]string{}},
				{Ref: "pkg:npm/component-2@2.0.0", Dependencies: &[]string{}},
			},
		}

		actual := result.ToCycloneDX(BOMMetadata{
			ArtifactName: "merged-artifact",
		})

		assert.Nil(t, StructuralCompareCdxBoms(actual, expected))
	})

	t.Run("merge BOMs with duplicate components", func(t *testing.T) {
		bom1 := &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "GraphRootNodeID-bom-1"},
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
				{Ref: "GraphRootNodeID-bom-1", Dependencies: &[]string{"pkg:npm/component-1@1.0.0"}},
			},
		}

		bom2 := &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "GraphRootNodeID-bom-2"},
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
				{Ref: "GraphRootNodeID-bom-2", Dependencies: &[]string{"pkg:npm/component-1@1.0.0"}},
			},
		}

		result := NewSBOMGraph()
		result.MergeGraph(SBOMGraphFromCycloneDX(bom1, "artifact-1", "test"))
		result.MergeGraph(SBOMGraphFromCycloneDX(bom2, "artifact-2", "test"))

		expected := &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef: "merged-artifact",
				},
			},
			Components: &[]cdx.Component{
				{
					BOMRef: "merged-artifact",
				},
				{
					BOMRef: "pkg:npm/component-1@1.0.0",
				},
			},
			Dependencies: &[]cdx.Dependency{
				{Ref: "merged-artifact", Dependencies: &[]string{"pkg:npm/component-1@1.0.0"}},
				{Ref: "pkg:npm/component-1@1.0.0", Dependencies: &[]string{}},
			},
		}

		assert.Nil(t, StructuralCompareCdxBoms(result.ToCycloneDX(BOMMetadata{
			ArtifactName: "merged-artifact",
		}), expected))
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

	normalized := SBOMGraphFromCycloneDX(b1, "test", "test")
	assert.NotNil(t, normalized)
}

func TestMergeCdxBomsSimple(t *testing.T) {
	b1 := &cdx.BOM{
		Metadata: GraphRootNodeIDMetadata,
		Components: &[]cdx.Component{{
			Name:       "comp-a",
			PackageURL: "pkg:maven/org.example/comp-a@1.0.0",
		}},
	}
	b2 := &cdx.BOM{
		Metadata: GraphRootNodeIDMetadata,
		Components: &[]cdx.Component{{
			Name:       "comp-b",
			PackageURL: "pkg:maven/org.example/comp-b@2.0.0",
		}},
		Vulnerabilities: &[]cdx.Vulnerability{{
			ID: "CVE-XYZ",
		}},
	}

	result := NewSBOMGraph()
	result.MergeGraph(SBOMGraphFromCycloneDX(b1, "artifact-1", "test"))
	result.MergeGraph(SBOMGraphFromCycloneDX(b2, "artifact-2", "test"))
	result.ToCycloneDX(BOMMetadata{})

	assert.Len(t, slices.Collect(result.Vulnerabilities()), 1)
}

func TestMergeComplex(t *testing.T) {
	artifactName := "test-artifact"

	t.Run("should add the subtree if it does not exist", func(t *testing.T) {
		currentSbom := &cdx.BOM{
			Metadata: GraphRootNodeIDMetadata,
			Components: &[]cdx.Component{
				{
					BOMRef: GraphRootNodeID,
				},
				{
					BOMRef: "pkg:container",
				},
			},
			Dependencies: &[]cdx.Dependency{
				{
					Ref: GraphRootNodeID,
					Dependencies: &[]string{
						"pkg:container",
					},
				},
			},
		}
		newSubtree := &cdx.BOM{
			Metadata: GraphRootNodeIDMetadata,
			Components: &[]cdx.Component{
				{
					BOMRef: GraphRootNodeID,
				},
				{
					BOMRef: "pkg:source",
				},
			},
			Dependencies: &[]cdx.Dependency{
				{
					Ref: GraphRootNodeID,
					Dependencies: &[]string{
						"pkg:source",
					},
				},
			},
		}

		currentGraph := SBOMGraphFromCycloneDX(currentSbom, artifactName, "container-scan")
		newGraph := SBOMGraphFromCycloneDX(newSubtree, artifactName, "source-scan")
		currentGraph.MergeGraph(newGraph)

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

		assert.Nil(t, StructuralCompareCdxBoms(currentGraph.ToCycloneDX(BOMMetadata{
			ArtifactName: artifactName,
		}), expected))
	})

	t.Run("should update the subtree if it does already exist", func(t *testing.T) {
		currentSbom := &cdx.BOM{
			Metadata: GraphRootNodeIDMetadata,
			Components: &[]cdx.Component{
				{
					BOMRef: GraphRootNodeID,
				},
				{
					BOMRef: "pkg:container@1.0.0",
				},
			},
			Dependencies: &[]cdx.Dependency{
				{
					Ref: GraphRootNodeID,
					Dependencies: &[]string{
						"pkg:container@1.0.0",
					},
				},
			},
		}
		newSubtree := &cdx.BOM{
			Metadata: GraphRootNodeIDMetadata,
			Components: &[]cdx.Component{
				{
					BOMRef: GraphRootNodeID,
				},
				{
					BOMRef: "pkg:container@2.0.0",
				},
			},
			Dependencies: &[]cdx.Dependency{
				{
					Ref: GraphRootNodeID,
					Dependencies: &[]string{
						"pkg:container@2.0.0",
					},
				},
			},
		}

		resultGraph := SBOMGraphFromCycloneDX(currentSbom, artifactName, "container-scan")

		subtree := SBOMGraphFromCycloneDX(newSubtree, artifactName, "container-scan")
		resultGraph.MergeGraph(subtree)

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

		assert.Nil(t, StructuralCompareCdxBoms(resultGraph.ToCycloneDX(BOMMetadata{
			ArtifactName: artifactName,
		}), expected))
	})

}

func TestCalculateDepth(t *testing.T) {
	t.Run("calculateDepth with valid tree", func(t *testing.T) {
		bom := SBOMGraphFromCycloneDX(&cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef: "pkg:GraphRootNodeID",
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
					Ref: "pkg:GraphRootNodeID",
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
		}, "pkg:artifact", "origin")

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
		bom := SBOMGraphFromCycloneDX(&cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef: "pkg:devguard/testorg/testgroup/testdepth",
				},
			},
			Components: &[]cdx.Component{
				{
					BOMRef: "pkg:devguard/testorg/testgroup/testdepth",
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
					Ref: "pkg:devguard/testorg/testgroup/testdepth",
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
		}, "pkg:artifact", "origin")

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
		bom := SBOMGraphFromCycloneDX(&cdx.BOM{
			Components:   &[]cdx.Component{},
			Dependencies: &[]cdx.Dependency{},
		}, "pkg:artifact", "origin")

		actual := bom.CalculateDepth()

		if len(actual) != 0 {
			t.Errorf("expected empty depth map, got %v", actual)
		}
	})

	t.Run("calculate depth with vex AND sbom path", func(t *testing.T) {
		bom := SBOMGraphFromCycloneDX(&cdx.BOM{
			Components: &[]cdx.Component{
				{
					BOMRef:     "pkg:devguard/testorg/testgroup/testdepth",
					PackageURL: "pkg:devguard/testorg/testgroup/testdepth",
				},
				{
					BOMRef:     "pkg:golang/a",
					PackageURL: "pkg:golang/a",
				},
				{
					BOMRef:     "pkg:golang/b",
					PackageURL: "pkg:golang/b",
				},
				{
					BOMRef:     "pkg:golang/c",
					PackageURL: "pkg:golang/c",
				},
			},
			Dependencies: &[]cdx.Dependency{
				{
					Ref: "pkg:devguard/testorg/testgroup/testdepth",
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
		}, "artifact", "test")

		// lets merge a vex that adds a false positive to golang/c
		vex := SBOMGraphFromCycloneDX(&cdx.BOM{

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
		}, "artifact", "vex")
		vex.MergeGraph(bom)
		actual := bom.CalculateDepth()

		expectedDepths := map[string]int{
			"pkg:golang/c": 4, // GraphRootNodeID -> artifact -> test -> pkg:devguard/testorg/testgroup/testdepth -> pkg:golang/a -> pkg:golang/b -> pkg:golang/c
		}

		for node, expectedDepth := range expectedDepths {
			if actual[node] != expectedDepth {
				t.Errorf("expected depth of %s to be %d, got %d", node, expectedDepth, actual[node])
			}
		}
	})
}
