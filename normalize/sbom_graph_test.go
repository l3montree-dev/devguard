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

		result := SBOMGraphFromCycloneDX(bom, artifactName, origin, false)
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

		result := SBOMGraphFromCycloneDX(bom, artifactName, origin, false)

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

		result := SBOMGraphFromCycloneDX(bom, artifactName, origin, false)
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

		result := SBOMGraphFromCycloneDX(bom, artifactName, origin, false)
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

		result := SBOMGraphFromCycloneDX(bom, artifactName, origin, false)
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

	t.Run("keepOriginalSbomRootComponent=false should redirect root children to info source", func(t *testing.T) {
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
					PackageURL: "pkg:npm/component-a@1.0.0",
					Type:       cdx.ComponentTypeLibrary,
				},
			},
			Dependencies: &[]cdx.Dependency{
				{Ref: GraphRootNodeID, Dependencies: &[]string{"pkg:npm/component-a@1.0.0"}},
			},
		}

		result := SBOMGraphFromCycloneDX(bom, artifactName, origin, false)

		// With keepOriginalSbomRootComponent=false, component-a should be a child of the info source, not the root
		// Verify the graph structure
		edges := result.Edges()
		foundEdge := false
		for parentID, childID := range edges {
			// The info source should have component-a as a child
			parentNode := result.nodes[parentID]
			if parentNode != nil && parentNode.Type == GraphNodeTypeInfoSource && childID == "pkg:npm/component-a@1.0.0" {
				foundEdge = true
				break
			}
		}
		assert.True(t, foundEdge, "component-a should be a child of the info source when keepOriginalSbomRootComponent=false")
	})

	t.Run("keepOriginalSbomRootComponent=true should preserve original root component with edge to it", func(t *testing.T) {
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
					PackageURL: "pkg:npm/component-a@1.0.0",
					Type:       cdx.ComponentTypeLibrary,
				},
			},
			Dependencies: &[]cdx.Dependency{
				{Ref: GraphRootNodeID, Dependencies: &[]string{"pkg:npm/component-a@1.0.0"}},
			},
		}

		result := SBOMGraphFromCycloneDX(bom, artifactName, origin, true)

		// With keepOriginalSbomRootComponent=true, we should have:
		// 1. An edge from info source to the original root ref
		// 2. An edge from root ref to component-a (not redirected to info source)
		edges := result.Edges()

		foundRootEdge := false
		foundComponentEdge := false

		for parentID, childID := range edges {
			parentNode := result.nodes[parentID]
			// Check for info source -> root edge
			if parentNode != nil && parentNode.Type == GraphNodeTypeInfoSource && childID == GraphRootNodeID {
				foundRootEdge = true
			}
			// Check for root -> component-a edge (not through info source)
			if parentID == GraphRootNodeID && childID == "pkg:npm/component-a@1.0.0" {
				foundComponentEdge = true
			}
		}

		assert.True(t, foundRootEdge, "info source should have an edge to the original root component when keepOriginalSbomRootComponent=true")
		assert.True(t, foundComponentEdge, "root component should have an edge to component-a when keepOriginalSbomRootComponent=true")
	})

	t.Run("keepOriginalSbomRootComponent=true with multiple root children", func(t *testing.T) {
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
					PackageURL: "pkg:npm/component-a@1.0.0",
					Type:       cdx.ComponentTypeLibrary,
				},
				{
					BOMRef:     "pkg:npm/component-b@2.0.0",
					Name:       "component-b",
					PackageURL: "pkg:npm/component-b@2.0.0",
					Type:       cdx.ComponentTypeLibrary,
				},
			},
			Dependencies: &[]cdx.Dependency{
				{Ref: GraphRootNodeID, Dependencies: &[]string{
					"pkg:npm/component-a@1.0.0",
					"pkg:npm/component-b@2.0.0",
				}},
			},
		}

		result := SBOMGraphFromCycloneDX(bom, artifactName, origin, true)

		// Both components should be children of root, not info source
		edges := result.Edges()
		componentAChildren := 0
		componentBChildren := 0

		for parentID, childID := range edges {
			if parentID == GraphRootNodeID {
				if childID == "pkg:npm/component-a@1.0.0" {
					componentAChildren++
				}
				if childID == "pkg:npm/component-b@2.0.0" {
					componentBChildren++
				}
			}
		}

		assert.Equal(t, 1, componentAChildren, "component-a should be a direct child of root")
		assert.Equal(t, 1, componentBChildren, "component-b should be a direct child of root")
	})

	t.Run("keepOriginalSbomRootComponent=true with no root dependencies", func(t *testing.T) {
		bom := &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef: GraphRootNodeID,
				},
			},
			Components: &[]cdx.Component{
				{
					BOMRef:     "pkg:npm/orphan-component@1.0.0",
					Name:       "orphan-component",
					PackageURL: "pkg:npm/orphan-component@1.0.0",
					Type:       cdx.ComponentTypeLibrary,
				},
			},
			Dependencies: &[]cdx.Dependency{
				{Ref: "pkg:npm/orphan-component@1.0.0", Dependencies: &[]string{}},
			},
		}

		result := SBOMGraphFromCycloneDX(bom, artifactName, origin, true)

		// Even with keepOriginalSbomRootComponent=true, orphan components should still be connected to info source
		edges := result.Edges()
		foundInfoSourceEdge := false

		for parentID, childID := range edges {
			parentNode := result.nodes[parentID]
			if parentNode != nil && parentNode.Type == GraphNodeTypeInfoSource && childID == "pkg:npm/orphan-component@1.0.0" {
				foundInfoSourceEdge = true
				break
			}
		}

		assert.True(t, foundInfoSourceEdge, "orphan components should be connected to info source")
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
		result.MergeGraph(SBOMGraphFromCycloneDX(bom1, "artifact-1", "sbom-1", false))
		result.MergeGraph(SBOMGraphFromCycloneDX(bom2, "artifact-2", "sbom-2", false))

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
		result.MergeGraph(SBOMGraphFromCycloneDX(bom1, "artifact-1", "test", false))
		result.MergeGraph(SBOMGraphFromCycloneDX(bom2, "artifact-2", "test", false))

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
		actual := result.ToCycloneDX(BOMMetadata{
			ArtifactName: "merged-artifact",
		})

		assert.Nil(t, StructuralCompareCdxBoms(actual, expected))
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

	normalized := SBOMGraphFromCycloneDX(b1, "test", "test", false)
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
	result.MergeGraph(SBOMGraphFromCycloneDX(b1, "artifact-1", "test", false))
	result.MergeGraph(SBOMGraphFromCycloneDX(b2, "artifact-2", "test", false))
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
					BOMRef:     "pkg:container",
					PackageURL: "pkg:container@1.0.0",
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
					BOMRef:     "pkg:source",
					PackageURL: "pkg:source@2.0.0",
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

		currentGraph := SBOMGraphFromCycloneDX(currentSbom, artifactName, "container-scan", false)
		newGraph := SBOMGraphFromCycloneDX(newSubtree, artifactName, "source-scan", false)
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
					BOMRef:     "pkg:container@2.0.0",
					PackageURL: "pkg:container@2.0.0",
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
		newSubtree := &cdx.BOM{
			Metadata: GraphRootNodeIDMetadata,
			Components: &[]cdx.Component{
				{
					BOMRef: GraphRootNodeID,
				},
				{
					BOMRef:     "pkg:container@2.0.0",
					PackageURL: "pkg:container@2.0.0",
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

		resultGraph := SBOMGraphFromCycloneDX(currentSbom, artifactName, "container-scan", false)

		subtree := SBOMGraphFromCycloneDX(newSubtree, artifactName, "container-scan", false)
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

func TestFindAllPathsToPURL(t *testing.T) {
	t.Run("multiple information sources pointing to same component - should return multiple paths", func(t *testing.T) {
		g := NewSBOMGraph()

		// Add artifact
		artifactID := g.AddArtifact("test-artifact")

		// Add two different info sources (SBOMs) under the same artifact
		infoSource1 := g.AddInfoSource(artifactID, "package-lock.json", InfoSourceSBOM)
		infoSource2 := g.AddInfoSource(artifactID, "yarn.lock", InfoSourceSBOM)

		// Add the same component under both info sources
		comp := cdx.Component{
			BOMRef:     "pkg:npm/lodash@4.17.21",
			Name:       "lodash",
			Version:    "4.17.21",
			PackageURL: "pkg:npm/lodash@4.17.21",
			Type:       cdx.ComponentTypeLibrary,
		}
		compID := g.AddComponent(comp)

		// Connect both info sources to the same component
		g.AddEdge(infoSource1, compID)
		g.AddEdge(infoSource2, compID)

		// Find all paths to the component
		paths := g.FindAllPathsToPURL("pkg:npm/lodash@4.17.21", 0)

		// Should return two paths (one through each info source)
		assert.Len(t, paths, 2, "Should return separate paths for each info source")

		// Both paths should have the same component-only representation
		assert.Equal(t, paths[0].ToStringSliceComponentOnly(), paths[1].ToStringSliceComponentOnly())
		assert.Equal(t, []string{"pkg:npm/lodash@4.17.21"}, paths[0].ToStringSliceComponentOnly())
	})

	t.Run("multiple artifacts pointing to same component - should return multiple paths", func(t *testing.T) {
		g := NewSBOMGraph()

		// Add two different artifacts
		artifact1ID := g.AddArtifact("app-frontend")
		artifact2ID := g.AddArtifact("app-backend")

		// Add info sources under each artifact
		infoSource1 := g.AddInfoSource(artifact1ID, "frontend-sbom", InfoSourceSBOM)
		infoSource2 := g.AddInfoSource(artifact2ID, "backend-sbom", InfoSourceSBOM)

		// Add the same component under both info sources
		comp := cdx.Component{
			BOMRef:     "pkg:npm/express@4.18.0",
			Name:       "express",
			Version:    "4.18.0",
			PackageURL: "pkg:npm/express@4.18.0",
			Type:       cdx.ComponentTypeLibrary,
		}
		compID := g.AddComponent(comp)

		// Connect both info sources to the same component
		g.AddEdge(infoSource1, compID)
		g.AddEdge(infoSource2, compID)

		// Find all paths to the component
		paths := g.FindAllPathsToPURL("pkg:npm/express@4.18.0", 0)

		// Should return two paths (one through each artifact)
		assert.Len(t, paths, 2, "Should return separate paths through different artifacts")

		// Both paths should have the same component-only representation
		assert.Equal(t, paths[0].ToStringSliceComponentOnly(), paths[1].ToStringSliceComponentOnly())
		assert.Equal(t, []string{"pkg:npm/express@4.18.0"}, paths[0].ToStringSliceComponentOnly())
	})

	t.Run("multiple dependency paths to same component - should return multiple paths", func(t *testing.T) {
		g := NewSBOMGraph()

		// Add artifact and info source
		artifactID := g.AddArtifact("test-app")
		infoSource := g.AddInfoSource(artifactID, "sbom.json", InfoSourceSBOM)

		// Create a diamond dependency structure:
		// infoSource -> depA -> target
		// infoSource -> depB -> target
		depA := cdx.Component{
			BOMRef:     "pkg:npm/dep-a@1.0.0",
			Name:       "dep-a",
			Version:    "1.0.0",
			PackageURL: "pkg:npm/dep-a@1.0.0",
			Type:       cdx.ComponentTypeLibrary,
		}
		depAID := g.AddComponent(depA)

		depB := cdx.Component{
			BOMRef:     "pkg:npm/dep-b@1.0.0",
			Name:       "dep-b",
			Version:    "1.0.0",
			PackageURL: "pkg:npm/dep-b@1.0.0",
			Type:       cdx.ComponentTypeLibrary,
		}
		depBID := g.AddComponent(depB)

		target := cdx.Component{
			BOMRef:     "pkg:npm/target@1.0.0",
			Name:       "target",
			Version:    "1.0.0",
			PackageURL: "pkg:npm/target@1.0.0",
			Type:       cdx.ComponentTypeLibrary,
		}
		targetID := g.AddComponent(target)

		// Build the graph
		g.AddEdge(infoSource, depAID)
		g.AddEdge(infoSource, depBID)
		g.AddEdge(depAID, targetID)
		g.AddEdge(depBID, targetID)

		// Find all paths to the target component
		paths := g.FindAllPathsToPURL("pkg:npm/target@1.0.0", 0)

		// Should return two different paths through different dependencies
		assert.Len(t, paths, 2, "Should return multiple paths when there are different dependency chains")

		// Verify the paths contain the expected components
		path1 := []string{"pkg:npm/dep-a@1.0.0", "pkg:npm/target@1.0.0"}
		path2 := []string{"pkg:npm/dep-b@1.0.0", "pkg:npm/target@1.0.0"}

		assert.Contains(t, [][]string{paths[0].ToStringSliceComponentOnly(), paths[1].ToStringSliceComponentOnly()}, path1, "Should contain path through dep-a")
		assert.Contains(t, [][]string{paths[0].ToStringSliceComponentOnly(), paths[1].ToStringSliceComponentOnly()}, path2, "Should contain path through dep-b")
	})

	t.Run("component not found - should return empty paths", func(t *testing.T) {
		g := NewSBOMGraph()

		// Add some components
		artifactID := g.AddArtifact("test-app")
		infoSource := g.AddInfoSource(artifactID, "sbom.json", InfoSourceSBOM)

		comp := cdx.Component{
			BOMRef:     "pkg:npm/existing@1.0.0",
			PackageURL: "pkg:npm/existing@1.0.0",
		}
		compID := g.AddComponent(comp)
		g.AddEdge(infoSource, compID)

		// Search for non-existent component
		paths := g.FindAllPathsToPURL("pkg:npm/non-existent@1.0.0", 0)

		assert.Len(t, paths, 0, "Should return empty paths for non-existent component")
	})

	t.Run("deep dependency chain - should return complete path", func(t *testing.T) {
		g := NewSBOMGraph()

		// Add artifact and info source
		artifactID := g.AddArtifact("test-app")
		infoSource := g.AddInfoSource(artifactID, "sbom.json", InfoSourceSBOM)

		// Create a chain: infoSource -> A -> B -> C -> D
		compA := cdx.Component{
			BOMRef:     "pkg:npm/a@1.0.0",
			PackageURL: "pkg:npm/a@1.0.0",
		}
		compAID := g.AddComponent(compA)

		compB := cdx.Component{
			BOMRef:     "pkg:npm/b@1.0.0",
			PackageURL: "pkg:npm/b@1.0.0",
		}
		compBID := g.AddComponent(compB)

		compC := cdx.Component{
			BOMRef:     "pkg:npm/c@1.0.0",
			PackageURL: "pkg:npm/c@1.0.0",
		}
		compCID := g.AddComponent(compC)

		compD := cdx.Component{
			BOMRef:     "pkg:npm/d@1.0.0",
			PackageURL: "pkg:npm/d@1.0.0",
		}
		compDID := g.AddComponent(compD)

		// Build the chain
		g.AddEdge(infoSource, compAID)
		g.AddEdge(compAID, compBID)
		g.AddEdge(compBID, compCID)
		g.AddEdge(compCID, compDID)

		// Find path to the deepest component
		paths := g.FindAllPathsToPURL("pkg:npm/d@1.0.0", 0)

		assert.Len(t, paths, 1)
		expectedPath := []string{
			"pkg:npm/a@1.0.0",
			"pkg:npm/b@1.0.0",
			"pkg:npm/c@1.0.0",
			"pkg:npm/d@1.0.0",
		}
		assert.Equal(t, expectedPath, paths[0].ToStringSliceComponentOnly(), "Should return complete dependency chain")
	})

	t.Run("limit should stop early and return shortest paths first", func(t *testing.T) {
		g := NewSBOMGraph()

		// Add artifact and info source
		artifactID := g.AddArtifact("test-app")
		infoSource := g.AddInfoSource(artifactID, "sbom.json", InfoSourceSBOM)

		// Create multiple paths of different lengths to target:
		// Short path: infoSource -> target (length 1)
		// Medium path: infoSource -> dep1 -> target (length 2)
		// Long path: infoSource -> dep2 -> dep3 -> target (length 3)
		target := cdx.Component{
			BOMRef:     "pkg:npm/target@1.0.0",
			PackageURL: "pkg:npm/target@1.0.0",
		}
		targetID := g.AddComponent(target)

		dep1 := cdx.Component{
			BOMRef:     "pkg:npm/dep1@1.0.0",
			PackageURL: "pkg:npm/dep1@1.0.0",
		}
		dep1ID := g.AddComponent(dep1)

		dep2 := cdx.Component{
			BOMRef:     "pkg:npm/dep2@1.0.0",
			PackageURL: "pkg:npm/dep2@1.0.0",
		}
		dep2ID := g.AddComponent(dep2)

		dep3 := cdx.Component{
			BOMRef:     "pkg:npm/dep3@1.0.0",
			PackageURL: "pkg:npm/dep3@1.0.0",
		}
		dep3ID := g.AddComponent(dep3)

		// Build the graph with multiple paths
		g.AddEdge(infoSource, targetID) // Direct path (shortest)
		g.AddEdge(infoSource, dep1ID)   // Path through dep1
		g.AddEdge(dep1ID, targetID)
		g.AddEdge(infoSource, dep2ID) // Path through dep2 -> dep3
		g.AddEdge(dep2ID, dep3ID)
		g.AddEdge(dep3ID, targetID)

		// Without limit, should return all 3 paths
		allPaths := g.FindAllPathsToPURL("pkg:npm/target@1.0.0", 0)
		assert.Len(t, allPaths, 3, "Should return all 3 paths without limit")

		// With limit=1, should return only the shortest path
		limitedPaths := g.FindAllPathsToPURL("pkg:npm/target@1.0.0", 1)
		assert.Len(t, limitedPaths, 1, "Should return only 1 path with limit=1")
		// The shortest path is the direct one
		assert.Equal(t, []string{"pkg:npm/target@1.0.0"}, limitedPaths[0].ToStringSliceComponentOnly())

		// With limit=2, should return 2 shortest paths
		limitedPaths2 := g.FindAllPathsToPURL("pkg:npm/target@1.0.0", 2)
		assert.Len(t, limitedPaths2, 2, "Should return only 2 paths with limit=2")
	})

	t.Run("limit should work with FindAllComponentOnlyPathsToPURL", func(t *testing.T) {
		g := NewSBOMGraph()

		artifactID := g.AddArtifact("test-app")
		infoSource := g.AddInfoSource(artifactID, "sbom.json", InfoSourceSBOM)

		// Create diamond pattern with multiple paths
		target := cdx.Component{BOMRef: "pkg:npm/target@1.0.0", PackageURL: "pkg:npm/target@1.0.0"}
		dep1 := cdx.Component{BOMRef: "pkg:npm/dep1@1.0.0", PackageURL: "pkg:npm/dep1@1.0.0"}
		dep2 := cdx.Component{BOMRef: "pkg:npm/dep2@1.0.0", PackageURL: "pkg:npm/dep2@1.0.0"}
		dep3 := cdx.Component{BOMRef: "pkg:npm/dep3@1.0.0", PackageURL: "pkg:npm/dep3@1.0.0"}

		targetID := g.AddComponent(target)
		dep1ID := g.AddComponent(dep1)
		dep2ID := g.AddComponent(dep2)
		dep3ID := g.AddComponent(dep3)

		// Multiple paths to target
		g.AddEdge(infoSource, dep1ID)
		g.AddEdge(infoSource, dep2ID)
		g.AddEdge(infoSource, dep3ID)
		g.AddEdge(dep1ID, targetID)
		g.AddEdge(dep2ID, targetID)
		g.AddEdge(dep3ID, targetID)

		// Without limit
		allPaths := g.FindAllComponentOnlyPathsToPURL("pkg:npm/target@1.0.0", 0)
		assert.Len(t, allPaths, 3, "Should return all 3 paths without limit")

		// With limit=2
		limitedPaths := g.FindAllComponentOnlyPathsToPURL("pkg:npm/target@1.0.0", 2)
		assert.Len(t, limitedPaths, 2, "Should return only 2 paths with limit=2")
	})
}

func TestVulnerabilities(t *testing.T) {
	t.Run("empty graph returns no vulnerabilities", func(t *testing.T) {
		g := NewSBOMGraph()

		vulns := slices.Collect(g.Vulnerabilities())
		assert.Empty(t, vulns)
	})

	t.Run("single vulnerability without analysis", func(t *testing.T) {
		g := NewSBOMGraph()
		g.AddVulnerability(cdx.Vulnerability{
			ID:          "CVE-2021-1234",
			Description: "Test vulnerability",
		})

		vulns := slices.Collect(g.Vulnerabilities())
		assert.Len(t, vulns, 1)
		assert.Equal(t, "CVE-2021-1234", vulns[0].ID)
	})

	t.Run("single vulnerability with analysis", func(t *testing.T) {
		g := NewSBOMGraph()
		g.AddVulnerability(cdx.Vulnerability{
			ID: "CVE-2021-1234",
			Analysis: &cdx.VulnerabilityAnalysis{
				State: cdx.IASExploitable,
			},
		})

		vulns := slices.Collect(g.Vulnerabilities())
		assert.Len(t, vulns, 1)
		assert.Equal(t, "CVE-2021-1234", vulns[0].ID)
		assert.Equal(t, cdx.IASExploitable, vulns[0].Analysis.State)
	})

	t.Run("multiple unique vulnerabilities", func(t *testing.T) {
		g := NewSBOMGraph()
		g.AddVulnerability(cdx.Vulnerability{ID: "CVE-2021-1111"})
		g.AddVulnerability(cdx.Vulnerability{ID: "CVE-2021-2222"})
		g.AddVulnerability(cdx.Vulnerability{ID: "CVE-2021-3333"})

		vulns := slices.Collect(g.Vulnerabilities())
		assert.Len(t, vulns, 3)

		ids := make(map[string]bool)
		for _, v := range vulns {
			ids[v.ID] = true
		}
		assert.True(t, ids["CVE-2021-1111"])
		assert.True(t, ids["CVE-2021-2222"])
		assert.True(t, ids["CVE-2021-3333"])
	})

	t.Run("same ID different affects - NOT deduplicated (affects is part of key)", func(t *testing.T) {
		g := NewSBOMGraph()
		// Add same vulnerability ID with different affects
		g.AddVulnerability(cdx.Vulnerability{
			ID:      "CVE-2021-1234",
			Affects: &[]cdx.Affects{{Ref: "pkg:npm/lodash@4.17.20"}},
		})
		g.AddVulnerability(cdx.Vulnerability{
			ID:      "CVE-2021-1234",
			Affects: &[]cdx.Affects{{Ref: "pkg:npm/lodash@4.17.21"}},
		})

		vulns := slices.Collect(g.Vulnerabilities())
		// Both kept because they have different affects
		assert.Len(t, vulns, 2)
	})

	t.Run("duplicate vulnerability - existing has InTriage state should keep existing", func(t *testing.T) {
		g := NewSBOMGraph()
		// First add the InTriage one
		g.AddVulnerability(cdx.Vulnerability{
			ID: "CVE-2021-1234",
			Analysis: &cdx.VulnerabilityAnalysis{
				State: cdx.IASInTriage,
			},
			Affects: &[]cdx.Affects{{Ref: "pkg:npm/lodash@4.17.20"}},
		})
		// Then add one with different state
		g.AddVulnerability(cdx.Vulnerability{
			ID: "CVE-2021-1234",
			Analysis: &cdx.VulnerabilityAnalysis{
				State: cdx.IASExploitable,
			},
			Affects: &[]cdx.Affects{{Ref: "pkg:npm/lodash@4.17.20"}},
		})

		vulns := slices.Collect(g.Vulnerabilities())
		assert.Len(t, vulns, 1)
		assert.Equal(t, "CVE-2021-1234", vulns[0].ID)
		assert.NotNil(t, vulns[0].Analysis)
		assert.Equal(t, cdx.IASInTriage, vulns[0].Analysis.State)
	})

	t.Run("same ID same affects - new has InTriage state should replace", func(t *testing.T) {
		g := NewSBOMGraph()
		// First add one with Exploitable state
		g.AddVulnerability(cdx.Vulnerability{
			ID: "CVE-2021-1234",
			Analysis: &cdx.VulnerabilityAnalysis{
				State: cdx.IASExploitable,
			},
			Affects: &[]cdx.Affects{{Ref: "pkg:npm/lodash@4.17.20"}},
		})
		// Then add one with InTriage state and SAME affects
		g.AddVulnerability(cdx.Vulnerability{
			ID: "CVE-2021-1234",
			Analysis: &cdx.VulnerabilityAnalysis{
				State: cdx.IASInTriage,
			},
			Affects: &[]cdx.Affects{{Ref: "pkg:npm/lodash@4.17.20"}},
		})

		vulns := slices.Collect(g.Vulnerabilities())
		assert.Len(t, vulns, 1)
		assert.Equal(t, "CVE-2021-1234", vulns[0].ID)
		assert.NotNil(t, vulns[0].Analysis)
		assert.Equal(t, cdx.IASInTriage, vulns[0].Analysis.State)
	})

	t.Run("same ID same affects - neither has InTriage keeps first", func(t *testing.T) {
		g := NewSBOMGraph()
		g.AddVulnerability(cdx.Vulnerability{
			ID: "CVE-2021-1234",
			Analysis: &cdx.VulnerabilityAnalysis{
				State: cdx.IASExploitable,
			},
			Affects: &[]cdx.Affects{{Ref: "pkg:npm/lodash@4.17.20"}},
		})
		g.AddVulnerability(cdx.Vulnerability{
			ID: "CVE-2021-1234",
			Analysis: &cdx.VulnerabilityAnalysis{
				State: cdx.IASNotAffected,
			},
			Affects: &[]cdx.Affects{{Ref: "pkg:npm/lodash@4.17.20"}},
		})

		vulns := slices.Collect(g.Vulnerabilities())
		assert.Len(t, vulns, 1)
		assert.Equal(t, "CVE-2021-1234", vulns[0].ID)
	})

	t.Run("same ID same affects - one with analysis one without are NOT deduplicated", func(t *testing.T) {
		// When one vuln has analysis and one doesn't, they have different storage keys
		// The deduplication only works when both have analysis states
		g := NewSBOMGraph()
		g.AddVulnerability(cdx.Vulnerability{
			ID:      "CVE-2021-1234",
			Affects: &[]cdx.Affects{{Ref: "pkg:npm/lodash@4.17.20"}},
		})
		g.AddVulnerability(cdx.Vulnerability{
			ID: "CVE-2021-1234",
			Analysis: &cdx.VulnerabilityAnalysis{
				State: cdx.IASExploitable,
			},
			Affects: &[]cdx.Affects{{Ref: "pkg:npm/lodash@4.17.20"}},
		})

		vulns := slices.Collect(g.Vulnerabilities())
		// Both kept because storage keys differ (one has state, one doesn't)
		assert.Len(t, vulns, 2)
	})

	t.Run("same ID same affects - one with in triage, one with false positive", func(t *testing.T) {

		g := NewSBOMGraph()
		g.AddVulnerability(cdx.Vulnerability{
			ID: "CVE-2021-1234",
			Analysis: &cdx.VulnerabilityAnalysis{
				State: cdx.IASFalsePositive,
			},
			Affects: &[]cdx.Affects{{Ref: "pkg:npm/lodash@4.17.20"}},
		})
		g.AddVulnerability(cdx.Vulnerability{
			ID: "CVE-2021-1234",
			Analysis: &cdx.VulnerabilityAnalysis{
				State: cdx.IASInTriage,
			},
			Affects: &[]cdx.Affects{{Ref: "pkg:npm/lodash@4.17.20"}},
		})

		vulns := slices.Collect(g.Vulnerabilities())

		assert.Len(t, vulns, 1)
		assert.Equal(t, cdx.IASInTriage, vulns[0].Analysis.State)
	})

	t.Run("same vulnerability ID with different affects should NOT deduplicate", func(t *testing.T) {
		// The deduplication key includes affects, so different affects = different vulns
		g := NewSBOMGraph()
		g.AddVulnerability(cdx.Vulnerability{
			ID:      "CVE-2021-1234",
			Affects: &[]cdx.Affects{{Ref: "pkg:npm/package-a@1.0.0"}},
		})
		g.AddVulnerability(cdx.Vulnerability{
			ID:      "CVE-2021-1234",
			Affects: &[]cdx.Affects{{Ref: "pkg:npm/package-b@2.0.0"}},
		})

		vulns := slices.Collect(g.Vulnerabilities())
		// Both are kept because they have different affects
		assert.Len(t, vulns, 2)
	})

	t.Run("mixed vulnerabilities with various states", func(t *testing.T) {
		g := NewSBOMGraph()
		// Unique vuln 1
		g.AddVulnerability(cdx.Vulnerability{ID: "CVE-2021-1111"})
		// Duplicate vuln 2 - same affects, should keep InTriage
		g.AddVulnerability(cdx.Vulnerability{
			ID: "CVE-2021-2222",
			Analysis: &cdx.VulnerabilityAnalysis{
				State: cdx.IASExploitable,
			},
			Affects: &[]cdx.Affects{{Ref: "pkg:npm/a@1.0.0"}},
		})
		g.AddVulnerability(cdx.Vulnerability{
			ID: "CVE-2021-2222",
			Analysis: &cdx.VulnerabilityAnalysis{
				State: cdx.IASInTriage,
			},
			Affects: &[]cdx.Affects{{Ref: "pkg:npm/a@1.0.0"}}, // SAME affects
		})
		// Unique vuln 3
		g.AddVulnerability(cdx.Vulnerability{
			ID: "CVE-2021-3333",
			Analysis: &cdx.VulnerabilityAnalysis{
				State: cdx.IASFalsePositive,
			},
		})

		vulns := slices.Collect(g.Vulnerabilities())
		assert.Len(t, vulns, 3)

		vulnMap := make(map[string]*cdx.Vulnerability)
		for _, v := range vulns {
			vulnMap[v.ID] = v
		}

		assert.Contains(t, vulnMap, "CVE-2021-1111")
		assert.Contains(t, vulnMap, "CVE-2021-2222")
		assert.Contains(t, vulnMap, "CVE-2021-3333")

		// CVE-2021-2222 should have InTriage state
		assert.NotNil(t, vulnMap["CVE-2021-2222"].Analysis)
		assert.Equal(t, cdx.IASInTriage, vulnMap["CVE-2021-2222"].Analysis.State)
	})
}

func TestToMinimalTree(t *testing.T) {
	t.Run("simple tree with components", func(t *testing.T) {
		g := NewSBOMGraph()
		artifactID := g.AddArtifact("my-app")
		infoSourceID := g.AddInfoSource(artifactID, "package.json", InfoSourceSBOM)

		comp1 := cdx.Component{PackageURL: "pkg:npm/lodash@4.17.21", BOMRef: "pkg:npm/lodash@4.17.21"}
		comp2 := cdx.Component{PackageURL: "pkg:npm/express@4.18.2", BOMRef: "pkg:npm/express@4.18.2"}
		comp1ID := g.AddComponent(comp1)
		comp2ID := g.AddComponent(comp2)

		g.AddEdge(infoSourceID, comp1ID)
		g.AddEdge(infoSourceID, comp2ID)

		tree := g.ToMinimalTree()

		// Should contain all nodes (including structural nodes)
		assert.Contains(t, tree.Nodes, "pkg:npm/lodash@4.17.21")
		assert.Contains(t, tree.Nodes, "pkg:npm/express@4.18.2")

		// Info source should have both components as dependencies
		infoSourcePURL := "sbom:package.json@my-app"
		assert.Contains(t, tree.Dependencies[infoSourcePURL], "pkg:npm/lodash@4.17.21")
		assert.Contains(t, tree.Dependencies[infoSourcePURL], "pkg:npm/express@4.18.2")
	})

	t.Run("tree with component dependencies", func(t *testing.T) {
		g := NewSBOMGraph()
		artifactID := g.AddArtifact("my-app")
		infoSourceID := g.AddInfoSource(artifactID, "package.json", InfoSourceSBOM)

		// Create a dependency chain: infoSource -> a -> b -> c
		compA := cdx.Component{PackageURL: "pkg:npm/a@1.0.0", BOMRef: "pkg:npm/a@1.0.0"}
		compB := cdx.Component{PackageURL: "pkg:npm/b@1.0.0", BOMRef: "pkg:npm/b@1.0.0"}
		compC := cdx.Component{PackageURL: "pkg:npm/c@1.0.0", BOMRef: "pkg:npm/c@1.0.0"}

		compAID := g.AddComponent(compA)
		compBID := g.AddComponent(compB)
		compCID := g.AddComponent(compC)

		g.AddEdge(infoSourceID, compAID)
		g.AddEdge(compAID, compBID)
		g.AddEdge(compBID, compCID)

		tree := g.ToMinimalTree()

		// Verify nodes exist
		assert.Contains(t, tree.Nodes, "pkg:npm/a@1.0.0")
		assert.Contains(t, tree.Nodes, "pkg:npm/b@1.0.0")
		assert.Contains(t, tree.Nodes, "pkg:npm/c@1.0.0")

		// Verify dependency chain
		assert.Contains(t, tree.Dependencies["pkg:npm/a@1.0.0"], "pkg:npm/b@1.0.0")
		assert.Contains(t, tree.Dependencies["pkg:npm/b@1.0.0"], "pkg:npm/c@1.0.0")
		assert.Empty(t, tree.Dependencies["pkg:npm/c@1.0.0"])
	})

	t.Run("handles cycles correctly", func(t *testing.T) {
		g := NewSBOMGraph()
		artifactID := g.AddArtifact("my-app")
		infoSourceID := g.AddInfoSource(artifactID, "package.json", InfoSourceSBOM)

		comp1 := cdx.Component{PackageURL: "pkg:npm/a@1.0.0", BOMRef: "pkg:npm/a@1.0.0"}
		comp2 := cdx.Component{PackageURL: "pkg:npm/b@1.0.0", BOMRef: "pkg:npm/b@1.0.0"}
		comp3 := cdx.Component{PackageURL: "pkg:npm/c@1.0.0", BOMRef: "pkg:npm/c@1.0.0"}

		comp1ID := g.AddComponent(comp1)
		comp2ID := g.AddComponent(comp2)
		comp3ID := g.AddComponent(comp3)

		// Create a cycle: a -> b -> c -> a
		g.AddEdge(infoSourceID, comp1ID)
		g.AddEdge(comp1ID, comp2ID)
		g.AddEdge(comp2ID, comp3ID)
		g.AddEdge(comp3ID, comp1ID) // cycle back to a

		tree := g.ToMinimalTree()

		// Should not panic and should contain all nodes
		assert.Contains(t, tree.Nodes, "pkg:npm/a@1.0.0")
		assert.Contains(t, tree.Nodes, "pkg:npm/b@1.0.0")
		assert.Contains(t, tree.Nodes, "pkg:npm/c@1.0.0")

		// Cycle should be represented in dependencies
		assert.Contains(t, tree.Dependencies["pkg:npm/a@1.0.0"], "pkg:npm/b@1.0.0")
		assert.Contains(t, tree.Dependencies["pkg:npm/b@1.0.0"], "pkg:npm/c@1.0.0")
		assert.Contains(t, tree.Dependencies["pkg:npm/c@1.0.0"], "pkg:npm/a@1.0.0")
	})

	t.Run("empty graph", func(t *testing.T) {
		g := NewSBOMGraph()
		tree := g.ToMinimalTree()

		// Empty graph should have ROOT node but no component nodes
		assert.Contains(t, tree.Nodes, "") // ROOT has empty PackageURL
		assert.Empty(t, tree.Dependencies[""])
	})
}
