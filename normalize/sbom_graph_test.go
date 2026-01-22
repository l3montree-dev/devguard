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

func TestFindAllPathsToPURL(t *testing.T) {
	t.Run("multiple information sources pointing to same component - should return single path", func(t *testing.T) {
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
		paths := g.FindAllPathsToPURL("pkg:npm/lodash@4.17.21")

		// Should return only one unique path (just the component itself)
		// because the path only includes components, not structural nodes
		assert.Len(t, paths, 1, "Should return single path for component reachable through multiple info sources")
		assert.Equal(t, []string{"pkg:npm/lodash@4.17.21"}, paths[0])
	})

	t.Run("multiple artifacts pointing to same component - should return single path", func(t *testing.T) {
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
		paths := g.FindAllPathsToPURL("pkg:npm/express@4.18.0")

		// Should return only one unique path (just the component itself)
		// because both artifacts lead to the same component path
		assert.Len(t, paths, 1, "Should return single path for component reachable through multiple artifacts")
		assert.Equal(t, []string{"pkg:npm/express@4.18.0"}, paths[0])
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
		paths := g.FindAllPathsToPURL("pkg:npm/target@1.0.0")

		// Should return two different paths through different dependencies
		assert.Len(t, paths, 2, "Should return multiple paths when there are different dependency chains")

		// Verify the paths contain the expected components
		path1 := []string{"pkg:npm/dep-a@1.0.0", "pkg:npm/target@1.0.0"}
		path2 := []string{"pkg:npm/dep-b@1.0.0", "pkg:npm/target@1.0.0"}

		assert.Contains(t, paths, path1, "Should contain path through dep-a")
		assert.Contains(t, paths, path2, "Should contain path through dep-b")
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
		paths := g.FindAllPathsToPURL("pkg:npm/non-existent@1.0.0")

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
		paths := g.FindAllPathsToPURL("pkg:npm/d@1.0.0")

		assert.Len(t, paths, 1)
		expectedPath := []string{
			"pkg:npm/a@1.0.0",
			"pkg:npm/b@1.0.0",
			"pkg:npm/c@1.0.0",
			"pkg:npm/d@1.0.0",
		}
		assert.Equal(t, expectedPath, paths[0], "Should return complete dependency chain")
	})
}
