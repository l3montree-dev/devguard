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
		paths := g.FindAllPathsToPURL("pkg:npm/lodash@4.17.21")

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
		paths := g.FindAllPathsToPURL("pkg:npm/express@4.18.0")

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
		paths := g.FindAllPathsToPURL("pkg:npm/target@1.0.0")

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
		assert.Equal(t, expectedPath, paths[0].ToStringSliceComponentOnly(), "Should return complete dependency chain")
	})
}

func TestToMinimalTree(t *testing.T) {
	t.Run("simple tree from root scope", func(t *testing.T) {
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

		assert.Equal(t, "ROOT", tree.Name)
		assert.Len(t, tree.Children, 1)
		assert.Equal(t, "artifact:my-app", tree.Children[0].Name)
		assert.Len(t, tree.Children[0].Children, 1)
		assert.Equal(t, "sbom:package.json@my-app", tree.Children[0].Children[0].Name)
		assert.Len(t, tree.Children[0].Children[0].Children, 2)
	})

	t.Run("tree scoped to artifact", func(t *testing.T) {
		g := NewSBOMGraph()
		artifactID := g.AddArtifact("my-app")
		infoSourceID := g.AddInfoSource(artifactID, "package.json", InfoSourceSBOM)

		comp1 := cdx.Component{PackageURL: "pkg:npm/lodash@4.17.21", BOMRef: "pkg:npm/lodash@4.17.21"}
		comp1ID := g.AddComponent(comp1)
		g.AddEdge(infoSourceID, comp1ID)

		assert.Nil(t, g.ScopeToArtifact("my-app"))
		tree := g.ToMinimalTree()

		// Should start from artifact, not ROOT
		assert.Equal(t, "artifact:my-app", tree.Name)
		assert.Len(t, tree.Children, 1)
		assert.Equal(t, "sbom:package.json@my-app", tree.Children[0].Name)
	})

	t.Run("component appears under multiple artifacts", func(t *testing.T) {
		g := NewSBOMGraph()

		// Create two artifacts with same component
		artifact1ID := g.AddArtifact("app1")
		infoSource1ID := g.AddInfoSource(artifact1ID, "package.json", InfoSourceSBOM)

		artifact2ID := g.AddArtifact("app2")
		infoSource2ID := g.AddInfoSource(artifact2ID, "package.json", InfoSourceSBOM)

		sharedComp := cdx.Component{PackageURL: "pkg:npm/lodash@4.17.21", BOMRef: "pkg:npm/lodash@4.17.21"}
		sharedCompID := g.AddComponent(sharedComp)

		g.AddEdge(infoSource1ID, sharedCompID)
		g.AddEdge(infoSource2ID, sharedCompID)

		tree := g.ToMinimalTree()

		assert.Equal(t, "ROOT", tree.Name)
		assert.Len(t, tree.Children, 2)

		// Both artifacts should have the shared component
		var artifact1Tree, artifact2Tree *minimalTreeNode
		for _, child := range tree.Children {
			switch child.Name {
			case "artifact:app1":
				artifact1Tree = child
			case "artifact:app2":
				artifact2Tree = child
			}
		}

		assert.NotNil(t, artifact1Tree)
		assert.NotNil(t, artifact2Tree)

		// Both should have lodash as a descendant
		assert.Len(t, artifact1Tree.Children, 1)
		assert.Len(t, artifact1Tree.Children[0].Children, 1)
		assert.Equal(t, "pkg:npm/lodash@4.17.21", artifact1Tree.Children[0].Children[0].Name)

		assert.Len(t, artifact2Tree.Children, 1)
		assert.Len(t, artifact2Tree.Children[0].Children, 1)
		assert.Equal(t, "pkg:npm/lodash@4.17.21", artifact2Tree.Children[0].Children[0].Name)
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

		// Should not cause infinite recursion
		assert.NotNil(t, tree)
		assert.Equal(t, "ROOT", tree.Name)

		// Verify structure exists
		assert.Len(t, tree.Children, 1)
		artifact := tree.Children[0]
		assert.Equal(t, "artifact:my-app", artifact.Name)
	})

	t.Run("tree with component dependencies", func(t *testing.T) {
		g := NewSBOMGraph()
		artifactID := g.AddArtifact("my-app")
		infoSourceID := g.AddInfoSource(artifactID, "package.json", InfoSourceSBOM)

		// Create a dependency chain: root -> a -> b -> c
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

		// Navigate through the tree
		assert.Equal(t, "ROOT", tree.Name)
		artifact := tree.Children[0]
		infoSource := artifact.Children[0]
		componentA := infoSource.Children[0]
		assert.Equal(t, "pkg:npm/a@1.0.0", componentA.Name)
		assert.Len(t, componentA.Children, 1)

		componentB := componentA.Children[0]
		assert.Equal(t, "pkg:npm/b@1.0.0", componentB.Name)
		assert.Len(t, componentB.Children, 1)

		componentC := componentB.Children[0]
		assert.Equal(t, "pkg:npm/c@1.0.0", componentC.Name)
		assert.Len(t, componentC.Children, 0)
	})

	t.Run("empty graph", func(t *testing.T) {
		g := NewSBOMGraph()
		tree := g.ToMinimalTree()

		assert.Equal(t, "ROOT", tree.Name)
		assert.Len(t, tree.Children, 0)
	})
}
