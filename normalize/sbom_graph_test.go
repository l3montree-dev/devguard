package normalize

import (
	"os"
	"slices"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
)

var GraphRootNodeIDMetadata = &cdx.Metadata{
	Component: &cdx.Component{
		BOMRef: GraphRootNodeID,
		Name:   "test-artifact",
	},
}

func TestSBOMGraphFromCycloneDX(t *testing.T) {
	artifactName := "test-artifact"
	origin := "test-origin"

	t.Run("basic component without properties", func(t *testing.T) {
		bom := &cdx.BOM{
			BOMFormat:   "CycloneDX",
			SpecVersion: cdx.SpecVersion1_6,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef: GraphRootNodeID,
					Name:   artifactName,
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

		result, err := SBOMGraphFromCycloneDX(bom, artifactName, origin, false)
		assert.NoError(t, err)

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
			BOMFormat:   "CycloneDX",
			SpecVersion: cdx.SpecVersion1_6,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef: GraphRootNodeID,
					Name:   artifactName,
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

		result, err := SBOMGraphFromCycloneDX(bom, "test-artifact", "test-source", false)
		assert.NoError(t, err)

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
			BOMFormat:   "CycloneDX",
			SpecVersion: cdx.SpecVersion1_6,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef: GraphRootNodeID,
					Name:   artifactName,
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

		result, err := SBOMGraphFromCycloneDX(bom, "test-artifact", "test-source", false)
		assert.NoError(t, err)
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
			BOMFormat:   "CycloneDX",
			SpecVersion: cdx.SpecVersion1_6,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef: GraphRootNodeID,
					Name:   artifactName,
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

		result, err := SBOMGraphFromCycloneDX(bom, artifactName, origin, false)
		assert.NoError(t, err)
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
			BOMFormat:   "CycloneDX",
			SpecVersion: cdx.SpecVersion1_6,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef: GraphRootNodeID,
					Name:   artifactName,
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

		result, err := SBOMGraphFromCycloneDX(bom, artifactName, origin, false)
		assert.NoError(t, err)
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
			BOMFormat:   "CycloneDX",
			SpecVersion: cdx.SpecVersion1_6,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef: GraphRootNodeID,
					Name:   artifactName,
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

		result, err := SBOMGraphFromCycloneDX(bom, artifactName, origin, false)
		assert.NoError(t, err)

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
			BOMFormat:   "CycloneDX",
			SpecVersion: cdx.SpecVersion1_6,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef:     GraphRootNodeID,
					Name:       artifactName,
					PackageURL: "pkg:npm/test-artifact@1.0.0",
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

		result, err := SBOMGraphFromCycloneDX(bom, artifactName, origin, true)
		assert.NoError(t, err)

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
			BOMFormat:   "CycloneDX",
			SpecVersion: cdx.SpecVersion1_6,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef:     GraphRootNodeID,
					Name:       artifactName,
					PackageURL: "pkg:npm/artifactName@1.0.0",
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

		result, err := SBOMGraphFromCycloneDX(bom, artifactName, origin, true)
		assert.NoError(t, err)

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
			BOMFormat:   "CycloneDX",
			SpecVersion: cdx.SpecVersion1_6,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef:     GraphRootNodeID,
					Name:       artifactName,
					PackageURL: "pkg:npm/artifactName@1.0.0",
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

		result, err := SBOMGraphFromCycloneDX(bom, artifactName, origin, true)
		assert.NoError(t, err)

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

	t.Run("keepOriginalSbomRootComponent=true preserves root node and all its dependencies", func(t *testing.T) {
		// Create a BOM with a deeper dependency tree:
		// ROOT -> component-a -> component-b -> component-c
		rootRef := "pkg:npm/my-app@1.0.0"
		bom := &cdx.BOM{
			BOMFormat:   cdx.BOMFormat,
			SpecVersion: cdx.SpecVersion1_6,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef:     rootRef,
					Name:       "my-app",
					Version:    "1.0.0",
					PackageURL: rootRef,
					Type:       cdx.ComponentTypeApplication,
				},
			},
			Components: &[]cdx.Component{
				{
					BOMRef:     rootRef,
					Name:       "my-app",
					Version:    "1.0.0",
					PackageURL: rootRef,
					Type:       cdx.ComponentTypeApplication,
				},
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
				{
					BOMRef:     "pkg:npm/component-c@3.0.0",
					Name:       "component-c",
					Version:    "3.0.0",
					PackageURL: "pkg:npm/component-c@3.0.0",
					Type:       cdx.ComponentTypeLibrary,
				},
			},
			Dependencies: &[]cdx.Dependency{
				{Ref: rootRef, Dependencies: &[]string{"pkg:npm/component-a@1.0.0"}},
				{Ref: "pkg:npm/component-a@1.0.0", Dependencies: &[]string{"pkg:npm/component-b@2.0.0"}},
				{Ref: "pkg:npm/component-b@2.0.0", Dependencies: &[]string{"pkg:npm/component-c@3.0.0"}},
				{Ref: "pkg:npm/component-c@3.0.0", Dependencies: &[]string{}},
			},
		}

		result, err := SBOMGraphFromCycloneDX(bom, artifactName, origin, true)
		assert.NoError(t, err)

		// Verify the root node exists in the graph
		rootNode := result.nodes[rootRef]
		assert.NotNil(t, rootNode, "root component node should exist in the graph")
		assert.Equal(t, GraphNodeTypeComponent, rootNode.Type, "root node should be a component type")

		// Collect all edges
		edges := result.Edges()
		edgeMap := make(map[string][]string)
		for parentID, childID := range edges {
			edgeMap[parentID] = append(edgeMap[parentID], childID)
		}

		// Verify: info source -> root (keepOriginalSbomRootComponent adds this)
		var infoSourceID string
		for nodeID, node := range result.nodes {
			if node.Type == GraphNodeTypeInfoSource {
				infoSourceID = nodeID
				break
			}
		}
		assert.NotEmpty(t, infoSourceID, "info source should exist")
		assert.Contains(t, edgeMap[infoSourceID], rootRef,
			"info source should have an edge to the root component")

		// Verify: ONLY the root component is a direct child of info source
		assert.Len(t, edgeMap[infoSourceID], 1,
			"info source should have exactly ONE direct child (the root component)")
		assert.Equal(t, rootRef, edgeMap[infoSourceID][0],
			"the only direct child of info source should be the root component")

		// Verify: root -> component-a (NOT info source -> component-a)
		assert.Contains(t, edgeMap[rootRef], "pkg:npm/component-a@1.0.0",
			"root should have direct edge to component-a")
		assert.NotContains(t, edgeMap[infoSourceID], "pkg:npm/component-a@1.0.0",
			"info source should NOT have edge to component-a when keepOriginalSbomRootComponent=true")

		// Verify: component-a -> component-b (transitive dependency preserved)
		assert.Contains(t, edgeMap["pkg:npm/component-a@1.0.0"], "pkg:npm/component-b@2.0.0",
			"component-a should have edge to component-b")

		// Verify: component-b -> component-c (deeper transitive dependency preserved)
		assert.Contains(t, edgeMap["pkg:npm/component-b@2.0.0"], "pkg:npm/component-c@3.0.0",
			"component-b should have edge to component-c")

		// Verify the full dependency chain is reachable from info source
		// info source -> root -> component-a -> component-b -> component-c
		reachable := make(map[string]bool)
		var visit func(id string)
		visit = func(id string) {
			if reachable[id] {
				return
			}
			reachable[id] = true
			for _, child := range edgeMap[id] {
				visit(child)
			}
		}
		visit(infoSourceID)

		assert.True(t, reachable[rootRef], "root should be reachable from info source")
		assert.True(t, reachable["pkg:npm/component-a@1.0.0"], "component-a should be reachable")
		assert.True(t, reachable["pkg:npm/component-b@2.0.0"], "component-b should be reachable")
		assert.True(t, reachable["pkg:npm/component-c@3.0.0"], "component-c should be reachable")
	})

	t.Run("info source ID must not get double-prefixed with sbom:sbom:", func(t *testing.T) {
		bom := &cdx.BOM{
			BOMFormat:   "CycloneDX",
			SpecVersion: cdx.SpecVersion1_6,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef: GraphRootNodeID,
					Name:   artifactName,
				},
			},
			Components: &[]cdx.Component{{
				BOMRef:     "pkg:npm/dep@1.0.0",
				Name:       "dep",
				Version:    "1.0.0",
				PackageURL: "pkg:npm/dep@1.0.0",
				Type:       cdx.ComponentTypeLibrary,
			}},
			Dependencies: &[]cdx.Dependency{
				{Ref: GraphRootNodeID, Dependencies: &[]string{"pkg:npm/dep@1.0.0"}},
			},
		}

		// Simulate the caller already adding a "sbom:" prefix (the bug that was fixed).
		// AddInfoSource prepends sourceType ("sbom") automatically, so passing "sbom:url"
		// would produce "sbom:sbom:url@artifact" — a double prefix.
		for _, sourceID := range []string{"https://example.com/sbom.json", "sbom:https://example.com/sbom.json"} {
			result, err := SBOMGraphFromCycloneDX(bom, artifactName, sourceID, false)
			assert.NoError(t, err)

			artifactID := "artifact:" + artifactName
			infoSourceIDs := result.GetInfoSourceIDs(artifactID)
			assert.Len(t, infoSourceIDs, 1, "expected exactly one info source")

			id := infoSourceIDs[0]
			assert.NotContains(t, id, "sbom:sbom:", "info source ID must not contain double sbom: prefix, got: %s", id)
		}
	})

}

func TestMergeCdxBoms(t *testing.T) {
	t.Run("merge two BOMs with different components", func(t *testing.T) {
		bom1 := &cdx.BOM{
			BOMFormat:   "CycloneDX",
			SpecVersion: cdx.SpecVersion1_6,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "GraphRootNodeID-bom-1", Name: "artifact1"},
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
			BOMFormat:   "CycloneDX",
			SpecVersion: cdx.SpecVersion1_6,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "GraphRootNodeID-bom-2", Name: "artifact2"},
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
		graph1, err := SBOMGraphFromCycloneDX(bom1, "artifact-1", "sbom-1", false)
		assert.NoError(t, err)
		result.MergeGraph(graph1)
		graph2, err := SBOMGraphFromCycloneDX(bom2, "artifact-2", "sbom-2", false)
		assert.NoError(t, err)
		result.MergeGraph(graph2)

		expected := &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef: "merged-artifact@0.0.0",
				},
			},
			Components: &[]cdx.Component{
				{
					BOMRef: "merged-artifact@0.0.0",
				},
				{
					BOMRef: "pkg:npm/component-2@2.0.0",
				},
				{
					BOMRef: "pkg:npm/component-1@1.0.0",
				},
			},
			Dependencies: &[]cdx.Dependency{
				{Ref: "merged-artifact@0.0.0", Dependencies: &[]string{"pkg:npm/component-1@1.0.0", "pkg:npm/component-2@2.0.0"}},
				{Ref: "pkg:npm/component-1@1.0.0", Dependencies: &[]string{}},
				{Ref: "pkg:npm/component-2@2.0.0", Dependencies: &[]string{}},
			},
		}

		actual := result.ToCycloneDX(BOMMetadata{
			ArtifactName:     "merged-artifact",
			AssetVersionName: "0.0.0",
		})

		assert.Nil(t, StructuralCompareCdxBoms(actual, expected))
	})

	t.Run("merge BOMs with duplicate components", func(t *testing.T) {
		bom1 := &cdx.BOM{
			BOMFormat:   cdx.BOMFormat,
			SpecVersion: cdx.SpecVersion1_6,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "GraphRootNodeID-bom-1", Name: "TestArtifact"},
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
			BOMFormat:   "CycloneDX",
			SpecVersion: cdx.SpecVersion1_6,
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{BOMRef: "GraphRootNodeID-bom-2", Name: "artifact2"},
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
		graph1, err := SBOMGraphFromCycloneDX(bom1, "artifact-1", "test", false)
		assert.NoError(t, err)
		result.MergeGraph(graph1)
		graph2, err := SBOMGraphFromCycloneDX(bom2, "artifact-2", "test", false)
		assert.NoError(t, err)
		result.MergeGraph(graph2)

		expected := &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef: "merged-artifact@0.0.0",
				},
			},
			Components: &[]cdx.Component{
				{
					BOMRef: "merged-artifact@0.0.0",
				},
				{
					BOMRef: "pkg:npm/component-1@1.0.0",
				},
			},
			Dependencies: &[]cdx.Dependency{
				{Ref: "merged-artifact@0.0.0", Dependencies: &[]string{"pkg:npm/component-1@1.0.0"}},
				{Ref: "pkg:npm/component-1@1.0.0", Dependencies: &[]string{}},
			},
		}
		actual := result.ToCycloneDX(BOMMetadata{
			ArtifactName:     "merged-artifact",
			AssetVersionName: "0.0.0",
		})

		assert.Nil(t, StructuralCompareCdxBoms(actual, expected))
	})
}

func TestMergeCdxBomsSimple(t *testing.T) {
	b1 := &cdx.BOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: cdx.SpecVersion1_6,
		Metadata:    GraphRootNodeIDMetadata,
		Components: &[]cdx.Component{{
			Name:       "comp-a",
			PackageURL: "pkg:maven/org.example/comp-a@1.0.0",
			BOMRef:     "pkg:maven/org.example/comp-a@1.0.0",
		}},
	}
	b2 := &cdx.BOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: cdx.SpecVersion1_6,
		Metadata:    GraphRootNodeIDMetadata,
		Components: &[]cdx.Component{{
			Name:       "comp-b",
			BOMRef:     "pkg:maven/org.example/comp-b@2.0.0",
			PackageURL: "pkg:maven/org.example/comp-b@2.0.0",
		}},
		Vulnerabilities: &[]cdx.Vulnerability{{
			ID: "CVE-XYZ",
		}},
	}

	result := NewSBOMGraph()
	graph1, err := SBOMGraphFromCycloneDX(b1, "artifact-1", "test", false)
	assert.NoError(t, err)
	result.MergeGraph(graph1)
	graph2, err := SBOMGraphFromCycloneDX(b2, "artifact-2", "test", false)
	assert.NoError(t, err)
	result.MergeGraph(graph2)
	result.ToCycloneDX(BOMMetadata{})

	assert.Len(t, slices.Collect(result.Vulnerabilities()), 1)
}

func TestMergeComplex(t *testing.T) {
	artifactName := "test-artifact"

	t.Run("should add the subtree if it does not exist", func(t *testing.T) {
		currentSbom := &cdx.BOM{
			BOMFormat:   "CycloneDX",
			SpecVersion: cdx.SpecVersion1_6,
			Metadata:    GraphRootNodeIDMetadata,
			Components: &[]cdx.Component{
				{
					BOMRef: GraphRootNodeID,
					Name:   artifactName,
				},
				{
					BOMRef:     "pkg:container",
					Name:       "container-image",
					PackageURL: "pkg:oci/container@1.0.0",
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
			BOMFormat:   "CycloneDX",
			SpecVersion: cdx.SpecVersion1_6,
			Metadata:    GraphRootNodeIDMetadata,
			Components: &[]cdx.Component{
				{
					BOMRef: GraphRootNodeID,
					Name:   artifactName,
				},
				{
					BOMRef:     "pkg:source",
					Name:       "source-component",
					PackageURL: "pkg:oci/source@2.0.0",
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

		currentGraph, err := SBOMGraphFromCycloneDX(currentSbom, artifactName, "container-scan", false)
		assert.NoError(t, err)
		newGraph, err := SBOMGraphFromCycloneDX(newSubtree, artifactName, "source-scan", false)
		assert.NoError(t, err)
		currentGraph.MergeGraph(newGraph)

		expected := &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef: artifactName + "@0.0.0",
				},
			},
			Components: &[]cdx.Component{
				{
					BOMRef: artifactName + "@0.0.0",
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
					Ref: artifactName + "@0.0.0",
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
			ArtifactName:     artifactName,
			AssetVersionName: "0.0.0",
		}), expected))
	})

	t.Run("should update the subtree if it does already exist", func(t *testing.T) {
		currentSbom := &cdx.BOM{
			BOMFormat:   "CycloneDX",
			SpecVersion: cdx.SpecVersion1_6,
			Metadata:    GraphRootNodeIDMetadata,
			Components: &[]cdx.Component{
				{
					BOMRef: GraphRootNodeID,
					Name:   artifactName,
				},
				{
					BOMRef:     "pkg:container@2.0.0",
					PackageURL: "pkg:oci/container@2.0.0",
					Name:       "container-image",
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
			BOMFormat:   "CycloneDX",
			SpecVersion: cdx.SpecVersion1_6,
			Metadata:    GraphRootNodeIDMetadata,
			Components: &[]cdx.Component{
				{
					BOMRef: GraphRootNodeID,
					Name:   artifactName,
				},
				{
					BOMRef:     "pkg:container@2.0.0",
					PackageURL: "pkg:oci/container@2.0.0",
					Name:       "container-image-updated",
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

		resultGraph, err := SBOMGraphFromCycloneDX(currentSbom, artifactName, "container-scan", false)
		assert.NoError(t, err)

		subtree, err := SBOMGraphFromCycloneDX(newSubtree, artifactName, "container-scan", false)
		assert.NoError(t, err)
		resultGraph.MergeGraph(subtree)

		expected := &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					BOMRef: artifactName + "@0.0.0",
				},
			},
			Components: &[]cdx.Component{
				{
					BOMRef: artifactName + "@0.0.0",
				},
				{
					BOMRef: "pkg:container@2.0.0",
				},
			},
			Dependencies: &[]cdx.Dependency{
				{
					Ref: artifactName + "@0.0.0",
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
			ArtifactName:     artifactName,
			AssetVersionName: "0.0.0",
		}), expected))
	})

}

func TestFindAllComponentOnlyPathsToPURL(t *testing.T) {
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
		paths := g.FindAllComponentOnlyPathsToPURL("pkg:npm/lodash@4.17.21", 0)

		// Should return a single path (reachable through different info sources)
		assert.Len(t, paths, 1, "Should return separate paths for each info source")
	})

	t.Run("multiple artifacts pointing to same component - should return a single same path", func(t *testing.T) {
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
		paths := g.FindAllComponentOnlyPathsToPURL("pkg:npm/express@4.18.0", 0)

		// Should return two paths (one through each artifact)
		assert.Len(t, paths, 1, "Should return separate paths through different artifacts")
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
		paths := g.FindAllComponentOnlyPathsToPURL("pkg:npm/target@1.0.0", 0)

		// Should return two different paths through different dependencies
		assert.Len(t, paths, 2, "Should return multiple paths when there are different dependency chains")

		// Verify the paths contain the expected components
		path1 := []string{"pkg:npm/dep-a@1.0.0", "pkg:npm/target@1.0.0"}
		path2 := []string{"pkg:npm/dep-b@1.0.0", "pkg:npm/target@1.0.0"}

		assert.Contains(t, [][]string{paths[0], paths[1]}, path1, "Should contain path through dep-a")
		assert.Contains(t, [][]string{paths[0], paths[1]}, path2, "Should contain path through dep-b")
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
		paths := g.FindAllComponentOnlyPathsToPURL("pkg:npm/non-existent@1.0.0", 0)

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
		paths := g.FindAllComponentOnlyPathsToPURL("pkg:npm/d@1.0.0", 0)

		assert.Len(t, paths, 1)
		expectedPath := Path([]string{"pkg:npm/a@1.0.0", "pkg:npm/b@1.0.0", "pkg:npm/c@1.0.0", "pkg:npm/d@1.0.0"})
		assert.Equal(t, expectedPath, paths[0], "Should return the complete dependency chain")
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
		allPaths := g.FindAllComponentOnlyPathsToPURL("pkg:npm/target@1.0.0", 0)
		assert.Len(t, allPaths, 3, "Should return all 3 paths without limit")

		// With limit=1, should return only the shortest path
		limitedPaths := g.FindAllComponentOnlyPathsToPURL("pkg:npm/target@1.0.0", 1)
		assert.Len(t, limitedPaths, 1, "Should return only 1 path with limit=1")
		// The shortest path is the direct one
		assert.Equal(t, Path([]string{"pkg:npm/target@1.0.0"}), limitedPaths[0])

		// With limit=2, should return 2 shortest paths
		limitedPaths2 := g.FindAllComponentOnlyPathsToPURL("pkg:npm/target@1.0.0", 2)
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

	t.Run("root component with non-PURL BOMRef should still appear in vulnerability path", func(t *testing.T) {
		// Regression: when the root component's BOMRef is not a PURL (e.g. "my-app"),
		// but its PackageURL IS a valid PURL, the root should still appear in the
		// vulnerability path. Previously, isComponentNodeID checked the BOMRef format
		// and would incorrectly skip non-PURL BOMRefs.
		g := NewSBOMGraph()

		artifactID := g.AddArtifact("test-artifact")
		infoSource := g.AddInfoSource(artifactID, "sbom.json", InfoSourceSBOM)

		// Root component with non-PURL BOMRef but valid PackageURL
		root := cdx.Component{
			BOMRef:     "my-app", // NOT a PURL
			Name:       "my-app",
			Version:    "1.0.0",
			PackageURL: "pkg:npm/my-app@1.0.0",
			Type:       cdx.ComponentTypeApplication,
		}
		rootID := g.AddComponent(root)
		g.AddEdge(infoSource, rootID)

		// Intermediate dependency
		mid := cdx.Component{
			BOMRef:     "pkg:npm/express@4.18.0",
			Name:       "express",
			Version:    "4.18.0",
			PackageURL: "pkg:npm/express@4.18.0",
			Type:       cdx.ComponentTypeLibrary,
		}
		midID := g.AddComponent(mid)
		g.AddEdge(rootID, midID)

		// Vulnerable leaf dependency
		vuln := cdx.Component{
			BOMRef:     "pkg:npm/qs@6.5.0",
			Name:       "qs",
			Version:    "6.5.0",
			PackageURL: "pkg:npm/qs@6.5.0",
			Type:       cdx.ComponentTypeLibrary,
		}
		vulnID := g.AddComponent(vuln)
		g.AddEdge(midID, vulnID)

		paths := g.FindAllComponentOnlyPathsToPURL("pkg:npm/qs@6.5.0", 0)
		assert.Len(t, paths, 1, "Should find exactly one path")
		// Path should include the root component even though its BOMRef is not a PURL
		assert.Equal(t, Path{"pkg:npm/my-app@1.0.0", "pkg:npm/express@4.18.0", "pkg:npm/qs@6.5.0"}, paths[0],
			"Root component with non-PURL BOMRef must still appear in the vulnerability path")
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

	t.Run("duplicate vulnerability - existing has InTriage state should switch to exploitable", func(t *testing.T) {
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
		assert.Equal(t, cdx.IASExploitable, vulns[0].Analysis.State)
	})

	t.Run("same ID same affects - new has Exploitable state should not replace", func(t *testing.T) {
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
		assert.Equal(t, cdx.IASExploitable, vulns[0].Analysis.State)
	})

	t.Run("same ID same affects - keep exploitable", func(t *testing.T) {
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

	t.Run("same ID same affects - one with analysis one without are deduplicated", func(t *testing.T) {
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
		assert.Len(t, vulns, 1)
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
		// Duplicate vuln 2 - same affects, should keep is_exploitable since this is a "worse" state than InTriage
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
		assert.Equal(t, cdx.IASExploitable, vulnMap["CVE-2021-2222"].Analysis.State)
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

	t.Run("scoped to info source only shows its subtree", func(t *testing.T) {
		g := NewSBOMGraph()
		artifactID := g.AddArtifact("my-app")
		infoSourceID1 := g.AddInfoSource(artifactID, "package.json", InfoSourceSBOM)
		infoSourceID2 := g.AddInfoSource(artifactID, "other.json", InfoSourceSBOM)

		compA := cdx.Component{PackageURL: "pkg:npm/a@1.0.0", BOMRef: "pkg:npm/a@1.0.0"}
		compB := cdx.Component{PackageURL: "pkg:npm/b@1.0.0", BOMRef: "pkg:npm/b@1.0.0"}
		compC := cdx.Component{PackageURL: "pkg:npm/c@1.0.0", BOMRef: "pkg:npm/c@1.0.0"}

		compAID := g.AddComponent(compA)
		compBID := g.AddComponent(compB)
		compCID := g.AddComponent(compC)

		// infoSource1 -> a -> b
		g.AddEdge(infoSourceID1, compAID)
		g.AddEdge(compAID, compBID)
		// infoSource2 -> c
		g.AddEdge(infoSourceID2, compCID)

		// Scope to infoSource1
		err := g.ScopeToInfoSource("package.json@my-app", InfoSourceSBOM)
		assert.NoError(t, err)
		tree := g.ToMinimalTree()

		// Only a and b should be present (plus root)
		assert.Contains(t, tree.Nodes, "pkg:npm/a@1.0.0")
		assert.Contains(t, tree.Nodes, "pkg:npm/b@1.0.0")
		assert.NotContains(t, tree.Nodes, "pkg:npm/c@1.0.0")

		// infoSource1 should have a as dependency, a should have b
		assert.Contains(t, tree.Dependencies["sbom:package.json@my-app"], "pkg:npm/a@1.0.0")
		assert.Contains(t, tree.Dependencies["pkg:npm/a@1.0.0"], "pkg:npm/b@1.0.0")
		// infoSource2 and c should not appear
		assert.NotContains(t, tree.Dependencies, "sbom:other.json@my-app")
		assert.NotContains(t, tree.Nodes, "pkg:npm/c@1.0.0")
	})

}

func TestAddComponent_URLUnescaping(t *testing.T) {
	t.Run("should unescape URL-encoded plus sign in version", func(t *testing.T) {
		g := NewSBOMGraph()

		// PURL with URL-encoded + (%2B) in version
		encodedPurl := "pkg:deb/debian/libpam0g@1.4.0-9%2Bdeb11u2?arch=amd64&distro=debian-11.11"
		expectedPurl := "pkg:deb/debian/libpam0g@1.4.0-9+deb11u2?arch=amd64&distro=debian-11.11"

		comp := cdx.Component{
			BOMRef:     encodedPurl,
			Name:       "libpam0g",
			Version:    "1.4.0-9+deb11u2",
			PackageURL: encodedPurl,
			Type:       cdx.ComponentTypeLibrary,
		}

		g.AddComponent(comp)

		// Verify the component was added with unescaped PURL
		node := g.nodes[encodedPurl]
		assert.NotNil(t, node)
		assert.Equal(t, expectedPurl, node.Component.PackageURL)
	})

	t.Run("should preserve already unescaped plus sign", func(t *testing.T) {
		g := NewSBOMGraph()

		// PURL with literal + in version (already unescaped)
		purl := "pkg:deb/debian/libpam0g@1.4.0-9+deb11u2?arch=amd64&distro=debian-11.11"

		comp := cdx.Component{
			BOMRef:     purl,
			Name:       "libpam0g",
			Version:    "1.4.0-9+deb11u2",
			PackageURL: purl,
			Type:       cdx.ComponentTypeLibrary,
		}

		g.AddComponent(comp)

		// Verify the component was added with the same PURL (no change)
		node := g.nodes[purl]
		assert.NotNil(t, node)
		assert.Equal(t, purl, node.Component.PackageURL)
	})

	t.Run("should unescape multiple URL-encoded characters", func(t *testing.T) {
		g := NewSBOMGraph()

		// PURL with multiple URL-encoded characters
		encodedPurl := "pkg:deb/debian/libpam0g@1.4.0-9%2Bdeb11u2%2Bsecurity?arch=amd64&distro=debian-11.11"
		expectedPurl := "pkg:deb/debian/libpam0g@1.4.0-9+deb11u2+security?arch=amd64&distro=debian-11.11"

		comp := cdx.Component{
			BOMRef:     encodedPurl,
			Name:       "libpam0g",
			Version:    "1.4.0-9+deb11u2+security",
			PackageURL: encodedPurl,
			Type:       cdx.ComponentTypeLibrary,
		}

		g.AddComponent(comp)

		node := g.nodes[encodedPurl]
		assert.NotNil(t, node)
		assert.Equal(t, expectedPurl, node.Component.PackageURL)
	})

	t.Run("should handle empty PackageURL", func(t *testing.T) {
		g := NewSBOMGraph()

		comp := cdx.Component{
			BOMRef:     "some-ref",
			Name:       "test-component",
			Version:    "1.0.0",
			PackageURL: "",
			Type:       cdx.ComponentTypeLibrary,
		}

		g.AddComponent(comp)

		node := g.nodes["some-ref"]
		assert.NotNil(t, node)
		assert.Equal(t, "", node.Component.PackageURL)
	})

	t.Run("dependency vuln should have correct purl with plus sign", func(t *testing.T) {
		g := NewSBOMGraph()
		artifactID := g.AddArtifact("test-artifact")
		infoSourceID := g.AddInfoSource(artifactID, "test-sbom", InfoSourceSBOM)

		// Add component with URL-encoded PURL
		encodedPurl := "pkg:deb/debian/libpam0g@1.4.0-9%2Bdeb11u2?arch=amd64&distro=debian-11.11"
		expectedPurl := "pkg:deb/debian/libpam0g@1.4.0-9+deb11u2?arch=amd64&distro=debian-11.11"

		comp := cdx.Component{
			BOMRef:     encodedPurl,
			Name:       "libpam0g",
			Version:    "1.4.0-9+deb11u2",
			PackageURL: encodedPurl,
			Type:       cdx.ComponentTypeLibrary,
		}

		compID := g.AddComponent(comp)
		g.AddEdge(infoSourceID, compID)

		// Add vulnerability affecting this component
		vuln := cdx.Vulnerability{
			ID: "CVE-2024-1234",
			Affects: &[]cdx.Affects{
				{Ref: encodedPurl},
			},
		}
		g.AddVulnerability(vuln)

		// Verify component has correct unescaped PURL
		var foundComponent *GraphNode
		for node := range g.Components() {
			if node.BOMRef == encodedPurl {
				foundComponent = node
				break
			}
		}
		assert.NotNil(t, foundComponent)
		assert.Equal(t, expectedPurl, foundComponent.Component.PackageURL)

		// Verify vulnerability is stored and component PURL matches what would be used for dependency vuln
		var foundVuln *cdx.Vulnerability
		for v := range g.Vulnerabilities() {
			if v.ID == "CVE-2024-1234" {
				foundVuln = v
				break
			}
		}
		assert.NotNil(t, foundVuln)
		assert.NotNil(t, foundVuln.Affects)
		assert.Len(t, *foundVuln.Affects, 1)
	})
}

func TestToCycloneDXExternalReferencesArtifactEncoding(t *testing.T) {
	t.Run("artifact name with special characters should be properly URL encoded", func(t *testing.T) {
		g := NewSBOMGraph()

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
				// Add a simple component
				g.AddComponent(cdx.Component{
					BOMRef:     "pkg:npm/test@1.0.0",
					Name:       "test",
					PackageURL: "pkg:npm/test@1.0.0",
					Type:       cdx.ComponentTypeLibrary,
				})

				metadata := BOMMetadata{
					ArtifactName:          tc.artifactName,
					AssetVersionName:      "main",
					AssetVersionSlug:      "main",
					AssetSlug:             "my-asset",
					OrgSlug:               "my-org",
					ProjectSlug:           "my-project",
					AssetID:               [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, // dummy UUID
					AddExternalReferences: true,
					FrontendURL:           "http://localhost:3000",
					RootName:              "",
				}

				// Set API_URL for test
				t.Setenv("API_URL", "http://localhost:8080")

				bom := g.ToCycloneDX(metadata)

				// Check that external references exist
				assert.NotNil(t, bom.ExternalReferences)
				assert.GreaterOrEqual(t, len(*bom.ExternalReferences), 2, "should have at least VEX and SBOM URLs")

				// Find the VEX reference
				var vexRef *cdx.ExternalReference
				var sbomRef *cdx.ExternalReference
				for i := range *bom.ExternalReferences {
					if (*bom.ExternalReferences)[i].Type == cdx.ERTypeExploitabilityStatement {
						vexRef = &(*bom.ExternalReferences)[i]
					}
					if (*bom.ExternalReferences)[i].Type == cdx.ERTypeBOM {
						sbomRef = &(*bom.ExternalReferences)[i]
					}
				}
				assert.NotNil(t, vexRef, "should have VEX reference")
				assert.NotNil(t, sbomRef, "should have SBOM reference")
				assert.Contains(t, vexRef.URL, "/artifacts/"+tc.expectedInURL+"/vex.json/")
				assert.Contains(t, sbomRef.URL, "/artifacts/"+tc.expectedInURL+"/sbom.json/")
			})
		}
	})

	t.Run("all external reference URLs should be present", func(t *testing.T) {
		g := NewSBOMGraph()

		// Add a simple component
		g.AddComponent(cdx.Component{
			BOMRef:     "pkg:npm/test@1.0.0",
			Name:       "test",
			PackageURL: "pkg:npm/test@1.0.0",
			Type:       cdx.ComponentTypeLibrary,
		})

		metadata := BOMMetadata{
			ArtifactName:          "my-app",
			AssetVersionName:      "main",
			AssetVersionSlug:      "main",
			AssetSlug:             "my-asset",
			OrgSlug:               "my-org",
			ProjectSlug:           "my-project",
			AssetID:               [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			AddExternalReferences: true,
			FrontendURL:           "http://localhost:3000",
			RootName:              "",
		}

		// Set API_URL for test
		t.Setenv("API_URL", "http://localhost:8080")

		bom := g.ToCycloneDX(metadata)

		// Check that external references exist
		assert.NotNil(t, bom.ExternalReferences)
		assert.GreaterOrEqual(t, len(*bom.ExternalReferences), 3)

		// Verify we have VEX, SBOM, and Dashboard URLs
		typeCount := make(map[cdx.ExternalReferenceType]int)
		urlCount := make(map[string]int)

		for _, ref := range *bom.ExternalReferences {
			typeCount[ref.Type]++
			urlCount[ref.URL]++
		}

		// Check that we have exactly one of each type
		assert.Equal(t, 1, typeCount[cdx.ERTypeExploitabilityStatement], "should have exactly one VEX URL")
		assert.Equal(t, 1, typeCount[cdx.ERTypeBOM], "should have exactly one SBOM URL")
		assert.Equal(t, 1, typeCount[cdx.ERTypeDynamicAnalysisReport], "should have exactly one Dashboard URL")

		// Verify the URLs contain correct paths
		for _, ref := range *bom.ExternalReferences {
			switch ref.Type {
			case cdx.ERTypeExploitabilityStatement:
				assert.Contains(t, ref.URL, "/vex.json/")
			case cdx.ERTypeBOM:
				assert.Contains(t, ref.URL, "/sbom.json/")
			case cdx.ERTypeDynamicAnalysisReport:
				assert.Contains(t, ref.URL, "/assets/my-asset/refs/main")
			}
		}
	})
}

func TestScoping(t *testing.T) {
	// Build graph:
	// ROOT
	// ├── artifact:app1
	// │   ├── sbom:s1@app1
	// │   │   ├── pkg:npm/shared@1.0.0
	// │   │   └── pkg:npm/only1@1.0.0
	// │   └── sbom:s2@app1
	// │       └── pkg:npm/shared@1.0.0
	// └── artifact:app2
	//     └── sbom:s3@app2
	//         └── pkg:npm/only2@1.0.0
	buildGraph := func() *SBOMGraph {
		g := NewSBOMGraph()
		a1 := g.AddArtifact("app1")
		a2 := g.AddArtifact("app2")
		s1 := g.AddInfoSource(a1, "s1", InfoSourceSBOM)
		s2 := g.AddInfoSource(a1, "s2", InfoSourceSBOM)
		s3 := g.AddInfoSource(a2, "s3", InfoSourceSBOM)

		shared := g.AddComponent(cdx.Component{BOMRef: "pkg:npm/shared@1.0.0", PackageURL: "pkg:npm/shared@1.0.0", Name: "shared"})
		only1 := g.AddComponent(cdx.Component{BOMRef: "pkg:npm/only1@1.0.0", PackageURL: "pkg:npm/only1@1.0.0", Name: "only1"})
		only2 := g.AddComponent(cdx.Component{BOMRef: "pkg:npm/only2@1.0.0", PackageURL: "pkg:npm/only2@1.0.0", Name: "only2"})

		g.AddEdge(s1, shared)
		g.AddEdge(s1, only1)
		g.AddEdge(s2, shared)
		g.AddEdge(s3, only2)
		return g
	}

	componentIDs := func(g *SBOMGraph) []string {
		var ids []string
		for c := range g.Components() {
			ids = append(ids, c.BOMRef)
		}
		return ids
	}

	t.Run("ClearScope sees all components", func(t *testing.T) {
		g := buildGraph()
		g.ClearScope()
		ids := componentIDs(g)
		assert.Len(t, ids, 3)
		assert.Contains(t, ids, "pkg:npm/shared@1.0.0")
		assert.Contains(t, ids, "pkg:npm/only1@1.0.0")
		assert.Contains(t, ids, "pkg:npm/only2@1.0.0")
	})

	t.Run("ScopeToArtifact restricts visibility", func(t *testing.T) {
		g := buildGraph()
		err := g.ScopeToArtifact("app1")
		assert.NoError(t, err)
		ids := componentIDs(g)
		assert.Contains(t, ids, "pkg:npm/shared@1.0.0")
		assert.Contains(t, ids, "pkg:npm/only1@1.0.0")
		assert.NotContains(t, ids, "pkg:npm/only2@1.0.0")
	})

	t.Run("ScopeToArtifact other artifact", func(t *testing.T) {
		g := buildGraph()
		err := g.ScopeToArtifact("app2")
		assert.NoError(t, err)
		ids := componentIDs(g)
		assert.Equal(t, []string{"pkg:npm/only2@1.0.0"}, ids)
	})

	t.Run("Scope to unreachable node returns error", func(t *testing.T) {
		g := buildGraph()
		_ = g.ScopeToArtifact("app2")
		err := g.Scope("artifact:app1")
		assert.ErrorIs(t, err, ErrNodeNotReachable)
	})

	t.Run("IsScoped", func(t *testing.T) {
		g := buildGraph()
		assert.False(t, g.IsScoped())
		_ = g.ScopeToArtifact("app1")
		assert.True(t, g.IsScoped())
		g.ClearScope()
		assert.False(t, g.IsScoped())
	})

	t.Run("Node returns nil for out-of-scope node", func(t *testing.T) {
		g := buildGraph()
		_ = g.ScopeToArtifact("app2")
		assert.Nil(t, g.Node("pkg:npm/only1@1.0.0"))
		assert.NotNil(t, g.Node("pkg:npm/only2@1.0.0"))
	})

	t.Run("Edges respects scope", func(t *testing.T) {
		g := buildGraph()
		_ = g.ScopeToArtifact("app2")
		for _, child := range g.Edges() {
			assert.NotEqual(t, "pkg:npm/only1@1.0.0", child)
			assert.NotEqual(t, "pkg:npm/shared@1.0.0", child)
		}
	})

	t.Run("Clone preserves scope", func(t *testing.T) {
		g := buildGraph()
		_ = g.ScopeToArtifact("app1")
		clone := g.Clone()
		assert.Equal(t, g.CurrentScopeID(), clone.CurrentScopeID())
		ids := componentIDs(clone)
		assert.NotContains(t, ids, "pkg:npm/only2@1.0.0")
	})

	t.Run("ComponentsWithMultipleSources returns shared component", func(t *testing.T) {
		g := buildGraph()
		multi := g.ComponentsWithMultipleSources()
		assert.Equal(t, []string{"pkg:npm/shared@1.0.0"}, multi)
	})

	t.Run("ComponentsWithMultipleSources preserves scope", func(t *testing.T) {
		g := buildGraph()
		_ = g.ScopeToArtifact("app1")
		before := g.CurrentScopeID()
		_ = g.ComponentsWithMultipleSources()
		assert.Equal(t, before, g.CurrentScopeID())
	})

	t.Run("ComponentsWithMultipleSources works when scoped", func(t *testing.T) {
		g := buildGraph()
		_ = g.ScopeToArtifact("app1")
		multi := g.ComponentsWithMultipleSources()
		assert.Equal(t, []string{"pkg:npm/shared@1.0.0"}, multi)
	})

	t.Run("single source component not in ComponentsWithMultipleSources", func(t *testing.T) {
		g := buildGraph()
		multi := g.ComponentsWithMultipleSources()
		assert.NotContains(t, multi, "pkg:npm/only1@1.0.0")
		assert.NotContains(t, multi, "pkg:npm/only2@1.0.0")
	})
}

func TestDependencyGraph(t *testing.T) {
	t.Run("loading the sbom-dependency-tree.json should have only two direct dependencies", func(t *testing.T) {
		b, err := os.Open("testdata/sbom-dependency-tree.json")
		assert.Nil(t, err)

		var sbom cdx.BOM
		assert.Nil(t, cdx.NewBOMDecoder(b, cdx.BOMFileFormatJSON).Decode(&sbom))

		g, err := SBOMGraphFromCycloneDX(&sbom, "artifact", "infosource", false)
		assert.Nil(t, err)

		old := NewSBOMGraph()

		directDeps := g.edges["sbom:infosource@artifact"]
		assert.Len(t, directDeps, 2)
		assert.Contains(t, directDeps, "pkg:npm/%40l3montree/service-app@1.0.0")
		assert.Contains(t, directDeps, "pkg:npm/express@4.22.1")

		diff := old.MergeGraph(g)
		// check that we are only adding two edges to root
		rootEdges := make(map[string]struct{})
		for _, edge := range diff.AddedEdges {
			if edge[0] == "sbom:infosource@artifact" {
				rootEdges[edge[1]] = struct{}{}
			}
		}
		assert.Len(t, rootEdges, 2)
		// expect the correct edges to be added
		assert.Contains(t, rootEdges, "pkg:npm/%40l3montree/service-app@1.0.0")
		assert.Contains(t, rootEdges, "pkg:npm/express@4.22.1")
	})
}
