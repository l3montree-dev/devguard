package normalize

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
)

func TestToCycloneDX(t *testing.T) {
	t.Run("transitive dependencies should not be direct children of root", func(t *testing.T) {
		// Create a graph with: root -> A -> B -> C
		// Only A should be a direct dependency of root
		// B should be a dependency of A
		// C should be a dependency of B
		g := NewSBOMGraph()

		artifactID := g.AddArtifact("my-app")
		infoSourceID := g.AddInfoSource(artifactID, "trivy", InfoSourceSBOM)

		// Add components A, B, C
		compA := cdx.Component{
			BOMRef:     "pkg:npm/a@1.0.0",
			Name:       "a",
			Version:    "1.0.0",
			PackageURL: "pkg:npm/a@1.0.0",
			Type:       cdx.ComponentTypeLibrary,
		}
		compB := cdx.Component{
			BOMRef:     "pkg:npm/b@2.0.0",
			Name:       "b",
			Version:    "2.0.0",
			PackageURL: "pkg:npm/b@2.0.0",
			Type:       cdx.ComponentTypeLibrary,
		}
		compC := cdx.Component{
			BOMRef:     "pkg:npm/c@3.0.0",
			Name:       "c",
			Version:    "3.0.0",
			PackageURL: "pkg:npm/c@3.0.0",
			Type:       cdx.ComponentTypeLibrary,
		}

		idA := g.AddComponent(compA)
		idB := g.AddComponent(compB)
		idC := g.AddComponent(compC)

		// Build the dependency chain
		g.AddEdge(infoSourceID, idA) // info source -> A
		g.AddEdge(idA, idB)          // A -> B
		g.AddEdge(idB, idC)          // B -> C

		// Export to CycloneDX
		bom := g.ToCycloneDX(BOMMetadata{
			RootName:     "my-app",
			ArtifactName: "my-app",
		})

		// Verify the dependencies array structure
		assert.NotNil(t, bom.Dependencies)
		deps := *bom.Dependencies

		// Find each dependency entry
		var rootDeps, aDeps, bDeps, cDeps *cdx.Dependency
		for i := range deps {
			switch deps[i].Ref {
			case "my-app":
				rootDeps = &deps[i]
			case "pkg:npm/a@1.0.0":
				aDeps = &deps[i]
			case "pkg:npm/b@2.0.0":
				bDeps = &deps[i]
			case "pkg:npm/c@3.0.0":
				cDeps = &deps[i]
			}
		}

		// Verify root has only A as direct dependency, not B or C
		assert.NotNil(t, rootDeps, "Root dependency entry should exist")
		assert.NotNil(t, rootDeps.Dependencies, "Root dependencies list should not be nil")
		assert.Len(t, *rootDeps.Dependencies, 1, "Root should have exactly 1 direct dependency")
		assert.Contains(t, *rootDeps.Dependencies, "pkg:npm/a@1.0.0", "Root should have A as direct dependency")
		assert.NotContains(t, *rootDeps.Dependencies, "pkg:npm/b@2.0.0", "Root should NOT have B as direct dependency")
		assert.NotContains(t, *rootDeps.Dependencies, "pkg:npm/c@3.0.0", "Root should NOT have C as direct dependency")

		// Verify A has only B as dependency
		assert.NotNil(t, aDeps, "A dependency entry should exist")
		assert.NotNil(t, aDeps.Dependencies, "A dependencies list should not be nil")
		assert.Len(t, *aDeps.Dependencies, 1, "A should have exactly 1 dependency")
		assert.Contains(t, *aDeps.Dependencies, "pkg:npm/b@2.0.0", "A should have B as dependency")
		assert.NotContains(t, *aDeps.Dependencies, "pkg:npm/c@3.0.0", "A should NOT have C as direct dependency")

		// Verify B has only C as dependency
		assert.NotNil(t, bDeps, "B dependency entry should exist")
		assert.NotNil(t, bDeps.Dependencies, "B dependencies list should not be nil")
		assert.Len(t, *bDeps.Dependencies, 1, "B should have exactly 1 dependency")
		assert.Contains(t, *bDeps.Dependencies, "pkg:npm/c@3.0.0", "B should have C as dependency")

		// Verify C has no dependencies
		assert.NotNil(t, cDeps, "C dependency entry should exist")
		assert.NotNil(t, cDeps.Dependencies, "C dependencies list should not be nil")
		assert.Len(t, *cDeps.Dependencies, 0, "C should have no dependencies")
	})

	t.Run("multiple direct dependencies from root", func(t *testing.T) {
		// Create a graph with: root -> A, root -> B
		// Both A and B should be direct dependencies of root
		g := NewSBOMGraph()

		artifactID := g.AddArtifact("my-app")
		infoSourceID := g.AddInfoSource(artifactID, "trivy", InfoSourceSBOM)

		compA := cdx.Component{
			BOMRef:     "pkg:npm/a@1.0.0",
			Name:       "a",
			Version:    "1.0.0",
			PackageURL: "pkg:npm/a@1.0.0",
			Type:       cdx.ComponentTypeLibrary,
		}
		compB := cdx.Component{
			BOMRef:     "pkg:npm/b@2.0.0",
			Name:       "b",
			Version:    "2.0.0",
			PackageURL: "pkg:npm/b@2.0.0",
			Type:       cdx.ComponentTypeLibrary,
		}

		idA := g.AddComponent(compA)
		idB := g.AddComponent(compB)

		g.AddEdge(infoSourceID, idA) // info source -> A
		g.AddEdge(infoSourceID, idB) // info source -> B

		bom := g.ToCycloneDX(BOMMetadata{
			RootName:     "my-app",
			ArtifactName: "my-app",
		})

		assert.NotNil(t, bom.Dependencies)
		deps := *bom.Dependencies

		var rootDeps *cdx.Dependency
		for i := range deps {
			if deps[i].Ref == "my-app" {
				rootDeps = &deps[i]
				break
			}
		}

		assert.NotNil(t, rootDeps)
		assert.NotNil(t, rootDeps.Dependencies)
		assert.Len(t, *rootDeps.Dependencies, 2, "Root should have exactly 2 direct dependencies")
		assert.Contains(t, *rootDeps.Dependencies, "pkg:npm/a@1.0.0")
		assert.Contains(t, *rootDeps.Dependencies, "pkg:npm/b@2.0.0")
	})

	t.Run("diamond dependency pattern", func(t *testing.T) {
		// Create a diamond: root -> A, root -> B, A -> C, B -> C
		// Root should have A and B as direct deps
		// C should not be a direct dependency of root
		g := NewSBOMGraph()

		artifactID := g.AddArtifact("my-app")
		infoSourceID := g.AddInfoSource(artifactID, "trivy", InfoSourceSBOM)

		compA := cdx.Component{
			BOMRef:     "pkg:npm/a@1.0.0",
			Name:       "a",
			Version:    "1.0.0",
			PackageURL: "pkg:npm/a@1.0.0",
			Type:       cdx.ComponentTypeLibrary,
		}
		compB := cdx.Component{
			BOMRef:     "pkg:npm/b@2.0.0",
			Name:       "b",
			Version:    "2.0.0",
			PackageURL: "pkg:npm/b@2.0.0",
			Type:       cdx.ComponentTypeLibrary,
		}
		compC := cdx.Component{
			BOMRef:     "pkg:npm/c@3.0.0",
			Name:       "c",
			Version:    "3.0.0",
			PackageURL: "pkg:npm/c@3.0.0",
			Type:       cdx.ComponentTypeLibrary,
		}

		idA := g.AddComponent(compA)
		idB := g.AddComponent(compB)
		idC := g.AddComponent(compC)

		g.AddEdge(infoSourceID, idA) // info source -> A
		g.AddEdge(infoSourceID, idB) // info source -> B
		g.AddEdge(idA, idC)          // A -> C
		g.AddEdge(idB, idC)          // B -> C

		bom := g.ToCycloneDX(BOMMetadata{
			RootName:     "my-app",
			ArtifactName: "my-app",
		})

		assert.NotNil(t, bom.Dependencies)
		deps := *bom.Dependencies

		var rootDeps, aDeps, bDeps *cdx.Dependency
		for i := range deps {
			switch deps[i].Ref {
			case "my-app":
				rootDeps = &deps[i]
			case "pkg:npm/a@1.0.0":
				aDeps = &deps[i]
			case "pkg:npm/b@2.0.0":
				bDeps = &deps[i]
			}
		}

		// Root should have only A and B, not C
		assert.NotNil(t, rootDeps)
		assert.Len(t, *rootDeps.Dependencies, 2, "Root should have exactly 2 direct dependencies")
		assert.Contains(t, *rootDeps.Dependencies, "pkg:npm/a@1.0.0")
		assert.Contains(t, *rootDeps.Dependencies, "pkg:npm/b@2.0.0")
		assert.NotContains(t, *rootDeps.Dependencies, "pkg:npm/c@3.0.0", "Root should NOT have C as direct dependency")

		// A should have C
		assert.NotNil(t, aDeps)
		assert.Contains(t, *aDeps.Dependencies, "pkg:npm/c@3.0.0")

		// B should have C
		assert.NotNil(t, bDeps)
		assert.Contains(t, *bDeps.Dependencies, "pkg:npm/c@3.0.0")
	})
}
