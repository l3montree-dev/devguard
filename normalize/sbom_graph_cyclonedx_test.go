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

func TestToCycloneDXRootComponent(t *testing.T) {
	t.Run("root component should include version from AssetVersionName", func(t *testing.T) {
		g := NewSBOMGraph()
		artifactID := g.AddArtifact("my-app")
		g.AddInfoSource(artifactID, "trivy", InfoSourceSBOM)

		bom := g.ToCycloneDX(BOMMetadata{
			RootName:         "my-app",
			ArtifactName:     "my-app",
			AssetVersionName: "1.2.3",
		})

		// Find root component by BOMRef (name@version format)
		var rootComp *cdx.Component
		for i := range *bom.Components {
			if (*bom.Components)[i].BOMRef == "my-app@1.2.3" {
				rootComp = &(*bom.Components)[i]
				break
			}
		}

		assert.NotNil(t, rootComp, "Root component should exist with version in BOMRef")
		assert.Equal(t, "my-app@1.2.3", rootComp.BOMRef, "BOMRef should include version")
		assert.Equal(t, "my-app@1.2.3", rootComp.Name, "Name should include version")
	})

	t.Run("root component should not have version when AssetVersionName is empty", func(t *testing.T) {
		g := NewSBOMGraph()
		artifactID := g.AddArtifact("my-app")
		g.AddInfoSource(artifactID, "trivy", InfoSourceSBOM)

		bom := g.ToCycloneDX(BOMMetadata{
			RootName:     "my-app",
			ArtifactName: "my-app",
		})

		// Find root component
		var rootComp *cdx.Component
		for i := range *bom.Components {
			if (*bom.Components)[i].Name == "my-app" {
				rootComp = &(*bom.Components)[i]
				break
			}
		}

		assert.NotNil(t, rootComp, "Root component should exist")
		assert.Equal(t, "my-app", rootComp.BOMRef, "BOMRef should not have version suffix")
	})

	t.Run("dependencies should reference root with version", func(t *testing.T) {
		g := NewSBOMGraph()
		artifactID := g.AddArtifact("my-app")
		infoSourceID := g.AddInfoSource(artifactID, "trivy", InfoSourceSBOM)

		comp := cdx.Component{
			BOMRef:     "pkg:npm/lodash@4.17.21",
			Name:       "lodash",
			Version:    "4.17.21",
			PackageURL: "pkg:npm/lodash@4.17.21",
			Type:       cdx.ComponentTypeLibrary,
		}
		compID := g.AddComponent(comp)
		g.AddEdge(infoSourceID, compID)

		bom := g.ToCycloneDX(BOMMetadata{
			RootName:         "my-app",
			ArtifactName:     "my-app",
			AssetVersionName: "2.0.0",
		})

		// Find root dependency entry
		var rootDeps *cdx.Dependency
		for i := range *bom.Dependencies {
			if (*bom.Dependencies)[i].Ref == "my-app@2.0.0" {
				rootDeps = &(*bom.Dependencies)[i]
				break
			}
		}

		assert.NotNil(t, rootDeps, "Root dependency entry should exist with version")
		assert.Contains(t, *rootDeps.Dependencies, "pkg:npm/lodash@4.17.21", "Root should depend on lodash")
	})
}

func TestSBOMGraphFromVulnerabilities(t *testing.T) {
	t.Run("VEX should include affected components", func(t *testing.T) {
		// When creating a VEX from vulnerabilities, the components referenced
		// in the Affects field should be included in the output BOM.
		// This is a CycloneDX VEX requirement.
		vulns := []cdx.Vulnerability{
			{
				ID: "CVE-2023-12345",
				Source: &cdx.Source{
					Name: "NVD",
					URL:  "https://nvd.nist.gov/vuln/detail/CVE-2023-12345",
				},
				Affects: &[]cdx.Affects{{
					Ref: "pkg:npm/lodash@4.17.20",
				}},
				Analysis: &cdx.VulnerabilityAnalysis{
					State: cdx.IASNotAffected,
				},
			},
			{
				ID: "CVE-2023-67890",
				Source: &cdx.Source{
					Name: "NVD",
					URL:  "https://nvd.nist.gov/vuln/detail/CVE-2023-67890",
				},
				Affects: &[]cdx.Affects{{
					Ref: "pkg:npm/express@4.18.0",
				}},
				Analysis: &cdx.VulnerabilityAnalysis{
					State: cdx.IASExploitable,
				},
			},
		}

		g := SBOMGraphFromVulnerabilities(vulns)
		bom := g.ToCycloneDX(BOMMetadata{
			RootName:     "my-app",
			ArtifactName: "my-app",
		})

		// Verify vulnerabilities are present
		assert.NotNil(t, bom.Vulnerabilities, "Vulnerabilities should be present")
		assert.Len(t, *bom.Vulnerabilities, 2, "Should have 2 vulnerabilities")

		// Verify the affected components are included in the components list
		assert.NotNil(t, bom.Components, "Components should be present")

		// Find the affected components
		componentPurls := make(map[string]bool)
		for _, comp := range *bom.Components {
			componentPurls[comp.PackageURL] = true
		}

		assert.True(t, componentPurls["pkg:npm/lodash@4.17.20"], "lodash component should be in the BOM")
		assert.True(t, componentPurls["pkg:npm/express@4.18.0"], "express component should be in the BOM")
	})

	t.Run("VEX should include component even when vulnerability affects multiple", func(t *testing.T) {
		// A vulnerability can affect multiple components
		vulns := []cdx.Vulnerability{
			{
				ID: "CVE-2023-99999",
				Affects: &[]cdx.Affects{
					{Ref: "pkg:npm/package-a@1.0.0"},
					{Ref: "pkg:npm/package-b@2.0.0"},
				},
			},
		}

		g := SBOMGraphFromVulnerabilities(vulns)
		bom := g.ToCycloneDX(BOMMetadata{
			RootName:     "my-app",
			ArtifactName: "my-app",
		})

		assert.NotNil(t, bom.Components, "Components should be present")

		componentPurls := make(map[string]bool)
		for _, comp := range *bom.Components {
			componentPurls[comp.PackageURL] = true
		}

		assert.True(t, componentPurls["pkg:npm/package-a@1.0.0"], "package-a should be in the BOM")
		assert.True(t, componentPurls["pkg:npm/package-b@2.0.0"], "package-b should be in the BOM")
	})
}
