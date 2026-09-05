package normalize

import (
	"encoding/json"
	"os"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
)

// buildTree assembles a tree the way the parser would, with the SBOM's direct
// dependencies hanging off the parse root.
func buildTree(children map[string][]string, artifactName string) *MerkleTree {
	return BuildMerkleTree(Adjacency{Children: children}, merkleParseRoot, artifactName)
}

func findDependency(bom *cdx.BOM, ref string) *cdx.Dependency {
	for i := range *bom.Dependencies {
		if (*bom.Dependencies)[i].Ref == ref {
			return &(*bom.Dependencies)[i]
		}
	}
	return nil
}

func TestContainerScanRootComponentSharesArtifactPurlStaysReachable(t *testing.T) {
	artifactName := "pkg:oci/my-image"

	bom := &cdx.BOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: cdx.SpecVersion1_6,
		Metadata: &cdx.Metadata{
			Component: &cdx.Component{
				BOMRef:     "pkg:oci/my-image@sha256:deadbeef",
				Name:       "my-image",
				PackageURL: "pkg:oci/my-image@sha256:deadbeef",
				Type:       cdx.ComponentTypeContainer,
			},
		},
		Components: &[]cdx.Component{{
			BOMRef:     "pkg:npm/vulnerable-lib@1.0.0",
			Name:       "vulnerable-lib",
			Version:    "1.0.0",
			PackageURL: "pkg:npm/vulnerable-lib@1.0.0",
			Type:       cdx.ComponentTypeLibrary,
		}},
		Dependencies: &[]cdx.Dependency{
			{Ref: "pkg:oci/my-image@sha256:deadbeef", Dependencies: &[]string{"pkg:npm/vulnerable-lib@1.0.0"}},
		},
	}

	parsed, err := MerkleTreeFromCycloneDX(bom, artifactName)
	assert.NoError(t, err)

	assert.Contains(t, parsed.Tree.ComponentIDs(), "pkg:npm/vulnerable-lib@1.0.0",
		"the scanned image's real component must stay reachable from the artifact")
}

func TestStackOverflowSBOMToMerkleTree(t *testing.T) {
	// read the testdata/stack-overflow-sbom.json to reproduce the issue
	b, _ := os.ReadFile("testdata/stack-overflow-sbom.json")
	var bom cdx.BOM
	err := json.Unmarshal(b, &bom)
	assert.NoError(t, err, "Should unmarshal the test SBOM without error")

	_, err = MerkleTreeFromCycloneDX(&bom, "")
	assert.NoError(t, err, "Should build a merkle tree from the CycloneDX BOM without error")
}

func TestMerkleTreeFromCycloneDXShortCircuitsInvalidIntermediaryNode(t *testing.T) {
	deps := []cdx.Dependency{
		{Ref: "root", Dependencies: &[]string{"pkg:npm/a@1.0.0"}},
		{Ref: "pkg:npm/a@1.0.0", Dependencies: &[]string{"invalid-node"}},
		{Ref: "invalid-node", Dependencies: &[]string{"pkg:npm/c@3.0.0"}},
	}

	bom := &cdx.BOM{
		SpecVersion: cdx.SpecVersion1_6,
		BOMFormat:   "CycloneDX",
		Version:     1,
		Metadata: &cdx.Metadata{
			Component: &cdx.Component{
				BOMRef: "root",
				Name:   "root",
				Type:   cdx.ComponentTypeApplication,
			},
		},
		Components: &[]cdx.Component{
			{
				BOMRef:     "pkg:npm/a@1.0.0",
				Name:       "a",
				Version:    "1.0.0",
				PackageURL: "pkg:npm/a@1.0.0",
				Type:       cdx.ComponentTypeLibrary,
			},
			{
				BOMRef:     "pkg:npm/c@3.0.0",
				Name:       "c",
				Version:    "3.0.0",
				PackageURL: "pkg:npm/c@3.0.0",
				Type:       cdx.ComponentTypeLibrary,
			},
		},
		Dependencies: &deps,
	}

	parsed, err := MerkleTreeFromCycloneDX(bom, "")
	assert.NoError(t, err)

	exported := parsed.Tree.ToCycloneDX(BOMMetadata{RootName: "root", ArtifactName: "root"}, parsed.Components)
	assert.NotNil(t, exported.Dependencies)

	rootDeps := findDependency(exported, "root")
	aDeps := findDependency(exported, "pkg:npm/a@1.0.0")

	assert.NotNil(t, rootDeps)
	assert.NotNil(t, rootDeps.Dependencies)
	assert.Contains(t, *rootDeps.Dependencies, "pkg:npm/a@1.0.0")
	assert.NotContains(t, *rootDeps.Dependencies, "pkg:npm/c@3.0.0")

	assert.NotNil(t, aDeps)
	assert.NotNil(t, aDeps.Dependencies)
	assert.Contains(t, *aDeps.Dependencies, "pkg:npm/c@3.0.0", "A should be short-circuited to C through invalid intermediary")
	assert.NotContains(t, *aDeps.Dependencies, "invalid-node")
}

func TestMerkleTreeFromCycloneDXShortCircuitsMultipleInvalidIntermediaryNodes(t *testing.T) {
	deps := []cdx.Dependency{
		{Ref: "root", Dependencies: &[]string{"pkg:npm/a@1.0.0"}},
		{Ref: "pkg:npm/a@1.0.0", Dependencies: &[]string{"invalid-node-1"}},
		{Ref: "invalid-node-1", Dependencies: &[]string{"invalid-node-2"}},
		{Ref: "invalid-node-2", Dependencies: &[]string{"pkg:npm/c@3.0.0"}},
	}

	bom := &cdx.BOM{
		SpecVersion: cdx.SpecVersion1_6,
		BOMFormat:   "CycloneDX",
		Version:     1,
		Metadata: &cdx.Metadata{
			Component: &cdx.Component{
				BOMRef: "root",
				Name:   "root",
				Type:   cdx.ComponentTypeApplication,
			},
		},
		Components: &[]cdx.Component{
			{
				BOMRef:     "pkg:npm/a@1.0.0",
				Name:       "a",
				Version:    "1.0.0",
				PackageURL: "pkg:npm/a@1.0.0",
				Type:       cdx.ComponentTypeLibrary,
			},
			{
				BOMRef:     "pkg:npm/c@3.0.0",
				Name:       "c",
				Version:    "3.0.0",
				PackageURL: "pkg:npm/c@3.0.0",
				Type:       cdx.ComponentTypeLibrary,
			},
		},
		Dependencies: &deps,
	}

	parsed, err := MerkleTreeFromCycloneDX(bom, "")
	assert.NoError(t, err)

	exported := parsed.Tree.ToCycloneDX(BOMMetadata{RootName: "root", ArtifactName: "root"}, parsed.Components)
	assert.NotNil(t, exported.Dependencies)

	rootDeps := findDependency(exported, "root")
	aDeps := findDependency(exported, "pkg:npm/a@1.0.0")

	assert.NotNil(t, rootDeps)
	assert.NotNil(t, rootDeps.Dependencies)
	assert.Contains(t, *rootDeps.Dependencies, "pkg:npm/a@1.0.0")

	assert.NotNil(t, aDeps)
	assert.NotNil(t, aDeps.Dependencies)
	assert.Contains(t, *aDeps.Dependencies, "pkg:npm/c@3.0.0", "A should be short-circuited through multiple invalid intermediaries")
	assert.NotContains(t, *aDeps.Dependencies, "invalid-node-1")
	assert.NotContains(t, *aDeps.Dependencies, "invalid-node-2")
}

func TestToCycloneDX(t *testing.T) {
	t.Run("transitive dependencies should not be direct children of root", func(t *testing.T) {
		// root -> A -> B -> C: only A is a direct dependency of root
		tree := buildTree(map[string][]string{
			merkleParseRoot:   {"pkg:npm/a@1.0.0"},
			"pkg:npm/a@1.0.0": {"pkg:npm/b@2.0.0"},
			"pkg:npm/b@2.0.0": {"pkg:npm/c@3.0.0"},
		}, "my-app")

		bom := tree.ToCycloneDX(BOMMetadata{
			RootName:     "my-app",
			ArtifactName: "my-app",
		}, nil)

		assert.NotNil(t, bom.Dependencies)

		rootDeps := findDependency(bom, "my-app")
		aDeps := findDependency(bom, "pkg:npm/a@1.0.0")
		bDeps := findDependency(bom, "pkg:npm/b@2.0.0")
		cDeps := findDependency(bom, "pkg:npm/c@3.0.0")

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
		tree := buildTree(map[string][]string{
			merkleParseRoot: {"pkg:npm/a@1.0.0", "pkg:npm/b@2.0.0"},
		}, "my-app")

		bom := tree.ToCycloneDX(BOMMetadata{
			RootName:     "my-app",
			ArtifactName: "my-app",
		}, nil)

		assert.NotNil(t, bom.Dependencies)

		rootDeps := findDependency(bom, "my-app")

		assert.NotNil(t, rootDeps)
		assert.NotNil(t, rootDeps.Dependencies)
		assert.Len(t, *rootDeps.Dependencies, 2, "Root should have exactly 2 direct dependencies")
		assert.Contains(t, *rootDeps.Dependencies, "pkg:npm/a@1.0.0")
		assert.Contains(t, *rootDeps.Dependencies, "pkg:npm/b@2.0.0")
	})

	t.Run("diamond dependency pattern", func(t *testing.T) {
		// root -> A, root -> B, A -> C, B -> C
		tree := buildTree(map[string][]string{
			merkleParseRoot:   {"pkg:npm/a@1.0.0", "pkg:npm/b@2.0.0"},
			"pkg:npm/a@1.0.0": {"pkg:npm/c@3.0.0"},
			"pkg:npm/b@2.0.0": {"pkg:npm/c@3.0.0"},
		}, "my-app")

		bom := tree.ToCycloneDX(BOMMetadata{
			RootName:     "my-app",
			ArtifactName: "my-app",
		}, nil)

		assert.NotNil(t, bom.Dependencies)

		rootDeps := findDependency(bom, "my-app")
		aDeps := findDependency(bom, "pkg:npm/a@1.0.0")
		bDeps := findDependency(bom, "pkg:npm/b@2.0.0")

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
		tree := buildTree(map[string][]string{}, "my-app")

		bom := tree.ToCycloneDX(BOMMetadata{
			ArtifactName:     "my-app",
			AssetVersionName: "1.2.3",
		}, nil)

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
		tree := buildTree(map[string][]string{}, "my-app")

		bom := tree.ToCycloneDX(BOMMetadata{
			RootName:     "my-app",
			ArtifactName: "my-app",
		}, nil)

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
		tree := buildTree(map[string][]string{
			merkleParseRoot: {"pkg:npm/lodash@4.17.21"},
		}, "my-app")

		bom := tree.ToCycloneDX(BOMMetadata{
			ArtifactName:     "my-app",
			AssetVersionName: "2.0.0",
		}, nil)

		rootDeps := findDependency(bom, "my-app@2.0.0")

		assert.NotNil(t, rootDeps, "Root dependency entry should exist with version")
		assert.Contains(t, *rootDeps.Dependencies, "pkg:npm/lodash@4.17.21", "Root should depend on lodash")
	})
}

func TestCycloneDXVEXFromVulnerabilities(t *testing.T) {
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

		bom := CycloneDXVEXFromVulnerabilities(vulns, BOMMetadata{
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

		bom := CycloneDXVEXFromVulnerabilities(vulns, BOMMetadata{
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

func TestToCycloneDXRootPURLWithQualifiers(t *testing.T) {
	tests := []struct {
		name             string
		artifactName     string
		assetVersionName string
		expectedVersion  string
		expectedPURL     string
	}{
		{
			name:             "PURL with qualifiers should have version before qualifiers",
			artifactName:     "pkg:oci/devguard?repository_url=ghcr.io/l3montree-dev/devguard",
			assetVersionName: "1.0.0",
			expectedVersion:  "1.0.0",
			expectedPURL:     "pkg:oci/devguard@1.0.0?repository_url=ghcr.io%2Fl3montree-dev%2Fdevguard",
		},
		{
			name:             "PURL without qualifiers works normally",
			artifactName:     "pkg:oci/devguard",
			assetVersionName: "2.0.0",
			expectedVersion:  "2.0.0",
			expectedPURL:     "pkg:oci/devguard@2.0.0",
		},
		{
			name:             "PURL with multiple qualifiers preserves all qualifiers",
			artifactName:     "pkg:oci/myapp?repository_url=ghcr.io/org/myapp&tag=latest",
			assetVersionName: "3.0.0",
			expectedVersion:  "3.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree := buildTree(map[string][]string{}, tt.artifactName)

			bom := tree.ToCycloneDX(BOMMetadata{
				ArtifactName:     tt.artifactName,
				AssetVersionName: tt.assetVersionName,
			}, nil)

			// Find the root component
			var rootComp *cdx.Component
			for i := range *bom.Components {
				c := &(*bom.Components)[i]
				if c.Type == cdx.ComponentTypeApplication {
					rootComp = c
					break
				}
			}

			assert.NotNil(t, rootComp, "Root component should exist")
			assert.NotEmpty(t, rootComp.PackageURL, "Root component should have a valid PackageURL")

			// Parse the resulting PURL to verify it's structurally valid
			parsedPURL, err := packageurl.FromString(rootComp.PackageURL)
			assert.NoError(t, err, "Root PackageURL should be a valid PURL: %s", rootComp.PackageURL)
			assert.Equal(t, tt.expectedVersion, parsedPURL.Version, "PURL version should match")

			if tt.expectedPURL != "" {
				assert.Equal(t, tt.expectedPURL, rootComp.PackageURL, "PackageURL should be correctly formed")
			}
		})
	}
}
