package transformer_test

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sbomOf builds one SBOM from a parent -> children map, rooted at "root".
func sbomOf(artifactName string, children map[string][]string) *normalize.MerkleTree {
	return normalize.BuildMerkleTree(normalize.Adjacency{Children: children}, "root", artifactName)
}

func TestVulnInPackageToDependencyVulns(t *testing.T) {
	assetID := uuid.New()
	assetVersionName := "main"
	artifactName := "my-artifact"

	t.Run("same CVE in different dependency paths creates separate vulnerabilities", func(t *testing.T) {
		// the same vulnerable component reachable via two dependency paths:
		//   pkg:golang/trivy@1.0.0  -> pkg:golang/stdlib@1.20.0
		//   pkg:golang/cosign@1.0.0 -> pkg:golang/stdlib@1.20.0
		trivyPurl := "pkg:golang/trivy@1.0.0"
		cosignPurl := "pkg:golang/cosign@1.0.0"
		stdlibPurl := "pkg:golang/stdlib@1.20.0"

		forest := normalize.MerkleForest{sbomOf(artifactName, map[string][]string{
			"root":     {trivyPurl, cosignPurl},
			trivyPurl:  {stdlibPurl},
			cosignPurl: {stdlibPurl},
		})}

		purl, err := packageurl.FromString(stdlibPurl)
		require.NoError(t, err)

		vuln := models.VulnInPackage{
			Purl:         purl,
			CVEID:        "CVE-2024-1234",
			FixedVersion: new("1.21.0"),
			CVE: models.CVE{
				CVE:         "CVE-2024-1234",
				Description: "Test vulnerability",
				CVSS:        7.5,
			},
		}

		vulns := transformer.VulnInPackageToDependencyVulns(vuln, forest, assetID, assetVersionName, artifactName)

		// Should create 2 separate vulnerabilities, one for each dependency path
		assert.Len(t, vulns, 2)

		// Verify each vuln has a different path but same CVE
		pathStrs := make(map[string]bool)
		for _, v := range vulns {
			assert.Equal(t, "CVE-2024-1234", v.CVEID)
			assert.Equal(t, stdlibPurl, v.ComponentPurl)
			assert.Equal(t, assetID, v.AssetID)
			assert.Equal(t, assetVersionName, v.AssetVersionName)
			assert.NotEmpty(t, v.VulnerabilityPath)

			pathStrs[strings.Join(v.VulnerabilityPath, ",")] = true

			require.Len(t, v.Artifacts, 1)
			assert.Equal(t, artifactName, v.Artifacts[0].ArtifactName)
		}

		// Verify we have 2 distinct paths
		assert.Len(t, pathStrs, 2)

		// Verify the hashes are different (since dependency paths are different)
		hash1 := vulns[0].CalculateHash()
		hash2 := vulns[1].CalculateHash()
		assert.NotEqual(t, hash1, hash2)
	})

	t.Run("single path creates single vulnerability", func(t *testing.T) {
		compPurl := "pkg:npm/lodash@4.17.20"

		forest := normalize.MerkleForest{sbomOf(artifactName, map[string][]string{
			"root": {compPurl},
		})}

		purl, err := packageurl.FromString(compPurl)
		require.NoError(t, err)

		vuln := models.VulnInPackage{
			Purl:  purl,
			CVEID: "CVE-2021-23337",
			CVE: models.CVE{
				CVE:         "CVE-2021-23337",
				Description: "Prototype pollution in lodash",
			},
		}

		vulns := transformer.VulnInPackageToDependencyVulns(vuln, forest, assetID, assetVersionName, artifactName)

		assert.Len(t, vulns, 1)
		assert.Equal(t, "CVE-2021-23337", vulns[0].CVEID)
		// the path holds the component, never the SBOM source it came from
		pathStr := strings.Join(vulns[0].VulnerabilityPath, ",")
		assert.NotContains(t, pathStr, "trivy")
		assert.Contains(t, pathStr, compPurl)
	})

	t.Run("no path found creates fallback vulnerability with empty path", func(t *testing.T) {
		forest := normalize.MerkleForest{sbomOf(artifactName, map[string][]string{})}

		// Create vuln for a component not in the SBOM
		purl, err := packageurl.FromString("pkg:npm/unknown@1.0.0")
		require.NoError(t, err)

		vuln := models.VulnInPackage{
			Purl:  purl,
			CVEID: "CVE-2024-9999",
			CVE: models.CVE{
				CVE: "CVE-2024-9999",
			},
		}

		vulns := transformer.VulnInPackageToDependencyVulns(vuln, forest, assetID, assetVersionName, artifactName)

		assert.Len(t, vulns, 1)
		assert.Empty(t, vulns[0].VulnerabilityPath)
	})

	t.Run("two SBOM sources agreeing on a chain do not create an extra vuln", func(t *testing.T) {
		// One artifact with two origins - a scanner and package-lock.json - that
		// both report pkg:A -> pkg:B. The SBOMs are stored separately, but they
		// agree, so the paths are identical and only ONE vuln is created.
		pkgAPurl := "pkg:npm/a@1.0.0"
		pkgBPurl := "pkg:npm/b@1.0.0"

		chain := map[string][]string{
			"root":   {pkgAPurl},
			pkgAPurl: {pkgBPurl},
		}
		forest := normalize.MerkleForest{
			sbomOf(artifactName, chain),
			sbomOf(artifactName, chain),
		}

		purl, err := packageurl.FromString(pkgBPurl)
		require.NoError(t, err)

		vuln := models.VulnInPackage{
			Purl:  purl,
			CVEID: "CVE-2024-5678",
			CVE:   models.CVE{CVE: "CVE-2024-5678"},
		}

		vulns := transformer.VulnInPackageToDependencyVulns(vuln, forest, assetID, assetVersionName, artifactName)

		assert.Len(t, vulns, 1)
		assert.Equal(t, "CVE-2024-5678", vulns[0].CVEID)
		assert.Equal(t, pkgBPurl, vulns[0].ComponentPurl)
		assert.Equal(t, []string{pkgAPurl, pkgBPurl}, vulns[0].VulnerabilityPath)
	})

	t.Run("two SBOM sources disagreeing about a chain both get reported", func(t *testing.T) {
		// The case the old merged graph could not represent: two origins give
		// the same component different parents, so both paths must survive.
		pkgBPurl := "pkg:npm/b@1.0.0"

		forest := normalize.MerkleForest{
			sbomOf(artifactName, map[string][]string{
				"root":            {"pkg:npm/a@1.0.0"},
				"pkg:npm/a@1.0.0": {pkgBPurl},
			}),
			sbomOf(artifactName, map[string][]string{
				"root":            {"pkg:npm/x@1.0.0"},
				"pkg:npm/x@1.0.0": {pkgBPurl},
			}),
		}

		purl, err := packageurl.FromString(pkgBPurl)
		require.NoError(t, err)

		vulns := transformer.VulnInPackageToDependencyVulns(models.VulnInPackage{
			Purl:  purl,
			CVEID: "CVE-2024-DISAGREE",
			CVE:   models.CVE{CVE: "CVE-2024-DISAGREE"},
		}, forest, assetID, assetVersionName, artifactName)

		require.Len(t, vulns, 2)
		paths := []string{
			strings.Join(vulns[0].VulnerabilityPath, ","),
			strings.Join(vulns[1].VulnerabilityPath, ","),
		}
		assert.Contains(t, paths, "pkg:npm/a@1.0.0,"+pkgBPurl)
		assert.Contains(t, paths, "pkg:npm/x@1.0.0,"+pkgBPurl)
	})

	t.Run("transitive dependency has correct depth", func(t *testing.T) {
		dep1Purl := "pkg:npm/dep1@1.0.0"
		dep2Purl := "pkg:npm/dep2@1.0.0"
		vulnPurl := "pkg:npm/vulnerable@1.0.0"

		forest := normalize.MerkleForest{sbomOf(artifactName, map[string][]string{
			"root":   {dep1Purl},
			dep1Purl: {dep2Purl},
			dep2Purl: {vulnPurl},
		})}

		purl, err := packageurl.FromString(vulnPurl)
		require.NoError(t, err)

		vuln := models.VulnInPackage{
			Purl:  purl,
			CVEID: "CVE-2024-DEEP",
			CVE:   models.CVE{CVE: "CVE-2024-DEEP"},
		}

		vulns := transformer.VulnInPackageToDependencyVulns(vuln, forest, assetID, assetVersionName, artifactName)

		assert.Len(t, vulns, 1)
		// Path: dep1 > dep2 > vulnerable = 3 elements, depth = 3
		assert.Equal(t, 3, len(vulns[0].VulnerabilityPath))
		pathStr := strings.Join(vulns[0].VulnerabilityPath, ",")
		assert.Contains(t, pathStr, dep1Purl)
		assert.Contains(t, pathStr, dep2Purl)
		assert.Contains(t, pathStr, vulnPurl)
	})
}
