package transformer_test

import (
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVulnInPackageToDependencyVulns(t *testing.T) {
	assetID := uuid.New()
	assetVersionName := "main"
	artifactName := "my-artifact"

	t.Run("same CVE in different dependency paths creates separate vulnerabilities", func(t *testing.T) {
		// Create an SBOM graph with the same vulnerable component reachable via two different dependency paths:
		// root -> artifact -> sbom -> trivy -> stdlib
		// root -> artifact -> sbom -> cosign -> stdlib
		// The actual PURL paths are:
		// pkg:golang/trivy@1.0.0 -> pkg:golang/stdlib@1.20.0
		// pkg:golang/cosign@1.0.0 -> pkg:golang/stdlib@1.20.0
		sbom := normalize.NewSBOMGraph()

		artifactID := sbom.AddArtifact(artifactName)
		infoSourceID := sbom.AddInfoSource(artifactID, "sbom-tool", normalize.InfoSourceSBOM)

		// Add intermediate packages (trivy and cosign as actual packages)
		trivyPurl := "pkg:golang/trivy@1.0.0"
		trivyComp := cdx.Component{
			PackageURL: trivyPurl,
			Name:       "trivy",
			Version:    "1.0.0",
			Type:       cdx.ComponentTypeLibrary,
		}
		trivyID := sbom.AddComponent(trivyComp)
		sbom.AddEdge(infoSourceID, trivyID)

		cosignPurl := "pkg:golang/cosign@1.0.0"
		cosignComp := cdx.Component{
			PackageURL: cosignPurl,
			Name:       "cosign",
			Version:    "1.0.0",
			Type:       cdx.ComponentTypeLibrary,
		}
		cosignID := sbom.AddComponent(cosignComp)
		sbom.AddEdge(infoSourceID, cosignID)

		// Add the vulnerable stdlib component
		stdlibPurl := "pkg:golang/stdlib@1.20.0"
		stdlibComp := cdx.Component{
			PackageURL: stdlibPurl,
			Name:       "stdlib",
			Version:    "1.20.0",
			Type:       cdx.ComponentTypeLibrary,
		}
		stdlibID := sbom.AddComponent(stdlibComp)

		// Create two paths to stdlib via different intermediate packages
		sbom.AddEdge(trivyID, stdlibID)
		sbom.AddEdge(cosignID, stdlibID)

		// Scope to the artifact
		err := sbom.ScopeToArtifact(artifactName)
		require.NoError(t, err)

		// Create a vulnerability for stdlib
		purl, err := packageurl.FromString(stdlibPurl)
		require.NoError(t, err)

		vuln := models.VulnInPackage{
			Purl:         purl,
			CVEID:        "CVE-2024-1234",
			FixedVersion: utils.Ptr("1.21.0"),
			CVE: models.CVE{
				CVE:         "CVE-2024-1234",
				Description: "Test vulnerability",
				CVSS:        7.5,
			},
		}

		// Transform the vulnerability
		vulns := transformer.VulnInPackageToDependencyVulns(vuln, sbom, assetID, assetVersionName, artifactName)

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

			// Convert path slice to string for uniqueness check
			pathStrs[strings.Join(v.VulnerabilityPath, ",")] = true

			// Verify artifact is set
			require.Len(t, v.Artifacts, 1)
			assert.Equal(t, artifactName, v.Artifacts[0].ArtifactName)
		}

		// Verify we have 2 distinct paths
		assert.Len(t, pathStrs, 2)

		// Verify the hashes are different (since dependency paths are different)
		// Hash only includes actual package PURLs, not structural nodes
		hash1 := vulns[0].CalculateHash()
		hash2 := vulns[1].CalculateHash()
		assert.NotEqual(t, hash1, hash2)
	})

	t.Run("single path creates single vulnerability", func(t *testing.T) {
		sbom := normalize.NewSBOMGraph()

		artifactID := sbom.AddArtifact(artifactName)
		trivyID := sbom.AddInfoSource(artifactID, "trivy", normalize.InfoSourceSBOM)

		// Add component with single path
		compPurl := "pkg:npm/lodash@4.17.20"
		comp := cdx.Component{
			PackageURL: compPurl,
			Name:       "lodash",
			Version:    "4.17.20",
			Type:       cdx.ComponentTypeLibrary,
		}
		compID := sbom.AddComponent(comp)
		sbom.AddEdge(trivyID, compID)

		err := sbom.ScopeToArtifact(artifactName)
		require.NoError(t, err)

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

		vulns := transformer.VulnInPackageToDependencyVulns(vuln, sbom, assetID, assetVersionName, artifactName)

		assert.Len(t, vulns, 1)
		assert.Equal(t, "CVE-2021-23337", vulns[0].CVEID)
		// Path should contain trivy info source and the component purl
		pathStr := strings.Join(vulns[0].VulnerabilityPath, ",")
		assert.NotContains(t, pathStr, "trivy")
		assert.Contains(t, pathStr, compPurl)
	})

	t.Run("no path found creates fallback vulnerability with empty path", func(t *testing.T) {
		sbom := normalize.NewSBOMGraph()
		sbom.AddArtifact(artifactName)

		err := sbom.ScopeToArtifact(artifactName)
		require.NoError(t, err)

		// Create vuln for a component not in the graph
		purl, err := packageurl.FromString("pkg:npm/unknown@1.0.0")
		require.NoError(t, err)

		vuln := models.VulnInPackage{
			Purl:  purl,
			CVEID: "CVE-2024-9999",
			CVE: models.CVE{
				CVE: "CVE-2024-9999",
			},
		}

		vulns := transformer.VulnInPackageToDependencyVulns(vuln, sbom, assetID, assetVersionName, artifactName)

		assert.Len(t, vulns, 1)
		assert.Empty(t, vulns[0].VulnerabilityPath)
	})

	t.Run("transitive dependency has correct depth", func(t *testing.T) {
		sbom := normalize.NewSBOMGraph()

		artifactID := sbom.AddArtifact(artifactName)
		infoSourceID := sbom.AddInfoSource(artifactID, "npm", normalize.InfoSourceSBOM)

		// Create a chain: infoSource -> dep1 -> dep2 -> vulnerable
		dep1Purl := "pkg:npm/dep1@1.0.0"
		dep1 := cdx.Component{PackageURL: dep1Purl, Name: "dep1", Version: "1.0.0", Type: cdx.ComponentTypeLibrary}
		dep1ID := sbom.AddComponent(dep1)
		sbom.AddEdge(infoSourceID, dep1ID)

		dep2Purl := "pkg:npm/dep2@1.0.0"
		dep2 := cdx.Component{PackageURL: dep2Purl, Name: "dep2", Version: "1.0.0", Type: cdx.ComponentTypeLibrary}
		dep2ID := sbom.AddComponent(dep2)
		sbom.AddEdge(dep1ID, dep2ID)

		vulnPurl := "pkg:npm/vulnerable@1.0.0"
		vulnComp := cdx.Component{PackageURL: vulnPurl, Name: "vulnerable", Version: "1.0.0", Type: cdx.ComponentTypeLibrary}
		vulnID := sbom.AddComponent(vulnComp)
		sbom.AddEdge(dep2ID, vulnID)

		err := sbom.ScopeToArtifact(artifactName)
		require.NoError(t, err)

		purl, err := packageurl.FromString(vulnPurl)
		require.NoError(t, err)

		vuln := models.VulnInPackage{
			Purl:  purl,
			CVEID: "CVE-2024-DEEP",
			CVE:   models.CVE{CVE: "CVE-2024-DEEP"},
		}

		vulns := transformer.VulnInPackageToDependencyVulns(vuln, sbom, assetID, assetVersionName, artifactName)

		assert.Len(t, vulns, 1)
		// Path: dep1 > dep2 > vulnerable = 3 elements, depth = 3
		assert.Equal(t, 3, len(vulns[0].VulnerabilityPath))
		pathStr := strings.Join(vulns[0].VulnerabilityPath, ",")
		assert.Contains(t, pathStr, dep1Purl)
		assert.Contains(t, pathStr, dep2Purl)
		assert.Contains(t, pathStr, vulnPurl)
	})
}
