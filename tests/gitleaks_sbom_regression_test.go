package tests

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/l3montree-dev/devguard/cmd/devguard-scanner/commands"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func loadGitleaksReproBOM(t *testing.T, relPath string) *cdx.BOM {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata/gitleaks_repro", relPath))
	if err != nil {
		t.Fatal(err)
	}
	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(bytes.NewReader(b), cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
		t.Fatalf("%s: %v", relPath, err)
	}
	return &bom
}

func createCveXCrypto(db shared.DB) {
	cve := models.CVE{
		CVE:  "CVE-2099-00001",
		CVSS: 10.0,
	}
	if err := db.Create(&cve).Error; err != nil {
		panic(err)
	}

	affectedComponent := models.AffectedComponent{
		PurlWithoutVersion: "pkg:golang/golang.org/x/crypto",
		SemverFixed:        new("0.52.0"),
	}
	if err := db.Create(&affectedComponent).Error; err != nil {
		panic(err)
	}
	if err := db.Model(&cve).Association("AffectedComponents").Append(&affectedComponent); err != nil {
		panic(err)
	}
}

// TestGitleaksVulnPathThroughRealBackend merges every supplementary SBOM
// baked into the devguard-scanner image (gitleaks, trivy, crane,
// devguard-scanner itself, its python tools, semgrep) into a real trivy
// image scan of that image - exactly what `sca` does at runtime - uploads
// the result to the real dependency-vuln scan endpoint, and checks that the
// x/crypto vulnerability is attributed to gitleaks, not to root. This is the
// end-to-end version of https://github.com/l3montree-dev/devguard/issues/2463.
func TestGitleaksVulnPathThroughRealBackend(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		createCveXCrypto(f.DB)

		bom := loadGitleaksReproBOM(t, "main.json")
		extraNames := []string{
			"supplementary/gitleaks.json",
			"supplementary/crane.json",
			"supplementary/devguard-scanner.json",
			"supplementary/devguard-scanner-tools.json",
			"supplementary/semgrep-core.json",
			"supplementary/trivy.json",
		}
		var extras []*cdx.BOM
		for _, name := range extraNames {
			extras = append(extras, loadGitleaksReproBOM(t, name))
		}
		if err := commands.MergeSupplementarySBOMs(bom, extras); err != nil {
			t.Fatal(err)
		}

		bomBytes, err := json.Marshal(bom)
		assert.Nil(t, err)

		controller := f.App.ScanController
		app := echo.New()
		org, project, asset, _ := f.CreateOrgProjectAssetAndVersion()

		recorder := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", bytes.NewReader(bomBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Artifact-Name", "pkg:oci/devguard-scanner")
		req.Header.Set("X-Asset-Default-Branch", "main")
		req.Header.Set("X-Asset-Ref", "main")
		req.Header.Set("X-Origin", "test")
		ctx := app.NewContext(req, recorder)

		authSession := NewUserSession(t, "abc")
		shared.SetAsset(ctx, asset)
		shared.SetProject(ctx, project)
		shared.SetOrg(ctx, org)
		shared.SetSession(ctx, authSession)

		err = controller.ScanDependencyVulnFromProject(ctx)
		assert.Nil(t, err)
		assert.Equal(t, 200, recorder.Code)

		var response dtos.ScanResponse
		assert.Nil(t, json.Unmarshal(recorder.Body.Bytes(), &response))
		assert.NotEmpty(t, response.DependencyVulns, "expected at least one dependency vuln for x/crypto")

		for _, vuln := range response.DependencyVulns {
			assert.Equal(t, "CVE-2099-00001", vuln.CVEID)
			assert.Equal(t, "pkg:golang/golang.org/x/crypto@v0.35.0", vuln.ComponentPurl)
			assert.True(t, slices.ContainsFunc(vuln.VulnerabilityPath, func(ref string) bool {
				return bytes.Contains([]byte(ref), []byte("zricethezav/gitleaks"))
			}), "vulnerability path should go through gitleaks, got %v", vuln.VulnerabilityPath)
		}
	})
}
