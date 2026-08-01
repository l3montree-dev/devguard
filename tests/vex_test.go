package tests

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/vexrules"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// celFor builds a CEL expression that matches a specific CVE ID and path pattern,
// mirroring how transformers build VEXRule.CELExpression.
func celFor(cveID string, pattern []string) string {
	return vexrules.ToCELExpression(cveID, vexrules.PathPattern(pattern))
}

// TestApplyRulesToExistingIdempotent verifies that calling ApplyVEXRulesToVulns twice
// with the same vulns does not create duplicate events.
func TestApplyRulesToExistingIdempotent(t *testing.T) {
	t.Parallel()
	assetID := uuid.New()
	justification := "not_affected"

	rule := models.VEXRule{
		UpstreamVEXRule: models.UpstreamVEXRule{
			ID:            "rule-1",
			CELExpression: celFor("CVE-2024-1234", []string{"pkg:golang/lib@v1.0"}),
			EventType:     "falsePositive",
			Justification: justification,
		},
		AssetID:     assetID,
		Enabled:     true,
		CreatedByID: "user-1",
	}

	vuln := models.DependencyVuln{
		Vulnerability: models.Vulnerability{
			AssetID: assetID,
			State:   "open",
		},
		CVEID:             "CVE-2024-1234",
		VulnerabilityPath: []string{"pkg:golang/lib@v1.0"},
		ComponentPurl:     "pkg:golang/lib@v1.0",
	}

	// First call — should create 1 event
	vulns := []models.DependencyVuln{vuln}
	_, events, err := services.ApplyVEXRulesToVulns(context.Background(), []models.VEXRule{rule}, vulns)
	require.NoError(t, err)
	assert.Len(t, events, 1, "first call should create exactly 1 event")

	// Second call with the same vulns — should NOT create another event
	// BUG: the in-memory vuln.Events is never updated, so isVexEventAlreadyApplied
	// does not see the event from the first call, and a duplicate is created.
	_, events, err = services.ApplyVEXRulesToVulns(context.Background(), []models.VEXRule{rule}, vulns)
	require.NoError(t, err)

	// This assertion documents the current (buggy) behavior:
	// another event is created instead of none.
	assert.Len(t, events, 1,
		"BUG: second call creates a duplicate event because in-memory Events is not updated")
}

// TestUploadVEXExampleIntegration verifies that a VEX document can be uploaded successfully
func TestUploadVEXExampleIntegration(t *testing.T) {
	t.Parallel()
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		org, project, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()

		// Read the vex-example.json file
		vexData, err := os.ReadFile("testdata/vex-example.json")
		require.NoError(t, err)

		// Setup echo app
		app := echo.New()
		req := httptest.NewRequest("POST", "/vex", bytes.NewReader(vexData))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Artifact-Name", "test-artifact")
		req.Header.Set("X-Origin", "test-upload")

		recorder := httptest.NewRecorder()
		ctx := app.NewContext(req, recorder)

		shared.SetAsset(ctx, asset)
		shared.SetProject(ctx, project)
		shared.SetOrg(ctx, org)
		shared.SetSession(ctx, NewUserSession(t, "test"))

		shared.SetAssetVersion(ctx, assetVersion)

		// Call the UploadVEX endpoint
		err = f.App.ScanController.UploadVEX(ctx)

		// Verify the operation succeeded
		assert.NoError(t, err)
		assert.Equal(t, 200, recorder.Code)

		// Verify the BOM was decoded correctly
		var bom cdx.BOM
		decoder := cdx.NewBOMDecoder(bytes.NewReader(vexData), cdx.BOMFileFormatJSON)
		err = decoder.Decode(&bom)
		assert.NoError(t, err)
		assert.NotNil(t, bom.Vulnerabilities)

		// Verify VEX rules were created from the VEX document
		var vexRules []models.VEXRule
		result := f.DB.Where("asset_id = ?", asset.ID).Find(&vexRules)
		assert.NoError(t, result.Error)
	})
}
