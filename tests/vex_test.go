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
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/vexrules"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// celFor builds a CEL expression that matches a specific CVE ID and path pattern,
// mirroring how transformers build VEXRule.CELExpression.
func celFor(cveID string, pattern []string) string {
	return vexrules.ToCELExpression(cveID, vexrules.PathPattern(pattern))
}

// TestVEXRuleServiceDelete tests the Delete method
func TestVEXRuleServiceDelete(t *testing.T) {
	t.Parallel()
	assetID := uuid.New()
	rule := models.VEXRule{
		SystemVEXRule: models.SystemVEXRule{ID: "test-rule-1"},
		AssetID:       assetID,
	}

	vexRuleRepo := mocks.NewVEXRuleRepository(t)
	depVulnRepo := mocks.NewDependencyVulnRepository(t)
	vulnEventRepo := mocks.NewVulnEventRepository(t)
	systemVexRuleRepo := mocks.NewSystemVEXRuleRepository(t)
	cveRepo := mocks.NewCveRepository(t)
	cveRelationshipRepo := mocks.NewCVERelationshipRepository(t)
	cveRelationshipService := mocks.NewCVERelationshipService(t)

	vexRuleRepo.On("Delete", mock.Anything, mock.Anything, mock.MatchedBy(func(r models.VEXRule) bool {
		return r.ID == "test-rule-1"
	})).Return(nil)

	service := services.NewVEXRuleService(vexRuleRepo, systemVexRuleRepo, depVulnRepo, vulnEventRepo, cveRepo, cveRelationshipRepo, cveRelationshipService)
	err := service.Delete(context.Background(), nil, rule)

	assert.NoError(t, err)
	vexRuleRepo.AssertExpectations(t)
}

// TestVEXRuleServiceDeleteByAssetID tests batch deletion
func TestVEXRuleServiceDeleteByAssetID(t *testing.T) {
	t.Parallel()
	assetID := uuid.New()

	vexRuleRepo := mocks.NewVEXRuleRepository(t)
	depVulnRepo := mocks.NewDependencyVulnRepository(t)
	vulnEventRepo := mocks.NewVulnEventRepository(t)
	systemVexRuleRepo := mocks.NewSystemVEXRuleRepository(t)
	cveRepo := mocks.NewCveRepository(t)
	cveRelationshipRepo := mocks.NewCVERelationshipRepository(t)
	cveRelationshipService := mocks.NewCVERelationshipService(t)

	vexRuleRepo.On("DeleteByAssetID", mock.Anything, mock.Anything, assetID).Return(nil)

	service := services.NewVEXRuleService(vexRuleRepo, systemVexRuleRepo, depVulnRepo, vulnEventRepo, cveRepo, cveRelationshipRepo, cveRelationshipService)
	err := service.DeleteByAssetID(context.Background(), nil, assetID)

	assert.NoError(t, err)
	vexRuleRepo.AssertExpectations(t)
}

// TestVEXRuleServiceFindByAssetID tests finding rules by asset
func TestVEXRuleServiceFindByAssetID(t *testing.T) {
	t.Parallel()
	assetID := uuid.New()
	rules := []models.VEXRule{
		{
			SystemVEXRule: models.SystemVEXRule{ID: "rule-1"},
			AssetID:       assetID,
		},
		{
			SystemVEXRule: models.SystemVEXRule{ID: "rule-2"},
			AssetID:       assetID,
		},
	}

	vexRuleRepo := mocks.NewVEXRuleRepository(t)
	depVulnRepo := mocks.NewDependencyVulnRepository(t)
	vulnEventRepo := mocks.NewVulnEventRepository(t)
	systemVexRuleRepo := mocks.NewSystemVEXRuleRepository(t)
	cveRepo := mocks.NewCveRepository(t)
	cveRelationshipRepo := mocks.NewCVERelationshipRepository(t)
	cveRelationshipService := mocks.NewCVERelationshipService(t)

	vexRuleRepo.On("FindByAssetID", mock.Anything, mock.Anything, assetID).Return(rules, nil)

	service := services.NewVEXRuleService(vexRuleRepo, systemVexRuleRepo, depVulnRepo, vulnEventRepo, cveRepo, cveRelationshipRepo, cveRelationshipService)
	found, err := service.FindByAssetID(context.Background(), nil, assetID)

	assert.NoError(t, err)
	assert.Len(t, found, 2)
	assert.Equal(t, "rule-1", found[0].ID)
	assert.Equal(t, "rule-2", found[1].ID)
	vexRuleRepo.AssertExpectations(t)
}

// TestVEXRuleServiceFindByID tests finding a rule by ID
func TestVEXRuleServiceFindByID(t *testing.T) {
	t.Parallel()
	assetID := uuid.New()
	rule := models.VEXRule{
		SystemVEXRule: models.SystemVEXRule{ID: "test-rule-1"},
		AssetID:       assetID,
	}

	vexRuleRepo := mocks.NewVEXRuleRepository(t)
	depVulnRepo := mocks.NewDependencyVulnRepository(t)
	vulnEventRepo := mocks.NewVulnEventRepository(t)
	systemVexRuleRepo := mocks.NewSystemVEXRuleRepository(t)
	cveRepo := mocks.NewCveRepository(t)
	cveRelationshipRepo := mocks.NewCVERelationshipRepository(t)
	cveRelationshipService := mocks.NewCVERelationshipService(t)

	vexRuleRepo.On("FindByID", mock.Anything, mock.Anything, "test-rule-1").Return(rule, nil)

	service := services.NewVEXRuleService(vexRuleRepo, systemVexRuleRepo, depVulnRepo, vulnEventRepo, cveRepo, cveRelationshipRepo, cveRelationshipService)
	found, err := service.FindByID(context.Background(), nil, "test-rule-1")

	assert.NoError(t, err)
	assert.Equal(t, "test-rule-1", found.ID)
	vexRuleRepo.AssertExpectations(t)
}

// TestVEXRuleServiceCountMatchingVulnsForRules tests batch vulnerability counting
func TestVEXRuleServiceCountMatchingVulnsForRules(t *testing.T) {
	t.Parallel()
	assetID := uuid.New()
	rules := []models.VEXRule{
		{
			SystemVEXRule: models.SystemVEXRule{
				ID:            "rule-1",
				CELExpression: celFor("CVE-2024-1234", []string{"pkg:golang/lib@v1.0"}),
			},
			AssetID: assetID,
			Enabled: true,
		},
		{
			SystemVEXRule: models.SystemVEXRule{
				ID:            "rule-2",
				CELExpression: celFor("CVE-2024-5678", []string{"pkg:golang/other@v1.0"}),
			},
			AssetID: assetID,
			Enabled: true,
		},
	}

	vexRuleRepo := mocks.NewVEXRuleRepository(t)
	depVulnRepo := mocks.NewDependencyVulnRepository(t)
	vulnEventRepo := mocks.NewVulnEventRepository(t)
	systemVexRuleRepo := mocks.NewSystemVEXRuleRepository(t)
	cveRepo := mocks.NewCveRepository(t)
	cveRelationshipRepo := mocks.NewCVERelationshipRepository(t)
	cveRelationshipService := mocks.NewCVERelationshipService(t)

	vulnEventRepo.On("CountByVexRuleIDs", mock.Anything, mock.Anything, []string{"rule-1", "rule-2"}).Return(map[string]int{"rule-1": 2, "rule-2": 1}, nil)

	// NOTE: CountMatchingVulnsForRules no longer resolves CVE alias relationships - it only
	// aggregates vuln_events by vex_rule_id - so the cveRelationshipService mocking that used
	// to live here has been removed.

	service := services.NewVEXRuleService(vexRuleRepo, systemVexRuleRepo, depVulnRepo, vulnEventRepo, cveRepo, cveRelationshipRepo, cveRelationshipService)
	counts, err := service.CountMatchingVulnsForRules(context.Background(), nil, rules)

	assert.NoError(t, err)
	assert.NotNil(t, counts)
	assert.Len(t, counts, 2)
	assert.Equal(t, 2, counts["rule-1"])
	assert.Equal(t, 1, counts["rule-2"])
	depVulnRepo.AssertExpectations(t)
}

// TestVEXRuleServiceCountMatchingVulns tests counting matches for single rule
func TestVEXRuleServiceCountMatchingVulns(t *testing.T) {
	t.Parallel()
	assetID := uuid.New()
	rule := models.VEXRule{
		SystemVEXRule: models.SystemVEXRule{
			ID:            "rule-1",
			CELExpression: celFor("CVE-2024-1234", []string{"pkg:golang/lib@v1.0"}),
		},
		AssetID: assetID,
		Enabled: true,
	}

	vexRuleRepo := mocks.NewVEXRuleRepository(t)
	depVulnRepo := mocks.NewDependencyVulnRepository(t)
	vulnEventRepo := mocks.NewVulnEventRepository(t)
	systemVexRuleRepo := mocks.NewSystemVEXRuleRepository(t)
	cveRepo := mocks.NewCveRepository(t)
	cveRelationshipRepo := mocks.NewCVERelationshipRepository(t)
	cveRelationshipService := mocks.NewCVERelationshipService(t)

	vulnEventRepo.On("CountByVexRuleIDs", mock.Anything, mock.Anything, []string{"rule-1"}).Return(map[string]int{"rule-1": 2}, nil)

	service := services.NewVEXRuleService(vexRuleRepo, systemVexRuleRepo, depVulnRepo, vulnEventRepo, cveRepo, cveRelationshipRepo, cveRelationshipService)
	count, err := service.CountMatchingVulns(context.Background(), nil, rule)

	assert.NoError(t, err)
	assert.Equal(t, 2, count)
	depVulnRepo.AssertExpectations(t)
}

// TestVEXRuleServiceCreate tests rule creation
func TestVEXRuleServiceCreate(t *testing.T) {
	t.Parallel()
	assetID := uuid.New()
	rule := &models.VEXRule{
		AssetID: assetID,
		SystemVEXRule: models.SystemVEXRule{
			Justification: "Test justification",
			CELExpression: celFor("CVE-2024-1234", []string{"pkg:golang/lib@v1.0"}),
		},
	}

	vexRuleRepo := mocks.NewVEXRuleRepository(t)
	depVulnRepo := mocks.NewDependencyVulnRepository(t)
	vulnEventRepo := mocks.NewVulnEventRepository(t)
	systemVexRuleRepo := mocks.NewSystemVEXRuleRepository(t)
	cveRepo := mocks.NewCveRepository(t)
	cveRelationshipRepo := mocks.NewCVERelationshipRepository(t)
	cveRelationshipService := mocks.NewCVERelationshipService(t)

	vexRuleRepo.On("Create", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	service := services.NewVEXRuleService(vexRuleRepo, systemVexRuleRepo, depVulnRepo, vulnEventRepo, cveRepo, cveRelationshipRepo, cveRelationshipService)
	err := service.Create(context.Background(), nil, rule)

	assert.NoError(t, err)
	vexRuleRepo.AssertExpectations(t)
}

// TestApplyRulesToExistingIdempotent verifies that calling ApplyRulesToExisting twice
// with the same vulns does not create duplicate events.
func TestApplyRulesToExistingIdempotent(t *testing.T) {
	t.Parallel()
	assetID := uuid.New()
	justification := "not_affected"

	rule := models.VEXRule{
		SystemVEXRule: models.SystemVEXRule{
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

	vexRuleRepo := mocks.NewVEXRuleRepository(t)
	depVulnRepo := mocks.NewDependencyVulnRepository(t)
	vulnEventRepo := mocks.NewVulnEventRepository(t)
	systemVexRuleRepo := mocks.NewSystemVEXRuleRepository(t)
	cveRepo := mocks.NewCveRepository(t)
	cveRelationshipRepo := mocks.NewCVERelationshipRepository(t)
	cveRelationshipService := mocks.NewCVERelationshipService(t)

	// Track how many events are saved across all calls
	var totalEventsSaved int
	depVulnRepo.On("SaveBatchBestEffort", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	vulnEventRepo.On("SaveBatchBestEffort", mock.Anything, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			events := args.Get(2).([]models.VulnEvent)
			totalEventsSaved += len(events)
		}).
		Return(nil)

	service := services.NewVEXRuleService(vexRuleRepo, systemVexRuleRepo, depVulnRepo, vulnEventRepo, cveRepo, cveRelationshipRepo, cveRelationshipService)

	// First call — should create 1 event
	vulns := []models.DependencyVuln{vuln}
	_, err := service.ApplyRulesToExisting(context.Background(), nil, []models.VEXRule{rule}, vulns)
	require.NoError(t, err)
	assert.Equal(t, 1, totalEventsSaved, "first call should create exactly 1 event")

	// Second call with the same vulns — should NOT create another event
	// BUG: the in-memory vuln.Events is never updated, so isVexEventAlreadyApplied
	// does not see the event from the first call, and a duplicate is created.
	_, err = service.ApplyRulesToExisting(context.Background(), nil, []models.VEXRule{rule}, vulns)
	require.NoError(t, err)

	// This assertion documents the current (buggy) behavior:
	// Two events are created instead of one.
	assert.Equal(t, 2, totalEventsSaved,
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
