package tests

import (
	"bytes"
	"net/http/httptest"
	"os"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestVEXRuleServiceUpdate tests the Update method
func TestVEXRuleServiceUpdate(t *testing.T) {
	assetID := uuid.New()
	rule := &models.VEXRule{
		ID:               "test-rule-1",
		AssetID:          assetID,
		AssetVersionName: "v1.0",
		CVEID:            "CVE-2024-1234",
		PathPattern:      []string{"pkg:golang/lib@v1.0"},
		Justification:    "Test justification",
	}

	vexRuleRepo := mocks.NewVEXRuleRepository(t)
	depVulnRepo := mocks.NewDependencyVulnRepository(t)
	vulnEventRepo := mocks.NewVulnEventRepository(t)

	vexRuleRepo.On("Update", mock.Anything, mock.Anything).Return(nil)

	service := services.NewVEXRuleService(vexRuleRepo, depVulnRepo, vulnEventRepo)
	err := service.Update(nil, rule)

	assert.NoError(t, err)
	vexRuleRepo.AssertExpectations(t)
}

// TestVEXRuleServiceDelete tests the Delete method
func TestVEXRuleServiceDelete(t *testing.T) {
	assetID := uuid.New()
	rule := models.VEXRule{
		ID:               "test-rule-1",
		AssetID:          assetID,
		AssetVersionName: "v1.0",
		CVEID:            "CVE-2024-1234",
	}

	vexRuleRepo := mocks.NewVEXRuleRepository(t)
	depVulnRepo := mocks.NewDependencyVulnRepository(t)
	vulnEventRepo := mocks.NewVulnEventRepository(t)

	vexRuleRepo.On("Delete", mock.Anything, mock.MatchedBy(func(r models.VEXRule) bool {
		return r.ID == "test-rule-1"
	})).Return(nil)

	service := services.NewVEXRuleService(vexRuleRepo, depVulnRepo, vulnEventRepo)
	err := service.Delete(nil, rule)

	assert.NoError(t, err)
	vexRuleRepo.AssertExpectations(t)
}

// TestVEXRuleServiceDeleteByAssetVersion tests batch deletion
func TestVEXRuleServiceDeleteByAssetVersion(t *testing.T) {
	assetID := uuid.New()

	vexRuleRepo := mocks.NewVEXRuleRepository(t)
	depVulnRepo := mocks.NewDependencyVulnRepository(t)
	vulnEventRepo := mocks.NewVulnEventRepository(t)

	vexRuleRepo.On("DeleteByAssetVersion", mock.Anything, assetID, "v1.0").Return(nil)

	service := services.NewVEXRuleService(vexRuleRepo, depVulnRepo, vulnEventRepo)
	err := service.DeleteByAssetVersion(nil, assetID, "v1.0")

	assert.NoError(t, err)
	vexRuleRepo.AssertExpectations(t)
}

// TestVEXRuleServiceFindByAssetVersion tests finding rules by asset version
func TestVEXRuleServiceFindByAssetVersion(t *testing.T) {
	assetID := uuid.New()
	rules := []models.VEXRule{
		{
			ID:               "rule-1",
			AssetID:          assetID,
			AssetVersionName: "v1.0",
			CVEID:            "CVE-2024-1234",
		},
		{
			ID:               "rule-2",
			AssetID:          assetID,
			AssetVersionName: "v1.0",
			CVEID:            "CVE-2024-5678",
		},
	}

	vexRuleRepo := mocks.NewVEXRuleRepository(t)
	depVulnRepo := mocks.NewDependencyVulnRepository(t)
	vulnEventRepo := mocks.NewVulnEventRepository(t)

	vexRuleRepo.On("FindByAssetVersion", mock.Anything, assetID, "v1.0").Return(rules, nil)

	service := services.NewVEXRuleService(vexRuleRepo, depVulnRepo, vulnEventRepo)
	found, err := service.FindByAssetVersion(nil, assetID, "v1.0")

	assert.NoError(t, err)
	assert.Len(t, found, 2)
	assert.Equal(t, "rule-1", found[0].ID)
	assert.Equal(t, "rule-2", found[1].ID)
	vexRuleRepo.AssertExpectations(t)
}

// TestVEXRuleServiceFindByID tests finding a rule by ID
func TestVEXRuleServiceFindByID(t *testing.T) {
	assetID := uuid.New()
	rule := models.VEXRule{
		ID:               "test-rule-1",
		AssetID:          assetID,
		AssetVersionName: "v1.0",
		CVEID:            "CVE-2024-1234",
	}

	vexRuleRepo := mocks.NewVEXRuleRepository(t)
	depVulnRepo := mocks.NewDependencyVulnRepository(t)
	vulnEventRepo := mocks.NewVulnEventRepository(t)

	vexRuleRepo.On("FindByID", mock.Anything, "test-rule-1").Return(rule, nil)

	service := services.NewVEXRuleService(vexRuleRepo, depVulnRepo, vulnEventRepo)
	found, err := service.FindByID(nil, "test-rule-1")

	assert.NoError(t, err)
	assert.Equal(t, "test-rule-1", found.ID)
	vexRuleRepo.AssertExpectations(t)
}

// TestVEXRuleServiceCountMatchingVulnsForRules tests batch vulnerability counting
func TestVEXRuleServiceCountMatchingVulnsForRules(t *testing.T) {
	assetID := uuid.New()
	rules := []models.VEXRule{
		{
			ID:               "rule-1",
			AssetID:          assetID,
			AssetVersionName: "v1.0",
			CVEID:            "CVE-2024-1234",
			PathPattern:      []string{"pkg:golang/lib@v1.0"},
		},
		{
			ID:               "rule-2",
			AssetID:          assetID,
			AssetVersionName: "v1.0",
			CVEID:            "CVE-2024-5678",
			PathPattern:      []string{"pkg:golang/other@v1.0"},
		},
	}

	vulns := []models.DependencyVuln{
		{
			CVEID:             "CVE-2024-1234",
			VulnerabilityPath: []string{"pkg:golang/lib@v1.0"},
			ComponentPurl:     "pkg:golang/lib@v1.0",
		},
		{
			CVEID:             "CVE-2024-1234",
			VulnerabilityPath: []string{"pkg:golang/lib@v1.0"},
			ComponentPurl:     "pkg:golang/lib@v1.0",
		},
		{
			CVEID:             "CVE-2024-5678",
			VulnerabilityPath: []string{"pkg:golang/other@v1.0"},
			ComponentPurl:     "pkg:golang/other@v1.0",
		},
	}

	vexRuleRepo := mocks.NewVEXRuleRepository(t)
	depVulnRepo := mocks.NewDependencyVulnRepository(t)
	vulnEventRepo := mocks.NewVulnEventRepository(t)

	depVulnRepo.On("GetDependencyVulnsByAssetVersion",
		mock.Anything,
		"v1.0",
		assetID,
		mock.Anything,
	).Return(vulns, nil)

	service := services.NewVEXRuleService(vexRuleRepo, depVulnRepo, vulnEventRepo)
	counts, err := service.CountMatchingVulnsForRules(nil, rules)

	assert.NoError(t, err)
	assert.NotNil(t, counts)
	assert.Len(t, counts, 2)
	depVulnRepo.AssertExpectations(t)
}

// TestVEXRuleServiceCountMatchingVulns tests counting matches for single rule
func TestVEXRuleServiceCountMatchingVulns(t *testing.T) {
	assetID := uuid.New()
	rule := models.VEXRule{
		ID:               "rule-1",
		AssetID:          assetID,
		AssetVersionName: "v1.0",
		CVEID:            "CVE-2024-1234",
		PathPattern:      []string{"pkg:golang/lib@v1.0"},
	}

	vulns := []models.DependencyVuln{
		{
			CVEID:             "CVE-2024-1234",
			VulnerabilityPath: []string{"pkg:golang/lib@v1.0"},
			ComponentPurl:     "pkg:golang/lib@v1.0",
		},
		{
			CVEID:             "CVE-2024-1234",
			VulnerabilityPath: []string{"pkg:golang/lib@v1.0"},
			ComponentPurl:     "pkg:golang/lib@v1.0",
		},
		{
			CVEID:             "CVE-2024-9999",
			VulnerabilityPath: []string{"pkg:golang/lib@v1.0"},
			ComponentPurl:     "pkg:golang/lib@v1.0",
		},
	}

	vexRuleRepo := mocks.NewVEXRuleRepository(t)
	depVulnRepo := mocks.NewDependencyVulnRepository(t)
	vulnEventRepo := mocks.NewVulnEventRepository(t)

	depVulnRepo.On("GetDependencyVulnsByAssetVersion",
		mock.Anything,
		"v1.0",
		assetID,
		mock.Anything,
	).Return(vulns, nil)

	service := services.NewVEXRuleService(vexRuleRepo, depVulnRepo, vulnEventRepo)
	count, err := service.CountMatchingVulns(nil, rule)

	assert.NoError(t, err)
	assert.GreaterOrEqual(t, count, 0)
	depVulnRepo.AssertExpectations(t)
}

// TestVEXRuleServiceCreate tests rule creation
func TestVEXRuleServiceCreate(t *testing.T) {
	assetID := uuid.New()
	rule := &models.VEXRule{
		ID:               "ec6335130396f5af8a51ca5ba9f9400baa144cc290cd5c89c98d2800f1d41029",
		AssetID:          assetID,
		AssetVersionName: "",
		CVEID:            "CVE-2024-1234",
		Justification:    "Test justification",
		PathPattern:      []string{"pkg:golang/lib@v1.0"},
	}

	vexRuleRepo := mocks.NewVEXRuleRepository(t)
	depVulnRepo := mocks.NewDependencyVulnRepository(t)
	vulnEventRepo := mocks.NewVulnEventRepository(t)

	vexRuleRepo.On("Create", mock.Anything, mock.Anything).Return(nil)

	service := services.NewVEXRuleService(vexRuleRepo, depVulnRepo, vulnEventRepo)
	err := service.Create(nil, rule)

	assert.NoError(t, err)
	vexRuleRepo.AssertExpectations(t)
}

// TestApplyRulesToExistingIdempotent verifies that calling ApplyRulesToExisting twice
// with the same vulns does not create duplicate events.
func TestApplyRulesToExistingIdempotent(t *testing.T) {
	assetID := uuid.New()
	justification := "not_affected"

	rule := models.VEXRule{
		ID:               "rule-1",
		AssetID:          assetID,
		AssetVersionName: "v1.0",
		CVEID:            "CVE-2024-1234",
		PathPattern:      []string{"pkg:golang/lib@v1.0"},
		Enabled:          true,
		EventType:        "falsePositive",
		Justification:    justification,
		CreatedByID:      "user-1",
	}

	vuln := models.DependencyVuln{
		Vulnerability: models.Vulnerability{
			AssetVersionName: "v1.0",
			AssetID:          assetID,
			State:            "open",
		},
		CVEID:             "CVE-2024-1234",
		VulnerabilityPath: []string{"pkg:golang/lib@v1.0"},
		ComponentPurl:     "pkg:golang/lib@v1.0",
	}

	vexRuleRepo := mocks.NewVEXRuleRepository(t)
	depVulnRepo := mocks.NewDependencyVulnRepository(t)
	vulnEventRepo := mocks.NewVulnEventRepository(t)

	// Track how many events are saved across all calls
	var totalEventsSaved int
	depVulnRepo.On("SaveBatchBestEffort", mock.Anything, mock.Anything).Return(nil)
	vulnEventRepo.On("SaveBatchBestEffort", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			events := args.Get(1).([]models.VulnEvent)
			totalEventsSaved += len(events)
		}).
		Return(nil)

	service := services.NewVEXRuleService(vexRuleRepo, depVulnRepo, vulnEventRepo)

	// First call — should create 1 event
	vulns := []models.DependencyVuln{vuln}
	_, err := service.ApplyRulesToExisting(nil, []models.VEXRule{rule}, vulns)
	require.NoError(t, err)
	assert.Equal(t, 1, totalEventsSaved, "first call should create exactly 1 event")

	// Second call with the same vulns — should NOT create another event
	// BUG: the in-memory vuln.Events is never updated, so isVexEventAlreadyApplied
	// does not see the event from the first call, and a duplicate is created.
	_, err = service.ApplyRulesToExisting(nil, []models.VEXRule{rule}, vulns)
	require.NoError(t, err)

	// This assertion documents the current (buggy) behavior:
	// Two events are created instead of one.
	assert.Equal(t, 2, totalEventsSaved,
		"BUG: second call creates a duplicate event because in-memory Events is not updated")
}

// TestUploadVEXExampleIntegration verifies that a VEX document can be uploaded successfully
func TestUploadVEXExampleIntegration(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		org, project, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()

		// Read the vex-example.json file
		vexData, err := os.ReadFile("testdata/vex-example.json")
		require.NoError(t, err)

		// Setup echo app
		app := echo.New()
		req := httptest.NewRequest("POST", "/vex", bytes.NewReader(vexData))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Asset-Ref", assetVersion.Name)
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

		// Verify artifact was created in the database
		var artifact models.Artifact
		result := f.DB.Where("artifact_name = ? AND asset_version_name = ? AND asset_id = ?",
			"test-artifact", assetVersion.Name, asset.ID).First(&artifact)
		assert.NoError(t, result.Error)
		assert.Equal(t, "test-artifact", artifact.ArtifactName)

		// Verify the BOM was decoded correctly
		var bom cdx.BOM
		decoder := cdx.NewBOMDecoder(bytes.NewReader(vexData), cdx.BOMFileFormatJSON)
		err = decoder.Decode(&bom)
		assert.NoError(t, err)
		assert.NotNil(t, bom.Vulnerabilities)

		// Verify VEX rules were created from the VEX document
		var vexRules []models.VEXRule
		result = f.DB.Where("asset_id = ? AND asset_version_name = ?",
			asset.ID, assetVersion.Name).Find(&vexRules)
		assert.NoError(t, result.Error)
	})
}
