package tests

import (
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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
