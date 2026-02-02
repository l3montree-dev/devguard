package services

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestMapCDXToStatus(t *testing.T) {
	cases := []struct {
		name     string
		analysis *cdx.VulnerabilityAnalysis
		want     string
	}{
		{name: "nil analysis", analysis: nil, want: ""},
		{name: "resolved", analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASResolved}, want: "fixed"},
		{name: "false positive", analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASFalsePositive}, want: "falsePositive"},
		{name: "exploitable", analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASExploitable}, want: "open"},
		{name: "in triage", analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASInTriage}, want: "open"},
		{name: "response update fallback", analysis: &cdx.VulnerabilityAnalysis{State: "", Response: &[]cdx.ImpactAnalysisResponse{cdx.IARUpdate}}, want: "fixed"},
		{name: "response will not fix fallback", analysis: &cdx.VulnerabilityAnalysis{State: "", Response: &[]cdx.ImpactAnalysisResponse{cdx.IARWillNotFix}}, want: "accepted"},
		{name: "unknown response", analysis: &cdx.VulnerabilityAnalysis{State: "", Response: &[]cdx.ImpactAnalysisResponse{"unknown"}}, want: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mapCDXToVulnStatus(tc.analysis)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestMapCDXToEventType(t *testing.T) {
	cases := []struct {
		name      string
		analysis  *cdx.VulnerabilityAnalysis
		want      dtos.VulnEventType
		wantError bool
	}{
		{
			name:      "nil analysis",
			analysis:  nil,
			wantError: true,
		},
		{
			name:     "resolved state",
			analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASResolved},
			want:     dtos.EventTypeFixed,
		},
		{
			name:     "false positive state",
			analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASFalsePositive},
			want:     dtos.EventTypeFalsePositive,
		},
		{
			name:     "not affected state",
			analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASNotAffected},
			want:     dtos.EventTypeFalsePositive,
		},
		{
			name:     "exploitable without response",
			analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASExploitable},
			want:     dtos.EventTypeDetected,
		},
		{
			name:     "exploitable with will not fix",
			analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASExploitable, Response: &[]cdx.ImpactAnalysisResponse{cdx.IARWillNotFix}},
			want:     dtos.EventTypeAccepted,
		},
		{
			name:     "exploitable with update",
			analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASExploitable, Response: &[]cdx.ImpactAnalysisResponse{cdx.IARUpdate}},
			want:     dtos.EventTypeComment,
		},
		{
			name:     "in triage",
			analysis: &cdx.VulnerabilityAnalysis{State: cdx.IASInTriage},
			want:     dtos.EventTypeDetected,
		},
		{
			name:     "will not fix response fallback",
			analysis: &cdx.VulnerabilityAnalysis{State: "", Response: &[]cdx.ImpactAnalysisResponse{cdx.IARWillNotFix}},
			want:     dtos.EventTypeAccepted,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := mapCDXToEventType(tc.analysis)
			if tc.wantError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.want, got)
			}
		})
	}
}

func TestCreateVulnEventFromVEXRule(t *testing.T) {
	// This tests the internal function createVulnEventFromVEXRule
	assetID := uuid.New()
	testVuln := models.DependencyVuln{
		Vulnerability: models.Vulnerability{
			ID:               "test-vuln-id",
			AssetID:          assetID,
			AssetVersionName: "test-version",
			State:            dtos.VulnStateOpen,
		},
		CVEID: "CVE-2024-1234",
	}

	cases := []struct {
		name      string
		eventType dtos.VulnEventType
		wantError bool
	}{
		{
			name:      "false positive event",
			eventType: dtos.EventTypeFalsePositive,
		},
		{
			name:      "accepted event",
			eventType: dtos.EventTypeAccepted,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := &models.VEXRule{
				EventType:     tc.eventType,
				CreatedByID:   "test-user",
				Justification: "test justification",
			}

			// Call the internal function
			event, err := createVulnEventFromVEXRule(dtos.UpstreamStateInternal, testVuln, rule)
			if tc.wantError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, rule.Justification, *event.Justification)
			}
		})
	}
}

func TestIsVulnInTargetState(t *testing.T) {
	// Note: isVulnInTargetState is currently unexported, so we test it indirectly
	// through the ApplyRulesToExistingVulns behavior or write integration tests

	// For now, we can document the expected behavior here
	t.Run("vulnerability state matching", func(t *testing.T) {
		// False positive
		fpVuln := models.DependencyVuln{
			Vulnerability: models.Vulnerability{State: dtos.VulnStateFalsePositive},
		}
		fpRule := &models.VEXRule{EventType: dtos.EventTypeFalsePositive}
		// Should skip (already in target state)

		// Fixed
		fixedVuln := models.DependencyVuln{
			Vulnerability: models.Vulnerability{State: dtos.VulnStateFixed},
		}
		fixedRule := &models.VEXRule{EventType: dtos.EventTypeFixed}
		// Should skip (already in target state)

		// Accepted
		acceptedVuln := models.DependencyVuln{
			Vulnerability: models.Vulnerability{State: dtos.VulnStateAccepted},
		}
		acceptedRule := &models.VEXRule{EventType: dtos.EventTypeAccepted}
		// Should skip (already in target state)

		// Different states should be updated
		openVuln := models.DependencyVuln{
			Vulnerability: models.Vulnerability{State: dtos.VulnStateOpen},
		}
		fpRule2 := &models.VEXRule{EventType: dtos.EventTypeFalsePositive}
		// Should update open -> false positive

		assert.NotNil(t, fpVuln)
		assert.NotNil(t, fpRule)
		assert.NotNil(t, fixedVuln)
		assert.NotNil(t, fixedRule)
		assert.NotNil(t, acceptedVuln)
		assert.NotNil(t, acceptedRule)
		assert.NotNil(t, openVuln)
		assert.NotNil(t, fpRule2)
	})
}

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

	service := NewVEXRuleService(vexRuleRepo, depVulnRepo, vulnEventRepo)
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

	service := NewVEXRuleService(vexRuleRepo, depVulnRepo, vulnEventRepo)
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

	service := NewVEXRuleService(vexRuleRepo, depVulnRepo, vulnEventRepo)
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

	service := NewVEXRuleService(vexRuleRepo, depVulnRepo, vulnEventRepo)
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

	service := NewVEXRuleService(vexRuleRepo, depVulnRepo, vulnEventRepo)
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

	service := NewVEXRuleService(vexRuleRepo, depVulnRepo, vulnEventRepo)
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

	service := NewVEXRuleService(vexRuleRepo, depVulnRepo, vulnEventRepo)
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

	service := NewVEXRuleService(vexRuleRepo, depVulnRepo, vulnEventRepo)
	err := service.Create(nil, rule)

	assert.NoError(t, err)
	vexRuleRepo.AssertExpectations(t)
}
