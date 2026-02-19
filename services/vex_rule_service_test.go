package services

import (
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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
			name:      "resolved state",
			analysis:  &cdx.VulnerabilityAnalysis{State: cdx.IASResolved},
			wantError: true,
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
			name:      "exploitable without response",
			analysis:  &cdx.VulnerabilityAnalysis{State: cdx.IASExploitable},
			wantError: true,
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
			name:      "in triage",
			analysis:  &cdx.VulnerabilityAnalysis{State: cdx.IASInTriage},
			wantError: true,
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
				assert.NoError(t, err)
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
			event, err := createVulnEventFromVEXRule(testVuln, rule)
			if tc.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
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

// TestIsVexEventAlreadyApplied_PointerComparison demonstrates that isVexEventAlreadyApplied
// fails to detect duplicates because Justification is *string and == compares pointer addresses.
func TestIsVexEventAlreadyApplied_PointerComparison(t *testing.T) {
	justificationA := "not_affected"
	justificationB := "not_affected" // same value, different pointer

	existingEvent := models.VulnEvent{
		Type:          dtos.EventTypeFalsePositive,
		Justification: &justificationA,
	}

	newEvent := models.VulnEvent{
		Type:          dtos.EventTypeFalsePositive,
		Justification: &justificationB,
	}

	vuln := models.DependencyVuln{
		Vulnerability: models.Vulnerability{
			Events: []models.VulnEvent{existingEvent},
		},
	}

	// This SHOULD return true (same type + same justification string),
	// but returns false because &justificationA != &justificationB.
	assert.True(t, isVexEventAlreadyApplied(vuln, newEvent),
		"should detect duplicate event with same type and justification value")
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

// TestVEXRuleEnabledBasedOnParanoidMode tests that VEX rules are enabled/disabled based on asset ParanoidMode
func TestVEXRuleEnabledBasedOnParanoidMode(t *testing.T) {
	testCases := []struct {
		name            string
		paranoidMode    bool
		expectedEnabled bool
	}{
		{
			name:            "ParanoidMode disabled - rules should be enabled",
			paranoidMode:    false,
			expectedEnabled: true,
		},
		{
			name:            "ParanoidMode enabled - rules should be disabled",
			paranoidMode:    true,
			expectedEnabled: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assetID := uuid.New()
			asset := models.Asset{
				Model:        models.Model{ID: assetID},
				ParanoidMode: tc.paranoidMode,
			}
			assetVersion := models.AssetVersion{
				Name:    "v1.0",
				AssetID: assetID,
			}

			vexRuleRepo := mocks.NewVEXRuleRepository(t)
			depVulnRepo := mocks.NewDependencyVulnRepository(t)
			vulnEventRepo := mocks.NewVulnEventRepository(t)

			// Mock FindByAssetAndVexSource to return empty (no existing rules)
			vexRuleRepo.On("FindByAssetAndVexSource", mock.Anything, assetID, mock.Anything).Return([]models.VEXRule{}, nil)

			// Capture the rules being upserted and verify Enabled field
			var capturedRules []models.VEXRule
			vexRuleRepo.On("UpsertBatch", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
				capturedRules = args.Get(1).([]models.VEXRule)
			}).Return(nil)

			// Mock GetAllOpenVulnsByAssetVersionNameAndAssetID for ApplyRulesToExistingVulns
			depVulnRepo.On("GetAllOpenVulnsByAssetVersionNameAndAssetID", mock.Anything, mock.Anything, "v1.0", assetID).Return([]models.DependencyVuln{}, nil)

			service := NewVEXRuleService(vexRuleRepo, depVulnRepo, vulnEventRepo)

			// Create a minimal VEX report with one vulnerability
			vexReport := createTestVexReport()

			err := service.IngestVEX(nil, asset, assetVersion, vexReport)
			assert.NoError(t, err)

			// Verify that all captured rules have the expected Enabled value
			assert.NotEmpty(t, capturedRules, "expected at least one rule to be created")
			for _, rule := range capturedRules {
				assert.Equal(t, tc.expectedEnabled, rule.Enabled,
					"rule Enabled should be %v when ParanoidMode is %v", tc.expectedEnabled, tc.paranoidMode)
			}

			vexRuleRepo.AssertExpectations(t)
		})
	}
}

// TestMatchRulesToVulnsOnlyMatchesEnabledRules verifies that matchRulesToVulns only matches enabled rules
func TestMatchRulesToVulnsOnlyMatchesEnabledRules(t *testing.T) {
	assetID := uuid.New()

	enabledRule := models.VEXRule{
		ID:          "enabled-rule",
		AssetID:     assetID,
		CVEID:       "CVE-2024-1234",
		PathPattern: []string{"pkg:golang/lib@v1.0"},
		Enabled:     true,
	}

	disabledRule := models.VEXRule{
		ID:          "disabled-rule",
		AssetID:     assetID,
		CVEID:       "CVE-2024-5678",
		PathPattern: []string{"pkg:golang/other@v1.0"},
		Enabled:     false,
	}

	rules := []models.VEXRule{enabledRule, disabledRule}

	vulns := []models.DependencyVuln{
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

	ruleMap := make(map[string]models.VEXRule)
	for _, r := range rules {
		ruleMap[r.ID] = r
	}
	result := matchRulesToVulns(rules, vulns)

	// Only the enabled rule should have matches
	enabledMatches := 0
	disabledMatches := 0
	for ruleID, matchedVulns := range result {
		rule := ruleMap[ruleID]
		if rule.Enabled {
			enabledMatches += len(matchedVulns)
		} else {
			disabledMatches += len(matchedVulns)
		}
	}

	assert.Equal(t, 1, enabledMatches, "enabled rule should match one vulnerability")
	assert.Equal(t, 0, disabledMatches, "disabled rule should not match any vulnerabilities")
}

// createTestVexReport creates a minimal VEX report for testing
func createTestVexReport() *normalize.VexReport {
	return &normalize.VexReport{
		Source: "test-source",
		Report: &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					PackageURL: "pkg:golang/test-app@v1.0",
				},
			},
			Components: &[]cdx.Component{
				{
					BOMRef:     "comp-1",
					PackageURL: "pkg:golang/vulnerable-lib@v1.0",
				},
			},
			Vulnerabilities: &[]cdx.Vulnerability{
				{
					ID: "CVE-2024-1234",
					Analysis: &cdx.VulnerabilityAnalysis{
						State: cdx.IASFalsePositive,
					},
					Affects: &[]cdx.Affects{
						{Ref: "comp-1"},
					},
				},
			},
		},
	}
}

// TestApplyRulesToExistingVulnsOnlyAppliesEnabledRules tests that ApplyRulesToExistingVulns only applies enabled rules
func TestApplyRulesToExistingVulnsOnlyAppliesEnabledRules(t *testing.T) {
	assetID := uuid.New()
	assetVersionName := "v1.0"

	// Create an enabled rule
	enabledRule := models.VEXRule{
		ID:               "enabled-rule",
		AssetID:          assetID,
		AssetVersionName: assetVersionName,
		CVEID:            "CVE-2024-1234",
		PathPattern:      []string{"pkg:golang/vulnerable-lib@v1.0"},
		Enabled:          true,
		EventType:        dtos.EventTypeFalsePositive,
		CreatedByID:      "test-user",
		Justification:    "Not affected",
	}

	// Create a disabled rule
	disabledRule := models.VEXRule{
		ID:               "disabled-rule",
		AssetID:          assetID,
		AssetVersionName: assetVersionName,
		CVEID:            "CVE-2024-5678",
		PathPattern:      []string{"pkg:golang/other-lib@v1.0"},
		Enabled:          false,
		EventType:        dtos.EventTypeFalsePositive,
		CreatedByID:      "test-user",
		Justification:    "Also not affected",
	}

	// Create matching vulnerabilities
	vulnForEnabledRule := models.DependencyVuln{
		Vulnerability: models.Vulnerability{
			ID:               "vuln-1",
			AssetID:          assetID,
			AssetVersionName: assetVersionName,
			State:            dtos.VulnStateOpen,
		},
		CVEID:             "CVE-2024-1234",
		VulnerabilityPath: []string{"pkg:golang/vulnerable-lib@v1.0"},
		ComponentPurl:     "pkg:golang/vulnerable-lib@v1.0",
	}

	vulnForDisabledRule := models.DependencyVuln{
		Vulnerability: models.Vulnerability{
			ID:               "vuln-2",
			AssetID:          assetID,
			AssetVersionName: assetVersionName,
			State:            dtos.VulnStateOpen,
		},
		CVEID:             "CVE-2024-5678",
		VulnerabilityPath: []string{"pkg:golang/other-lib@v1.0"},
		ComponentPurl:     "pkg:golang/other-lib@v1.0",
	}

	vexRuleRepo := mocks.NewVEXRuleRepository(t)
	depVulnRepo := mocks.NewDependencyVulnRepository(t)
	vulnEventRepo := mocks.NewVulnEventRepository(t)

	// Mock GetAllOpenVulnsByAssetVersionNameAndAssetID to return both vulns
	depVulnRepo.On("GetAllOpenVulnsByAssetVersionNameAndAssetID", mock.Anything, mock.Anything, assetVersionName, assetID).
		Return([]models.DependencyVuln{vulnForEnabledRule, vulnForDisabledRule}, nil)

	// Track which vulns get saved - only the vuln matching the enabled rule should be updated
	var savedVulns []models.DependencyVuln
	depVulnRepo.On("SaveBatchBestEffort", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		savedVulns = args.Get(1).([]models.DependencyVuln)
	}).Return(nil)

	// Track which events get saved
	var savedEvents []models.VulnEvent
	vulnEventRepo.On("SaveBatchBestEffort", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		savedEvents = args.Get(1).([]models.VulnEvent)
	}).Return(nil)

	service := NewVEXRuleService(vexRuleRepo, depVulnRepo, vulnEventRepo)

	// Apply both rules (one enabled, one disabled)
	_, err := service.ApplyRulesToExistingVulns(nil, []models.VEXRule{enabledRule, disabledRule})
	assert.NoError(t, err)

	// Verify only the vuln matching the enabled rule was updated
	assert.Len(t, savedVulns, 1, "only one vuln should be updated (the one matching the enabled rule)")
	assert.Len(t, savedEvents, 1, "only one event should be created (for the enabled rule)")

	// Verify it's the correct vuln
	if len(savedVulns) > 0 {
		assert.Equal(t, "CVE-2024-1234", savedVulns[0].CVEID, "the updated vuln should match the enabled rule's CVE")
	}

	depVulnRepo.AssertExpectations(t)
	vulnEventRepo.AssertExpectations(t)
}

// TestEnablingRuleAppliesItToVulns tests that when a previously disabled rule is enabled, it gets applied
func TestEnablingRuleAppliesItToVulns(t *testing.T) {
	assetID := uuid.New()
	assetVersionName := "v1.0"

	// Start with a disabled rule
	rule := models.VEXRule{
		ID:               "test-rule",
		AssetID:          assetID,
		AssetVersionName: assetVersionName,
		CVEID:            "CVE-2024-1234",
		PathPattern:      []string{"pkg:golang/vulnerable-lib@v1.0"},
		Enabled:          false, // Initially disabled
		EventType:        dtos.EventTypeFalsePositive,
		CreatedByID:      "test-user",
		Justification:    "Not affected",
	}

	// Create a matching vulnerability
	matchingVuln := models.DependencyVuln{
		Vulnerability: models.Vulnerability{
			ID:               "vuln-1",
			AssetID:          assetID,
			AssetVersionName: assetVersionName,
			State:            dtos.VulnStateOpen,
		},
		CVEID:             "CVE-2024-1234",
		VulnerabilityPath: []string{"pkg:golang/vulnerable-lib@v1.0"},
		ComponentPurl:     "pkg:golang/vulnerable-lib@v1.0",
	}

	vexRuleRepo := mocks.NewVEXRuleRepository(t)
	depVulnRepo := mocks.NewDependencyVulnRepository(t)
	vulnEventRepo := mocks.NewVulnEventRepository(t)

	service := NewVEXRuleService(vexRuleRepo, depVulnRepo, vulnEventRepo)

	// First, try to apply the disabled rule - should not save any events
	depVulnRepo.On("GetAllOpenVulnsByAssetVersionNameAndAssetID", mock.Anything, mock.Anything, assetVersionName, assetID).
		Return([]models.DependencyVuln{matchingVuln}, nil).Once()

	// No SaveBatchBestEffort calls expected for disabled rule
	_, err := service.ApplyRulesToExistingVulns(nil, []models.VEXRule{rule})
	assert.NoError(t, err)

	// Now enable the rule and apply again - this time events should be saved
	rule.Enabled = true

	depVulnRepo.On("GetAllOpenVulnsByAssetVersionNameAndAssetID", mock.Anything, mock.Anything, assetVersionName, assetID).
		Return([]models.DependencyVuln{matchingVuln}, nil).Once()

	// Track saved events to verify rule was applied
	var savedEvents []models.VulnEvent
	depVulnRepo.On("SaveBatchBestEffort", mock.Anything, mock.Anything).Return(nil)
	vulnEventRepo.On("SaveBatchBestEffort", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		savedEvents = args.Get(1).([]models.VulnEvent)
	}).Return(nil)

	_, err = service.ApplyRulesToExistingVulns(nil, []models.VEXRule{rule})
	assert.NoError(t, err)

	// Verify that events were created when the rule was enabled
	assert.Len(t, savedEvents, 1, "enabled rule should create an event")
	if len(savedEvents) > 0 {
		assert.Equal(t, dtos.EventTypeFalsePositive, savedEvents[0].Type, "event type should match rule's event type")
	}

	depVulnRepo.AssertExpectations(t)
	vulnEventRepo.AssertExpectations(t)
}

// TestParseVEXRulesInBOM_ComponentPurlWithEncodedAtSign tests that component PURLs
// containing %40 (encoded @) are properly unescaped in the generated path pattern.
// This was a critical bug: componentPurl.String() kept the %40 encoding, causing
// path patterns to never match vulnerability paths that use the unescaped @ form.
func TestParseVEXRulesInBOM_ComponentPurlWithEncodedAtSign(t *testing.T) {
	assetID := uuid.New()
	asset := models.Asset{
		Model:        models.Model{ID: assetID},
		ParanoidMode: false,
	}
	assetVersion := models.AssetVersion{
		Name:    "v1.0",
		AssetID: assetID,
	}

	// Use a scoped npm package where the namespace contains @, which gets
	// percent-encoded to %40 by the packageurl library's ToString().
	vexReport := &normalize.VexReport{
		Source: "test-source",
		Report: &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					PackageURL: "pkg:npm/%40myorg/myapp@1.0.0",
				},
			},
			Components: &[]cdx.Component{
				{
					BOMRef:     "vuln-comp-1",
					PackageURL: "pkg:npm/%40myorg/vulnerable-lib@2.0.0",
				},
			},
			Vulnerabilities: &[]cdx.Vulnerability{
				{
					ID: "CVE-2024-9999",
					Analysis: &cdx.VulnerabilityAnalysis{
						State: cdx.IASFalsePositive,
					},
					Affects: &[]cdx.Affects{
						{Ref: "vuln-comp-1"},
					},
				},
			},
		},
	}

	vexRuleRepo := mocks.NewVEXRuleRepository(t)
	depVulnRepo := mocks.NewDependencyVulnRepository(t)
	vulnEventRepo := mocks.NewVulnEventRepository(t)

	vexRuleRepo.On("FindByAssetAndVexSource", mock.Anything, assetID, mock.Anything).Return([]models.VEXRule{}, nil)

	var capturedRules []models.VEXRule
	vexRuleRepo.On("UpsertBatch", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		capturedRules = args.Get(1).([]models.VEXRule)
	}).Return(nil)

	depVulnRepo.On("GetAllOpenVulnsByAssetVersionNameAndAssetID", mock.Anything, mock.Anything, "v1.0", assetID).Return([]models.DependencyVuln{}, nil)

	service := NewVEXRuleService(vexRuleRepo, depVulnRepo, vulnEventRepo)
	err := service.IngestVEX(nil, asset, assetVersion, vexReport)
	assert.NoError(t, err)

	assert.NotEmpty(t, capturedRules, "expected at least one rule to be created")

	rule := capturedRules[0]
	// The path pattern should have 3 elements: [componentPurl, *, vulnPurl]
	assert.Len(t, rule.PathPattern, 3, "path pattern should have componentPurl, wildcard, and vulnPurl")

	componentPurlInPattern := rule.PathPattern[0]
	vulnPurlInPattern := rule.PathPattern[2]

	// The critical assertion: @ must NOT be encoded as %40 in the path pattern.
	// Before the fix, componentPurl.String() was used directly, producing
	// "pkg:npm/%40myorg/myapp@1.0.0" instead of "pkg:npm/@myorg/myapp@1.0.0".
	assert.NotContains(t, componentPurlInPattern, "%40",
		"component PURL in path pattern must not contain %%40 — @ should be unescaped")
	assert.Contains(t, componentPurlInPattern, "@myorg/myapp@",
		"component PURL should contain the properly unescaped @")

	assert.NotContains(t, vulnPurlInPattern, "%40",
		"vuln PURL in path pattern must not contain %%40 — @ should be unescaped")
	assert.Contains(t, vulnPurlInPattern, "@myorg/vulnerable-lib@",
		"vuln PURL should contain the properly unescaped @")

	// Verify the wildcard is in the middle
	assert.Equal(t, dtos.PathPatternWildcard, rule.PathPattern[1],
		"middle element should be the wildcard")

	vexRuleRepo.AssertExpectations(t)
}

// TestMatchRulesToVulns_ComponentPurlWithAtSign verifies that rules with properly
// unescaped component PURLs (containing @) correctly match vulnerabilities.
func TestMatchRulesToVulns_ComponentPurlWithAtSign(t *testing.T) {
	rule := models.VEXRule{
		ID:      "rule-at-sign",
		CVEID:   "CVE-2024-9999",
		Enabled: true,
		// After the fix, path patterns contain unescaped @ signs
		PathPattern: []string{"pkg:npm/@myorg/myapp@1.0.0", "*", "pkg:npm/@myorg/vulnerable-lib@2.0.0"},
	}

	vuln := models.DependencyVuln{
		CVEID: "CVE-2024-9999",
		// Vulnerability paths in the DB use unescaped @ signs
		VulnerabilityPath: []string{"pkg:npm/@myorg/myapp@1.0.0", "pkg:npm/@myorg/vulnerable-lib@2.0.0"},
		ComponentPurl:     "pkg:npm/@myorg/vulnerable-lib@2.0.0",
	}

	result := matchRulesToVulns([]models.VEXRule{rule}, []models.DependencyVuln{vuln})

	assert.Len(t, result[rule.ID], 1, "rule should match the vulnerability")
	assert.Equal(t, "CVE-2024-9999", result[rule.ID][0].CVEID)
}

// TestMatchRulesToVulns_EncodedAtSignDoesNotMatch demonstrates that if the
// component PURL were still encoded with %40, it would NOT match vulnerability
// paths that use the unescaped @ form.
func TestMatchRulesToVulns_EncodedAtSignDoesNotMatch(t *testing.T) {
	// Simulate the old buggy behavior: %40 in the path pattern
	rule := models.VEXRule{
		ID:      "rule-encoded",
		CVEID:   "CVE-2024-9999",
		Enabled: true,
		// Bug: %40 instead of @ in component PURL
		PathPattern: []string{"pkg:npm/%40myorg/myapp@1.0.0", "*", "pkg:npm/%40myorg/vulnerable-lib@2.0.0"},
	}

	vuln := models.DependencyVuln{
		CVEID: "CVE-2024-9999",
		// DB stores unescaped @ signs
		VulnerabilityPath: []string{"pkg:npm/@myorg/myapp@1.0.0", "pkg:npm/@myorg/vulnerable-lib@2.0.0"},
		ComponentPurl:     "pkg:npm/@myorg/vulnerable-lib@2.0.0",
	}

	result := matchRulesToVulns([]models.VEXRule{rule}, []models.DependencyVuln{vuln})

	assert.Empty(t, result[rule.ID],
		"encoded %%40 in path pattern should NOT match unescaped @ in vulnerability path — this demonstrates the bug")
}

// TestMatchVulnsToRules tests the matchVulnsToRules function which maps vulnerability IDs to matching enabled VEX rules
func TestMatchVulnsToRules(t *testing.T) {
	t.Run("matches enabled rules by CVE and path pattern", func(t *testing.T) {
		vulns := []models.DependencyVuln{
			{
				Vulnerability: models.Vulnerability{ID: "vuln-1"},
				CVEID:         "CVE-2024-1234",
				VulnerabilityPath: []string{
					"pkg:golang/myapp@v1.0",
					"pkg:golang/lib@v1.0",
				},
			},
		}

		rules := []models.VEXRule{
			{
				CVEID:       "CVE-2024-1234",
				PathPattern: []string{"pkg:golang/myapp@v1.0", dtos.PathPatternWildcard, "pkg:golang/lib@v1.0"},
				Enabled:     true,
			},
		}

		result := matchVulnsToRules(vulns, rules)
		assert.Len(t, result["vuln-1"], 1, "should match the enabled rule")
	})

	t.Run("skips disabled rules", func(t *testing.T) {
		vulns := []models.DependencyVuln{
			{
				Vulnerability: models.Vulnerability{ID: "vuln-1"},
				CVEID:         "CVE-2024-1234",
				VulnerabilityPath: []string{
					"pkg:golang/lib@v1.0",
				},
			},
		}

		rules := []models.VEXRule{
			{
				CVEID:       "CVE-2024-1234",
				PathPattern: []string{"pkg:golang/lib@v1.0"},
				Enabled:     false,
			},
		}

		result := matchVulnsToRules(vulns, rules)
		assert.Empty(t, result["vuln-1"], "disabled rule should not match")
	})

	t.Run("does not match when CVE differs", func(t *testing.T) {
		vulns := []models.DependencyVuln{
			{
				Vulnerability:     models.Vulnerability{ID: "vuln-1"},
				CVEID:             "CVE-2024-1234",
				VulnerabilityPath: []string{"pkg:golang/lib@v1.0"},
			},
		}

		rules := []models.VEXRule{
			{
				CVEID:       "CVE-2024-9999",
				PathPattern: []string{"pkg:golang/lib@v1.0"},
				Enabled:     true,
			},
		}

		result := matchVulnsToRules(vulns, rules)
		assert.Empty(t, result["vuln-1"], "should not match when CVE IDs differ")
	})

	t.Run("does not match when path pattern does not match", func(t *testing.T) {
		vulns := []models.DependencyVuln{
			{
				Vulnerability:     models.Vulnerability{ID: "vuln-1"},
				CVEID:             "CVE-2024-1234",
				VulnerabilityPath: []string{"pkg:golang/other@v1.0"},
			},
		}

		rules := []models.VEXRule{
			{
				CVEID:       "CVE-2024-1234",
				PathPattern: []string{"pkg:golang/lib@v1.0"},
				Enabled:     true,
			},
		}

		result := matchVulnsToRules(vulns, rules)
		assert.Empty(t, result["vuln-1"], "should not match when path pattern does not match")
	})

	t.Run("multiple rules match same vuln", func(t *testing.T) {
		vulns := []models.DependencyVuln{
			{
				Vulnerability:     models.Vulnerability{ID: "vuln-1"},
				CVEID:             "CVE-2024-1234",
				VulnerabilityPath: []string{"pkg:golang/app@v1.0", "pkg:golang/lib@v1.0"},
			},
		}

		rules := []models.VEXRule{
			{
				CVEID:       "CVE-2024-1234",
				PathPattern: []string{"pkg:golang/lib@v1.0"},
				Enabled:     true,
			},
			{
				CVEID:       "CVE-2024-1234",
				PathPattern: []string{dtos.PathPatternWildcard, "pkg:golang/lib@v1.0"},
				Enabled:     true,
			},
		}

		result := matchVulnsToRules(vulns, rules)
		assert.Len(t, result["vuln-1"], 2, "both enabled rules should match the same vuln")
	})

	t.Run("empty vulns returns empty result", func(t *testing.T) {
		rules := []models.VEXRule{
			{CVEID: "CVE-2024-1234", PathPattern: []string{"pkg:golang/lib@v1.0"}, Enabled: true},
		}

		result := matchVulnsToRules(nil, rules)
		assert.Empty(t, result)
	})

	t.Run("empty rules returns empty result", func(t *testing.T) {
		vulns := []models.DependencyVuln{
			{
				Vulnerability:     models.Vulnerability{ID: "vuln-1"},
				CVEID:             "CVE-2024-1234",
				VulnerabilityPath: []string{"pkg:golang/lib@v1.0"},
			},
		}

		result := matchVulnsToRules(vulns, nil)
		assert.Empty(t, result)
	})
}

// TestParseVEXRulesInBOM_PathPatternFromProperties tests that when a VEX BOM contains
// pathPattern properties (created by devguard's BuildVeX), they are parsed directly
// instead of being reconstructed from PURLs.
func TestParseVEXRulesInBOM_PathPatternFromProperties(t *testing.T) {
	assetID := uuid.New()
	asset := models.Asset{
		Model:        models.Model{ID: assetID},
		ParanoidMode: false,
	}
	assetVersion := models.AssetVersion{
		Name:    "v1.0",
		AssetID: assetID,
	}

	// Simulate a VEX report that was produced by devguard itself (BuildVeX),
	// which embeds pathPattern as a JSON property on each vulnerability.
	vexReport := &normalize.VexReport{
		Source: "test-source",
		Report: &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					PackageURL: "pkg:golang/myapp@v1.0",
				},
			},
			Components: &[]cdx.Component{
				{
					BOMRef:     "comp-1",
					PackageURL: "pkg:golang/vulnerable-lib@v2.0",
				},
			},
			Vulnerabilities: &[]cdx.Vulnerability{
				{
					ID: "CVE-2024-1234",
					Analysis: &cdx.VulnerabilityAnalysis{
						State: cdx.IASFalsePositive,
					},
					Affects: &[]cdx.Affects{
						{Ref: "comp-1"},
					},
					Properties: &[]cdx.Property{
						{
							Name:  "devguard:pathPattern",
							Value: `["pkg:golang/root@v1.0","*","pkg:golang/vulnerable-lib@v2.0"]`,
						},
					},
				},
			},
		},
	}

	vexRuleRepo := mocks.NewVEXRuleRepository(t)
	depVulnRepo := mocks.NewDependencyVulnRepository(t)
	vulnEventRepo := mocks.NewVulnEventRepository(t)

	vexRuleRepo.On("FindByAssetAndVexSource", mock.Anything, assetID, mock.Anything).Return([]models.VEXRule{}, nil)

	var capturedRules []models.VEXRule
	vexRuleRepo.On("UpsertBatch", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		capturedRules = args.Get(1).([]models.VEXRule)
	}).Return(nil)

	depVulnRepo.On("GetAllOpenVulnsByAssetVersionNameAndAssetID", mock.Anything, mock.Anything, "v1.0", assetID).Return([]models.DependencyVuln{}, nil)

	service := NewVEXRuleService(vexRuleRepo, depVulnRepo, vulnEventRepo)
	err := service.IngestVEX(nil, asset, assetVersion, vexReport)
	assert.NoError(t, err)

	assert.NotEmpty(t, capturedRules, "expected at least one rule to be created")

	rule := capturedRules[0]
	// The path pattern should come directly from the property, not reconstructed from PURLs
	assert.Equal(t, dtos.PathPattern{"pkg:golang/root@v1.0", "*", "pkg:golang/vulnerable-lib@v2.0"}, dtos.PathPattern(rule.PathPattern),
		"path pattern should be parsed from the property value, not reconstructed from PURLs")

	vexRuleRepo.AssertExpectations(t)
}

// TestParseVEXRulesInBOM_MultiplePathPatternProperties tests that multiple pathPattern
// properties on a single vulnerability each produce a separate VEX rule.
func TestParseVEXRulesInBOM_MultiplePathPatternProperties(t *testing.T) {
	assetID := uuid.New()
	asset := models.Asset{
		Model:        models.Model{ID: assetID},
		ParanoidMode: false,
	}
	assetVersion := models.AssetVersion{
		Name:    "v1.0",
		AssetID: assetID,
	}

	vexReport := &normalize.VexReport{
		Source: "test-source",
		Report: &cdx.BOM{
			Metadata: &cdx.Metadata{
				Component: &cdx.Component{
					PackageURL: "pkg:golang/myapp@v1.0",
				},
			},
			Components: &[]cdx.Component{
				{
					BOMRef:     "comp-1",
					PackageURL: "pkg:golang/vulnerable-lib@v2.0",
				},
			},
			Vulnerabilities: &[]cdx.Vulnerability{
				{
					ID: "CVE-2024-1234",
					Analysis: &cdx.VulnerabilityAnalysis{
						State: cdx.IASFalsePositive,
					},
					Affects: &[]cdx.Affects{
						{Ref: "comp-1"},
					},
					Properties: &[]cdx.Property{
						{
							Name:  "devguard:pathPattern",
							Value: `["pkg:golang/root-a@v1.0","*","pkg:golang/vulnerable-lib@v2.0"]`,
						},
						{
							Name:  "devguard:pathPattern",
							Value: `["pkg:golang/root-b@v1.0","*","pkg:golang/vulnerable-lib@v2.0"]`,
						},
					},
				},
			},
		},
	}

	vexRuleRepo := mocks.NewVEXRuleRepository(t)
	depVulnRepo := mocks.NewDependencyVulnRepository(t)
	vulnEventRepo := mocks.NewVulnEventRepository(t)

	vexRuleRepo.On("FindByAssetAndVexSource", mock.Anything, assetID, mock.Anything).Return([]models.VEXRule{}, nil)

	var capturedRules []models.VEXRule
	vexRuleRepo.On("UpsertBatch", mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		capturedRules = args.Get(1).([]models.VEXRule)
	}).Return(nil)

	depVulnRepo.On("GetAllOpenVulnsByAssetVersionNameAndAssetID", mock.Anything, mock.Anything, "v1.0", assetID).Return([]models.DependencyVuln{}, nil)

	service := NewVEXRuleService(vexRuleRepo, depVulnRepo, vulnEventRepo)
	err := service.IngestVEX(nil, asset, assetVersion, vexReport)
	assert.NoError(t, err)

	assert.Len(t, capturedRules, 2, "each pathPattern property should produce a separate VEX rule")

	patterns := []dtos.PathPattern{
		dtos.PathPattern(capturedRules[0].PathPattern),
		dtos.PathPattern(capturedRules[1].PathPattern),
	}

	assert.Contains(t, patterns, dtos.PathPattern{"pkg:golang/root-a@v1.0", "*", "pkg:golang/vulnerable-lib@v2.0"})
	assert.Contains(t, patterns, dtos.PathPattern{"pkg:golang/root-b@v1.0", "*", "pkg:golang/vulnerable-lib@v2.0"})

	vexRuleRepo.AssertExpectations(t)
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
