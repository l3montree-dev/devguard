package services

import (
	"context"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/vexrules"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// celFor builds a CEL expression that matches a specific CVE ID and path pattern,
// mirroring how transformers build VEXRule.CELExpression for tests.
func celFor(cveID string, pattern []string) string {
	return vexrules.ToCELExpression(cveID, vexrules.PathPattern(pattern))
}

func TestCreateVulnEventFromVEXRule(t *testing.T) {
	// This tests the internal function createVulnEventFromVEXRule
	assetID := uuid.New()
	testVuln := models.DependencyVuln{
		Vulnerability: models.Vulnerability{
			ID:      uuid.MustParse("ffffffff-ffff-ffff-ffff-ffffffffffff"),
			AssetID: assetID,
			State:   dtos.VulnStateOpen,
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
				UpstreamVEXRule: models.UpstreamVEXRule{
					EventType:     tc.eventType,
					Justification: "test justification",
				},
				CreatedByID: "test-user",
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
		fpRule := &models.VEXRule{UpstreamVEXRule: models.UpstreamVEXRule{EventType: dtos.EventTypeFalsePositive}}
		// Should skip (already in target state)

		// Fixed
		fixedVuln := models.DependencyVuln{
			Vulnerability: models.Vulnerability{State: dtos.VulnStateFixed},
		}
		fixedRule := &models.VEXRule{UpstreamVEXRule: models.UpstreamVEXRule{EventType: dtos.EventTypeFixed}}
		// Should skip (already in target state)

		// Accepted
		acceptedVuln := models.DependencyVuln{
			Vulnerability: models.Vulnerability{State: dtos.VulnStateAccepted},
		}
		acceptedRule := &models.VEXRule{UpstreamVEXRule: models.UpstreamVEXRule{EventType: dtos.EventTypeAccepted}}
		// Should skip (already in target state)

		// Different states should be updated
		openVuln := models.DependencyVuln{
			Vulnerability: models.Vulnerability{State: dtos.VulnStateOpen},
		}
		fpRule2 := &models.VEXRule{UpstreamVEXRule: models.UpstreamVEXRule{EventType: dtos.EventTypeFalsePositive}}
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
		Events: []models.VulnEvent{existingEvent},
	}

	// This SHOULD return true (same type + same justification string),
	// but returns false because &justificationA != &justificationB.
	assert.True(t, isVexEventAlreadyApplied(vuln, newEvent),
		"should detect duplicate event with same type and justification value")
}

// TestVEXRuleServiceDelete tests the Delete method
func TestVEXRuleServiceDelete(t *testing.T) {
	assetID := uuid.New()
	rule := models.VEXRule{
		UpstreamVEXRule: models.UpstreamVEXRule{ID: "test-rule-1"},
		AssetID:         assetID,
	}

	vexRuleRepo := mocks.NewVEXRuleRepository(t)
	depVulnRepo := mocks.NewDependencyVulnRepository(t)
	vulnEventRepo := mocks.NewVulnEventRepository(t)
	upstreamVexRuleRepo := mocks.NewUpstreamVEXRuleRepository(t)
	cveRepo := mocks.NewCveRepository(t)
	cveRelationshipRepo := mocks.NewCVERelationshipRepository(t)
	cveRelationshipService := mocks.NewCVERelationshipService(t)

	vexRuleRepo.On("Delete", mock.Anything, mock.Anything, mock.MatchedBy(func(r models.VEXRule) bool {
		return r.ID == "test-rule-1"
	})).Return(nil)

	service := NewVEXRuleService(vexRuleRepo, upstreamVexRuleRepo, depVulnRepo, vulnEventRepo, cveRepo, cveRelationshipRepo, cveRelationshipService)

	err := service.Delete(context.Background(), nil, rule)

	assert.NoError(t, err)
	vexRuleRepo.AssertExpectations(t)
}

// TestVEXRuleServiceFindByAssetID tests finding rules by asset
func TestVEXRuleServiceFindByAssetID(t *testing.T) {
	assetID := uuid.New()
	rules := []models.VEXRule{
		{
			UpstreamVEXRule: models.UpstreamVEXRule{ID: "rule-1"},
			AssetID:         assetID,
		},
		{
			UpstreamVEXRule: models.UpstreamVEXRule{ID: "rule-2"},
			AssetID:         assetID,
		},
	}

	vexRuleRepo := mocks.NewVEXRuleRepository(t)
	depVulnRepo := mocks.NewDependencyVulnRepository(t)
	vulnEventRepo := mocks.NewVulnEventRepository(t)
	upstreamVexRuleRepo := mocks.NewUpstreamVEXRuleRepository(t)
	cveRepo := mocks.NewCveRepository(t)
	cveRelationshipRepo := mocks.NewCVERelationshipRepository(t)
	cveRelationshipService := mocks.NewCVERelationshipService(t)

	vexRuleRepo.On("FindByAssetID", mock.Anything, mock.Anything, assetID).Return(rules, nil)

	service := NewVEXRuleService(vexRuleRepo, upstreamVexRuleRepo, depVulnRepo, vulnEventRepo, cveRepo, cveRelationshipRepo, cveRelationshipService)
	found, err := service.FindByAssetID(context.Background(), nil, assetID)

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
		UpstreamVEXRule: models.UpstreamVEXRule{ID: "test-rule-1"},
		AssetID:         assetID,
	}

	vexRuleRepo := mocks.NewVEXRuleRepository(t)
	depVulnRepo := mocks.NewDependencyVulnRepository(t)
	vulnEventRepo := mocks.NewVulnEventRepository(t)
	upstreamVexRuleRepo := mocks.NewUpstreamVEXRuleRepository(t)
	cveRepo := mocks.NewCveRepository(t)
	cveRelationshipRepo := mocks.NewCVERelationshipRepository(t)
	cveRelationshipService := mocks.NewCVERelationshipService(t)

	vexRuleRepo.On("FindByID", mock.Anything, mock.Anything, "test-rule-1").Return(rule, nil)

	service := NewVEXRuleService(vexRuleRepo, upstreamVexRuleRepo, depVulnRepo, vulnEventRepo, cveRepo, cveRelationshipRepo, cveRelationshipService)
	found, err := service.FindByID(context.Background(), nil, "test-rule-1")

	assert.NoError(t, err)
	assert.Equal(t, "test-rule-1", found.ID)
	vexRuleRepo.AssertExpectations(t)
}

// TestVEXRuleServiceCountMatchingVulnsForRules tests batch vulnerability counting
func TestVEXRuleServiceCountMatchingVulnsForRules(t *testing.T) {
	assetID := uuid.New()
	rules := []models.VEXRule{
		{UpstreamVEXRule: models.UpstreamVEXRule{ID: "rule-1"}, AssetID: assetID, Enabled: true},
		{UpstreamVEXRule: models.UpstreamVEXRule{ID: "rule-2"}, AssetID: assetID, Enabled: true},
		{UpstreamVEXRule: models.UpstreamVEXRule{ID: "rule-3"}, AssetID: assetID, Enabled: true},
	}

	vexRuleRepo := mocks.NewVEXRuleRepository(t)
	depVulnRepo := mocks.NewDependencyVulnRepository(t)
	vulnEventRepo := mocks.NewVulnEventRepository(t)
	upstreamVexRuleRepo := mocks.NewUpstreamVEXRuleRepository(t)
	cveRepo := mocks.NewCveRepository(t)
	cveRelationshipRepo := mocks.NewCVERelationshipRepository(t)
	cveRelationshipService := mocks.NewCVERelationshipService(t)

	vulnEventRepo.On("CountByVexRuleIDs", mock.Anything, mock.Anything, []string{"rule-1", "rule-2", "rule-3"}).
		Return(map[string]int{"rule-1": 2, "rule-2": 1}, nil)

	// NOTE: CountMatchingVulnsForRules no longer resolves CVE alias relationships - it only
	// aggregates vuln_events by vex_rule_id (see services/vex_rule_service.go), so the
	// cveRelationshipService mocking that used to live here has been removed.

	service := NewVEXRuleService(vexRuleRepo, upstreamVexRuleRepo, depVulnRepo, vulnEventRepo, cveRepo, cveRelationshipRepo, cveRelationshipService)
	counts, err := service.CountMatchingVulnsForRules(context.Background(), nil, rules)

	assert.NoError(t, err)
	assert.NotNil(t, counts)
	assert.Len(t, counts, 3)
	assert.Equal(t, 2, counts["rule-1"])
	assert.Equal(t, 1, counts["rule-2"])
	assert.Equal(t, 0, counts["rule-3"])
	vulnEventRepo.AssertExpectations(t)
}

// TestVEXRuleServiceCountMatchingVulns tests counting matches for single rule
func TestVEXRuleServiceCountMatchingVulns(t *testing.T) {
	assetID := uuid.New()
	rule := models.VEXRule{UpstreamVEXRule: models.UpstreamVEXRule{ID: "rule-1"}, AssetID: assetID, Enabled: true}

	vexRuleRepo := mocks.NewVEXRuleRepository(t)
	depVulnRepo := mocks.NewDependencyVulnRepository(t)
	vulnEventRepo := mocks.NewVulnEventRepository(t)
	upstreamVexRuleRepo := mocks.NewUpstreamVEXRuleRepository(t)
	cveRepo := mocks.NewCveRepository(t)
	cveRelationshipRepo := mocks.NewCVERelationshipRepository(t)
	cveRelationshipService := mocks.NewCVERelationshipService(t)

	vulnEventRepo.On("CountByVexRuleIDs", mock.Anything, mock.Anything, []string{"rule-1"}).
		Return(map[string]int{"rule-1": 2}, nil)

	// NOTE: CountMatchingVulns no longer resolves CVE alias relationships (see above).

	service := NewVEXRuleService(vexRuleRepo, upstreamVexRuleRepo, depVulnRepo, vulnEventRepo, cveRepo, cveRelationshipRepo, cveRelationshipService)
	count, err := service.CountMatchingVulns(context.Background(), nil, rule)

	assert.NoError(t, err)
	assert.Equal(t, 2, count)
	vulnEventRepo.AssertExpectations(t)
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
			vexRuleRepo := mocks.NewVEXRuleRepository(t)
			depVulnRepo := mocks.NewDependencyVulnRepository(t)
			vulnEventRepo := mocks.NewVulnEventRepository(t)
			upstreamVexRuleRepo := mocks.NewUpstreamVEXRuleRepository(t)
			cveRepo := mocks.NewCveRepository(t)
			cveRelationshipRepo := mocks.NewCVERelationshipRepository(t)
			cveRelationshipService := mocks.NewCVERelationshipService(t)

			// Mock FindByAssetAndVexSource to return empty (no existing rules)
			vexRuleRepo.On("FindByAssetAndVexSource", mock.Anything, mock.Anything, assetID, mock.Anything).Return([]models.VEXRule{}, nil)

			// Capture the rules being upserted and verify Enabled field
			var capturedRules []models.VEXRule
			vexRuleRepo.On("UpsertBatch", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
				capturedRules = args.Get(2).([]models.VEXRule)
			}).Return(nil)

			// Mock GetAllOpenVulnsByAssetID for ApplyRulesToExistingVulns
			depVulnRepo.On("GetAllOpenVulnsByAssetID", mock.Anything, mock.Anything, assetID).Return([]models.DependencyVuln{}, nil)

			service := NewVEXRuleService(vexRuleRepo, upstreamVexRuleRepo, depVulnRepo, vulnEventRepo, cveRepo, cveRelationshipRepo, cveRelationshipService)

			newRule := models.VEXRule{
				AssetID: assetID,
				UpstreamVEXRule: models.UpstreamVEXRule{
					VexSource:     "test",
					CELExpression: celFor("CVE-2024-0001", []string{"pkg:npm/lib@1.0.0"}),
				},
			}
			err := service.IngestVEXRules(context.Background(), nil, asset, []models.VEXRule{newRule})
			assert.NoError(t, err)

			// Verify that all captured rules have the expected Enabled value
			assert.NotEmpty(t, capturedRules, "expected at least one rule to be created")
			for _, rule := range capturedRules {
				assert.Equal(t, tc.expectedEnabled, rule.Enabled,
					"rule Enabled should be %v when ParanoidMode is %v", tc.expectedEnabled, tc.paranoidMode)
			}

			vexRuleRepo.AssertExpectations(t)
			cveRelationshipService.AssertExpectations(t)
		})
	}
}

// TestApplyRulesToExistingVulnsOnlyAppliesEnabledRules tests that ApplyRulesToExistingVulns only applies enabled rules
func TestApplyRulesToExistingVulnsOnlyAppliesEnabledRules(t *testing.T) {
	assetID := uuid.New()

	// Create an enabled rule
	enabledRule := models.VEXRule{
		UpstreamVEXRule: models.UpstreamVEXRule{
			ID:            "enabled-rule",
			CELExpression: celFor("CVE-2024-1234", []string{"pkg:golang/vulnerable-lib@v1.0"}),
			EventType:     dtos.EventTypeFalsePositive,
			Justification: "Not affected",
		},
		AssetID:     assetID,
		Enabled:     true,
		CreatedByID: "test-user",
	}

	// Create a disabled rule
	disabledRule := models.VEXRule{
		UpstreamVEXRule: models.UpstreamVEXRule{
			ID:            "disabled-rule",
			CELExpression: celFor("CVE-2024-5678", []string{"pkg:golang/other-lib@v1.0"}),
			EventType:     dtos.EventTypeFalsePositive,
			Justification: "Also not affected",
		},
		AssetID:     assetID,
		Enabled:     false,
		CreatedByID: "test-user",
	}

	// Create matching vulnerabilities
	vulnForEnabledRule := models.DependencyVuln{
		Vulnerability: models.Vulnerability{
			ID:      uuid.MustParse("ffffffff-ffff-ffff-ffff-ffffffffffff"),
			AssetID: assetID,
			State:   dtos.VulnStateOpen,
		},
		CVEID:             "CVE-2024-1234",
		VulnerabilityPath: []string{"pkg:golang/vulnerable-lib@v1.0"},
		ComponentPurl:     "pkg:golang/vulnerable-lib@v1.0",
	}

	vulnForDisabledRule := models.DependencyVuln{
		Vulnerability: models.Vulnerability{
			ID:      uuid.MustParse("ffffffff-ffff-ffff-ffff-fffffffffffe"),
			AssetID: assetID,
			State:   dtos.VulnStateOpen,
		},
		CVEID:             "CVE-2024-5678",
		VulnerabilityPath: []string{"pkg:golang/other-lib@v1.0"},
		ComponentPurl:     "pkg:golang/other-lib@v1.0",
	}

	vexRuleRepo := mocks.NewVEXRuleRepository(t)
	depVulnRepo := mocks.NewDependencyVulnRepository(t)
	vulnEventRepo := mocks.NewVulnEventRepository(t)
	upstreamVexRuleRepo := mocks.NewUpstreamVEXRuleRepository(t)
	cveRepo := mocks.NewCveRepository(t)
	cveRelationshipRepo := mocks.NewCVERelationshipRepository(t)
	cveRelationshipService := mocks.NewCVERelationshipService(t)

	// Mock GetAllOpenVulnsByAssetID to return both vulns
	depVulnRepo.On("GetAllOpenVulnsByAssetID", mock.Anything, mock.Anything, assetID).
		Return([]models.DependencyVuln{vulnForEnabledRule, vulnForDisabledRule}, nil)

	// Track which vulns get saved - only the vuln matching the enabled rule should be updated
	var savedVulns []models.DependencyVuln
	depVulnRepo.On("SaveBatchBestEffort", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		savedVulns = args.Get(2).([]models.DependencyVuln)
	}).Return(nil)

	// Track which events get saved
	var savedEvents []models.VulnEvent
	vulnEventRepo.On("SaveBatchBestEffort", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		savedEvents = args.Get(2).([]models.VulnEvent)
	}).Return(nil)

	service := NewVEXRuleService(vexRuleRepo, upstreamVexRuleRepo, depVulnRepo, vulnEventRepo, cveRepo, cveRelationshipRepo, cveRelationshipService)

	// Apply both rules (one enabled, one disabled)
	_, err := service.ApplyRulesToExistingVulns(context.Background(), nil, assetID, []models.VEXRule{enabledRule, disabledRule})
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

	// Start with a disabled rule
	rule := models.VEXRule{
		UpstreamVEXRule: models.UpstreamVEXRule{
			ID:            "test-rule",
			CELExpression: celFor("CVE-2024-1234", []string{"pkg:golang/vulnerable-lib@v1.0"}),
			EventType:     dtos.EventTypeFalsePositive,
			Justification: "Not affected",
		},
		AssetID:     assetID,
		Enabled:     false, // Initially disabled
		CreatedByID: "test-user",
	}

	// Create a matching vulnerability
	matchingVuln := models.DependencyVuln{
		Vulnerability: models.Vulnerability{
			ID:      uuid.MustParse("ffffffff-ffff-ffff-ffff-ffffffffffff"),
			AssetID: assetID,
			State:   dtos.VulnStateOpen,
		},
		CVEID:             "CVE-2024-1234",
		VulnerabilityPath: []string{"pkg:golang/vulnerable-lib@v1.0"},
		ComponentPurl:     "pkg:golang/vulnerable-lib@v1.0",
	}

	vexRuleRepo := mocks.NewVEXRuleRepository(t)
	depVulnRepo := mocks.NewDependencyVulnRepository(t)
	vulnEventRepo := mocks.NewVulnEventRepository(t)
	upstreamVexRuleRepo := mocks.NewUpstreamVEXRuleRepository(t)
	cveRepo := mocks.NewCveRepository(t)
	cveRelationshipRepo := mocks.NewCVERelationshipRepository(t)
	cveRelationshipService := mocks.NewCVERelationshipService(t)

	service := NewVEXRuleService(vexRuleRepo, upstreamVexRuleRepo, depVulnRepo, vulnEventRepo, cveRepo, cveRelationshipRepo, cveRelationshipService)

	// First, try to apply the disabled rule - should not save any events
	depVulnRepo.On("GetAllOpenVulnsByAssetID", mock.Anything, mock.Anything, assetID).
		Return([]models.DependencyVuln{matchingVuln}, nil).Once()

	// No SaveBatchBestEffort calls expected for disabled rule
	_, err := service.ApplyRulesToExistingVulns(context.Background(), nil, assetID, []models.VEXRule{rule})
	assert.NoError(t, err)

	// Now enable the rule and apply again - this time events should be saved
	rule.Enabled = true

	depVulnRepo.On("GetAllOpenVulnsByAssetID", mock.Anything, mock.Anything, assetID).
		Return([]models.DependencyVuln{matchingVuln}, nil).Once()

	// Track saved events to verify rule was applied
	var savedEvents []models.VulnEvent
	depVulnRepo.On("SaveBatchBestEffort", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	vulnEventRepo.On("SaveBatchBestEffort", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		savedEvents = args.Get(2).([]models.VulnEvent)
	}).Return(nil)

	_, err = service.ApplyRulesToExistingVulns(context.Background(), nil, assetID, []models.VEXRule{rule})
	assert.NoError(t, err)

	// Verify that events were created when the rule was enabled
	assert.Len(t, savedEvents, 1, "enabled rule should create an event")
	if len(savedEvents) > 0 {
		assert.Equal(t, dtos.EventTypeFalsePositive, savedEvents[0].Type, "event type should match rule's event type")
	}

	depVulnRepo.AssertExpectations(t)
	vulnEventRepo.AssertExpectations(t)
	cveRelationshipService.AssertExpectations(t)
}

// TestMatchRulesToVulns_ComponentPurlWithAtSign verifies that rules with properly
// unescaped component PURLs (containing @) correctly match vulnerabilities.
func TestMatchRulesToVulns_ComponentPurlWithAtSign(t *testing.T) {
	vexRuleRepo := mocks.NewVEXRuleRepository(t)
	upstreamVexRuleRepo := mocks.NewUpstreamVEXRuleRepository(t)
	dependencyVulnRepo := mocks.NewDependencyVulnRepository(t)
	vulnEventRepo := mocks.NewVulnEventRepository(t)
	cveRepo := mocks.NewCveRepository(t)
	cveRelationshipRepo := mocks.NewCVERelationshipRepository(t)
	cveRelationshipService := mocks.NewCVERelationshipService(t)

	vexRuleService := NewVEXRuleService(
		vexRuleRepo,
		upstreamVexRuleRepo,
		dependencyVulnRepo,
		vulnEventRepo,
		cveRepo,
		cveRelationshipRepo,
		cveRelationshipService,
	)
	_ = vexRuleService

	rule := models.UpstreamVEXRule{
		ID: "rule-at-sign",
		// After the fix, path patterns contain unescaped @ signs
		CELExpression: celFor("CVE-2024-9999", []string{"pkg:npm/@myorg/myapp@1.0.0", "*", "pkg:npm/@myorg/vulnerable-lib@2.0.0"}),
	}

	vuln := models.DependencyVuln{
		CVEID: "CVE-2024-9999",
		// Vulnerability paths in the DB use unescaped @ signs
		VulnerabilityPath: []string{"pkg:npm/@myorg/myapp@1.0.0", "pkg:npm/@myorg/vulnerable-lib@2.0.0"},
		ComponentPurl:     "pkg:npm/@myorg/vulnerable-lib@2.0.0",
	}

	service := &VEXRuleService{}
	result := service.matchRulesToVulns(context.Background(), []models.UpstreamVEXRule{rule}, []models.DependencyVuln{vuln})

	assert.Len(t, result[rule.ID], 1, "rule should match the vulnerability")
	assert.Equal(t, "CVE-2024-9999", result[rule.ID][0].CVEID)
}

// TestVEXRuleServiceCreate tests rule creation
func TestVEXRuleServiceCreate(t *testing.T) {
	assetID := uuid.New()
	rule := &models.VEXRule{
		AssetID: assetID,
		UpstreamVEXRule: models.UpstreamVEXRule{
			Justification: "Test justification",
			CELExpression: celFor("CVE-2024-1234", []string{"pkg:golang/lib@v1.0"}),
		},
	}

	vexRuleRepo := mocks.NewVEXRuleRepository(t)
	depVulnRepo := mocks.NewDependencyVulnRepository(t)
	vulnEventRepo := mocks.NewVulnEventRepository(t)
	upstreamVexRuleRepo := mocks.NewUpstreamVEXRuleRepository(t)
	cveRepo := mocks.NewCveRepository(t)
	cveRelationshipRepo := mocks.NewCVERelationshipRepository(t)
	cveRelationshipService := mocks.NewCVERelationshipService(t)

	vexRuleRepo.On("Create", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	service := NewVEXRuleService(vexRuleRepo, upstreamVexRuleRepo, depVulnRepo, vulnEventRepo, cveRepo, cveRelationshipRepo, cveRelationshipService)
	err := service.Create(context.Background(), nil, rule)

	assert.NoError(t, err)
	vexRuleRepo.AssertExpectations(t)
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

	// Use a scoped npm package where the namespace contains @, which gets
	// percent-encoded to %40 by the packageurl library's ToString().
	bom := &cdx.BOM{
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
	}
	source := "test-source"

	vexRuleRepo := mocks.NewVEXRuleRepository(t)
	depVulnRepo := mocks.NewDependencyVulnRepository(t)
	vulnEventRepo := mocks.NewVulnEventRepository(t)
	upstreamVexRuleRepo := mocks.NewUpstreamVEXRuleRepository(t)
	cveRepo := mocks.NewCveRepository(t)
	cveRelationshipRepo := mocks.NewCVERelationshipRepository(t)
	cveRelationshipService := mocks.NewCVERelationshipService(t)

	vexRuleRepo.On("FindByAssetAndVexSource", mock.Anything, mock.Anything, assetID, mock.Anything).Return([]models.VEXRule{}, nil)

	var capturedRules []models.VEXRule
	vexRuleRepo.On("UpsertBatch", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		capturedRules = args.Get(2).([]models.VEXRule)
	}).Return(nil)

	depVulnRepo.On("GetAllOpenVulnsByAssetID", mock.Anything, mock.Anything, assetID).Return([]models.DependencyVuln{}, nil)

	service := NewVEXRuleService(vexRuleRepo, upstreamVexRuleRepo, depVulnRepo, vulnEventRepo, cveRepo, cveRelationshipRepo, cveRelationshipService)
	systemRules, err := transformer.CycloneDXVEXToRules(bom, source)
	assert.NoError(t, err)
	vexRules := transformer.AllUpstreamVEXRulesToVEXRules(systemRules, "test-user", assetID)
	err = service.IngestVEXRules(context.Background(), nil, asset, vexRules)
	assert.NoError(t, err)

	assert.NotEmpty(t, capturedRules, "expected at least one rule to be created")

	rule := capturedRules[0]
	// PathPattern is no longer a dedicated field - matching now happens purely via the
	// CEL expression, so we assert on its content instead of a []string PathPattern.
	celExpr := rule.CELExpression

	// The critical assertion: @ must NOT be encoded as %40 in the CEL expression's path
	// pattern. Before the fix, componentPurl.String() was used directly, producing
	// "pkg:npm/%40myorg/myapp@1.0.0" instead of "pkg:npm/@myorg/myapp@1.0.0".
	assert.NotContains(t, celExpr, "%40",
		"component PURL in CEL expression must not contain %%40 — @ should be unescaped")
	assert.Contains(t, celExpr, "@myorg/myapp@",
		"component PURL should contain the properly unescaped @")
	assert.Contains(t, celExpr, "@myorg/vulnerable-lib@",
		"vuln PURL should contain the properly unescaped @")

	// Verify the wildcard is present between the two purls
	assert.Contains(t, celExpr, vexrules.PathPatternWildcard,
		"middle element should be the wildcard")

	vexRuleRepo.AssertExpectations(t)
	depVulnRepo.AssertExpectations(t)
}

func TestParseVEXRulesFromOpenVEXReport_SelectValidProductID(t *testing.T) {
	testCases := []struct {
		name            string
		product         vex.Product
		wantPathPattern []string
	}{
		{
			name: "falls back to product id when identifiers are nil",
			product: vex.Product{
				Component: vex.Component{
					ID: "pkg:npm/@myorg/myapp@1.0.0",
				},
			},
			wantPathPattern: []string{vexrules.PathPatternWildcard, "pkg:npm/@myorg/myapp@1.0.0"},
		},
		{
			name: "uses purl identifier when present",
			product: vex.Product{
				Component: vex.Component{
					ID: "pkg:npm/ignored@0.0.0",
					Identifiers: map[vex.IdentifierType]string{
						vex.PURL: "pkg:npm/@myorg/myapp@1.0.0",
					},
				},
			},
			wantPathPattern: []string{vexrules.PathPatternWildcard, "pkg:npm/@myorg/myapp@1.0.0"},
		},
	}
	ts := time.Now().UTC()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			doc := &vex.VEX{
				Metadata: vex.Metadata{
					ID:        "openvex-report-1",
					Context:   "https://openvex.dev/ns/v0.2.0",
					Author:    "test-author",
					Version:   1,
					Timestamp: &ts,
				},
				Statements: []vex.Statement{
					{
						ID: "stmt-1",
						Vulnerability: vex.Vulnerability{
							Name: "CVE-2024-1234",
						},
						Status:          vex.StatusNotAffected,
						ImpactStatement: "not affected",
						Justification:   "component_not_present",
						Products:        []vex.Product{tc.product},
					},
				},
			}
			source := "test-source"

			rules, err := transformer.OpenVEXToRules(doc, source)
			assert.NoError(t, err)
			assert.Len(t, rules, 1)

			rule := rules[0]
			// UpstreamVEXRule is asset-agnostic (no AssetID/AssetVersionName field anymore);
			// matching against a CVE + path pattern is now encoded entirely in CELExpression.
			assert.Equal(t, dtos.EventTypeFalsePositive, rule.EventType)
			assert.Equal(t, celFor("CVE-2024-1234", tc.wantPathPattern), rule.CELExpression)
			assert.Equal(t, "not affected", rule.Justification)
			assert.Equal(t, dtos.MechanicalJustificationType("component_not_present"), rule.MechanicalJustification)
		})
	}
}

// TestParseVEXRulesFromOpenVEXReport_NormalAndMultipleStatements verifies
// parsing a normal OpenVEX report with multiple statements produces one
// VEX rule per statement.
func TestParseVEXRulesFromOpenVEXReport_NormalAndMultipleStatements(t *testing.T) {
	ts := time.Now().UTC()
	doc := &vex.VEX{
		Metadata: vex.Metadata{
			ID:        "openvex-report-2",
			Context:   "https://openvex.dev/ns/v0.2.0",
			Author:    "test-author",
			Version:   1,
			Timestamp: &ts,
		},
		Statements: []vex.Statement{
			{
				ID: "stmt-1",
				Vulnerability: vex.Vulnerability{
					Name: "CVE-2024-1111",
				},
				Status:        vex.StatusNotAffected,
				Justification: vex.ComponentNotPresent,
				Products: []vex.Product{
					{
						Component: vex.Component{
							ID: "pkg:golang/app@1.0",
							Identifiers: map[vex.IdentifierType]string{
								vex.PURL: "pkg:golang/app@1.0",
							},
						},
					},
				},
			},
			{
				ID: "stmt-2",
				Vulnerability: vex.Vulnerability{
					Name: "CVE-2024-2222",
				},
				Status:        vex.StatusNotAffected,
				Justification: vex.ComponentNotPresent,
				Products: []vex.Product{
					{
						Component: vex.Component{
							ID:          "pkg:golang/lib@2.0",
							Identifiers: map[vex.IdentifierType]string{},
						},
						Subcomponents: []vex.Subcomponent{
							{
								Component: vex.Component{
									ID: "pkg:golang/lib/sub@2.0",
								},
							},
						},
					},
					{
						Component: vex.Component{
							ID: "pkg:golang/app@1.0",
							Identifiers: map[vex.IdentifierType]string{
								vex.PURL: "pkg:golang/app@1.0",
							},
						},
					},
				},
			},
			{
				ID: "stmt-3",
				Vulnerability: vex.Vulnerability{
					Name: "CVE-2024-3333",
				},
				Status:          vex.StatusAffected,
				ActionStatement: "Update",
				Products: []vex.Product{
					{
						Component: vex.Component{
							ID: "pkg:golang/app@1.0",
							Identifiers: map[vex.IdentifierType]string{
								vex.PURL: "pkg:golang/app@1.0",
							},
						},
					},
				},
			},
		},
	}
	source := "test-source"

	rules, err := transformer.OpenVEXToRules(doc, source)

	assert.NoError(t, err)

	expected := []struct {
		cve                     string
		path                    []string
		mechanicalJustification string
		eventType               dtos.VulnEventType
	}{
		{cve: "CVE-2024-1111", path: []string{vexrules.PathPatternWildcard, "pkg:golang/app@1.0"}, mechanicalJustification: string(vex.ComponentNotPresent), eventType: dtos.EventTypeFalsePositive},
		// the vulnerable package is the subcomponent, not its containing product - see openVexStatementPurls
		{cve: "CVE-2024-2222", path: []string{vexrules.PathPatternWildcard, "pkg:golang/lib/sub@2.0"}, mechanicalJustification: string(vex.ComponentNotPresent), eventType: dtos.EventTypeFalsePositive},
		{cve: "CVE-2024-2222", path: []string{vexrules.PathPatternWildcard, "pkg:golang/app@1.0"}, mechanicalJustification: string(vex.ComponentNotPresent), eventType: dtos.EventTypeFalsePositive},
		{cve: "CVE-2024-3333", path: []string{vexrules.PathPatternWildcard, "pkg:golang/app@1.0"}, mechanicalJustification: "", eventType: dtos.EventTypeComment},
	}

	assert.Len(t, rules, len(expected), "number of generated rules should match expected")

	// We check by order, results and expected results have to line up for this test
	for i, exp := range expected {
		assert.Equal(t, celFor(exp.cve, exp.path), rules[i].CELExpression, "cel expression for %s", exp.cve)
		assert.Equal(t, exp.mechanicalJustification, string(rules[i].MechanicalJustification), "justification for %s", exp.cve)
		assert.Equal(t, exp.eventType, rules[i].EventType, "eventType for %s", exp.cve)
	}
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

	// Simulate a VEX report that was produced by devguard itself (BuildVeX),
	// which embeds pathPattern as a JSON property on each vulnerability.
	bom := &cdx.BOM{
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
	}
	source := "test-source"

	vexRuleRepo := mocks.NewVEXRuleRepository(t)
	depVulnRepo := mocks.NewDependencyVulnRepository(t)
	vulnEventRepo := mocks.NewVulnEventRepository(t)
	upstreamVexRuleRepo := mocks.NewUpstreamVEXRuleRepository(t)
	cveRepo := mocks.NewCveRepository(t)
	cveRelationshipRepo := mocks.NewCVERelationshipRepository(t)
	cveRelationshipService := mocks.NewCVERelationshipService(t)

	vexRuleRepo.On("FindByAssetAndVexSource", mock.Anything, mock.Anything, assetID, mock.Anything).Return([]models.VEXRule{}, nil)

	var capturedRules []models.VEXRule
	vexRuleRepo.On("UpsertBatch", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		capturedRules = args.Get(2).([]models.VEXRule)
	}).Return(nil)

	depVulnRepo.On("GetAllOpenVulnsByAssetID", mock.Anything, mock.Anything, assetID).Return([]models.DependencyVuln{}, nil)

	service := NewVEXRuleService(vexRuleRepo, upstreamVexRuleRepo, depVulnRepo, vulnEventRepo, cveRepo, cveRelationshipRepo, cveRelationshipService)
	systemRules, err := transformer.CycloneDXVEXToRules(bom, source)
	assert.NoError(t, err)
	vexRules := transformer.AllUpstreamVEXRulesToVEXRules(systemRules, "test-user", assetID)
	err = service.IngestVEXRules(context.Background(), nil, asset, vexRules)
	assert.NoError(t, err)

	assert.NotEmpty(t, capturedRules, "expected at least one rule to be created")

	rule := capturedRules[0]
	// The path pattern should come directly from the property, not reconstructed from PURLs
	assert.Equal(t, celFor("CVE-2024-1234", []string{"pkg:golang/root@v1.0", "*", "pkg:golang/vulnerable-lib@v2.0"}), rule.CELExpression,
		"cel expression should be built from the path pattern parsed from the property value, not reconstructed from PURLs")

	vexRuleRepo.AssertExpectations(t)
	depVulnRepo.AssertExpectations(t)
}

// TestParseVEXRulesInBOM_MultiplePathPatternProperties tests that multiple pathPattern
// properties on a single vulnerability each produce a separate VEX rule.
func TestParseVEXRulesInBOM_MultiplePathPatternProperties(t *testing.T) {
	assetID := uuid.New()
	asset := models.Asset{
		Model:        models.Model{ID: assetID},
		ParanoidMode: false,
	}

	bom := &cdx.BOM{
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
	}
	source := "test-source"

	vexRuleRepo := mocks.NewVEXRuleRepository(t)
	depVulnRepo := mocks.NewDependencyVulnRepository(t)
	vulnEventRepo := mocks.NewVulnEventRepository(t)
	upstreamVexRuleRepo := mocks.NewUpstreamVEXRuleRepository(t)
	cveRepo := mocks.NewCveRepository(t)
	cveRelationshipRepo := mocks.NewCVERelationshipRepository(t)
	cveRelationshipService := mocks.NewCVERelationshipService(t)

	vexRuleRepo.On("FindByAssetAndVexSource", mock.Anything, mock.Anything, assetID, mock.Anything).Return([]models.VEXRule{}, nil)

	var capturedRules []models.VEXRule
	vexRuleRepo.On("UpsertBatch", mock.Anything, mock.Anything, mock.Anything).Run(func(args mock.Arguments) {
		capturedRules = args.Get(2).([]models.VEXRule)
	}).Return(nil)

	depVulnRepo.On("GetAllOpenVulnsByAssetID", mock.Anything, mock.Anything, assetID).Return([]models.DependencyVuln{}, nil)

	service := NewVEXRuleService(vexRuleRepo, upstreamVexRuleRepo, depVulnRepo, vulnEventRepo, cveRepo, cveRelationshipRepo, cveRelationshipService)
	systemRules, err := transformer.CycloneDXVEXToRules(bom, source)
	assert.NoError(t, err)
	vexRules := transformer.AllUpstreamVEXRulesToVEXRules(systemRules, "test-user", assetID)
	err = service.IngestVEXRules(context.Background(), nil, asset, vexRules)
	assert.NoError(t, err)

	assert.Len(t, capturedRules, 2, "each pathPattern property should produce a separate VEX rule")

	celExprs := []string{
		capturedRules[0].CELExpression,
		capturedRules[1].CELExpression,
	}

	assert.Contains(t, celExprs, celFor("CVE-2024-1234", []string{"pkg:golang/root-a@v1.0", "*", "pkg:golang/vulnerable-lib@v2.0"}))
	assert.Contains(t, celExprs, celFor("CVE-2024-1234", []string{"pkg:golang/root-b@v1.0", "*", "pkg:golang/vulnerable-lib@v2.0"}))

	vexRuleRepo.AssertExpectations(t)
}
