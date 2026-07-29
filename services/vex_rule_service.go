// Copyright (C) 2026 l3montree GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package services

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/statemachine"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/l3montree-dev/devguard/vexrules"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
)

type VEXRuleService struct {
	vexRuleRepository        shared.VEXRuleRepository
	dependencyVulnRepository shared.DependencyVulnRepository
	vulnEventRepository      shared.VulnEventRepository
}

var _ shared.VEXRuleService = (*VEXRuleService)(nil)

func NewVEXRuleService(
	vexRuleRepository shared.VEXRuleRepository,
	dependencyVulnRepository shared.DependencyVulnRepository,
	vulnEventRepository shared.VulnEventRepository,
) *VEXRuleService {
	return &VEXRuleService{
		vexRuleRepository:        vexRuleRepository,
		dependencyVulnRepository: dependencyVulnRepository,
		vulnEventRepository:      vulnEventRepository,
	}
}

func (s *VEXRuleService) Create(ctx context.Context, tx shared.DB, rule *models.VEXRule) error {
	// Ensure the ID is calculated from composite key components
	rule.EnsureID()
	if err := s.vexRuleRepository.Create(ctx, tx, rule); err != nil {
		return fmt.Errorf("failed to create VEX rule: %w", err)
	}

	return nil
}

func (s *VEXRuleService) Begin(ctx context.Context) shared.DB {
	return s.vexRuleRepository.Begin(ctx)
}

func (s *VEXRuleService) Delete(ctx context.Context, tx shared.DB, rule models.VEXRule) error {
	return s.vexRuleRepository.Delete(ctx, tx, rule)
}

func (s *VEXRuleService) DeleteByAssetID(ctx context.Context, tx shared.DB, assetID uuid.UUID) error {
	return s.vexRuleRepository.DeleteByAssetID(ctx, tx, assetID)
}

func (s *VEXRuleService) FindByAssetID(ctx context.Context, tx shared.DB, assetID uuid.UUID) ([]models.VEXRule, error) {
	return s.vexRuleRepository.FindByAssetID(ctx, tx, assetID)
}

func (s *VEXRuleService) FindByAssetIDPaged(ctx context.Context, tx shared.DB, assetID uuid.UUID, pageInfo shared.PageInfo, search string, filterQuery []shared.FilterQuery, sortQuery []shared.SortQuery) (shared.Paged[models.VEXRule], error) {
	return s.vexRuleRepository.FindByAssetIDPaged(ctx, tx, assetID, pageInfo, search, filterQuery, sortQuery)
}

func (s *VEXRuleService) FindByAssetIDWithMatchingVuln(ctx context.Context, tx shared.DB, assetID uuid.UUID, vulnID uuid.UUID) ([]models.VEXRule, error) {
	// Fetch the vulnerability to get its CVEID and path
	vuln, err := s.dependencyVulnRepository.Read(ctx, tx, vulnID)
	if err != nil {
		return nil, fmt.Errorf("failed to find vulnerability: %w", err)
	}

	// Find rules for this CVE
	rules, err := s.vexRuleRepository.FindByAssetID(ctx, tx, assetID)
	if err != nil {
		return nil, err
	}

	// Filter rules to only those matching the vulnerability path pattern
	matches, err := vexrules.EvalRules(ctx, rules, vuln)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate CEL expressions: %w", err)
	}
	var matchingRules []models.VEXRule
	for _, rule := range rules {
		if matches[rule.ID] {
			matchingRules = append(matchingRules, rule)
		}
	}

	return matchingRules, nil
}

func (s *VEXRuleService) FindByID(ctx context.Context, tx shared.DB, id string) (models.VEXRule, error) {
	return s.vexRuleRepository.FindByID(ctx, tx, id)
}

// CountMatchingVulns returns the number of dependency vulnerabilities that a VEX rule has been applied to
func (s *VEXRuleService) CountMatchingVulns(ctx context.Context, tx shared.DB, rule models.VEXRule) (int, error) {
	counts, err := s.vulnEventRepository.CountByVexRuleIDs(ctx, tx, []string{rule.ID})
	if err != nil {
		return 0, fmt.Errorf("failed to count matching vulns: %w", err)
	}
	return counts[rule.ID], nil
}

// CountMatchingVulnsForRules returns, for each rule, the number of distinct
// dependency vulns it has an applied event for - i.e. vuln_events grouped by
// vex_rule_id. This avoids loading every vuln ever recorded for the asset
// (with full event/CVE preloads) just to recompute CEL matches that were
// already evaluated and recorded when the rule was applied.
func (s *VEXRuleService) CountMatchingVulnsForRules(ctx context.Context, tx shared.DB, rules []models.VEXRule) (map[string]int, error) {
	ctx, span := servicesTracer.Start(ctx, "VEXRuleService.CountMatchingVulnsForRules")
	defer span.End()
	span.SetAttributes(attribute.Int("rules.total", len(rules)))

	if len(rules) == 0 {
		return make(map[string]int), nil
	}

	ruleIDs := utils.Map(rules, func(r models.VEXRule) string { return r.ID })
	counts, err := s.vulnEventRepository.CountByVexRuleIDs(ctx, tx, ruleIDs)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("failed to count matching vulns: %w", err)
	}

	result := make(map[string]int, len(rules))
	for _, rule := range rules {
		if count, ok := counts[rule.ID]; ok {
			result[rule.ID] = count
		} else {
			result[rule.ID] = 0
		}
	}

	return result, nil
}

// CreateVulnEventFromVEXRule creates a VulnEvent based on a VEX rule and vulnerability.
// The event type is determined by the rule's EventType field.
func createVulnEventFromVEXRule(vuln models.DependencyVuln, rule *models.VEXRule) (models.VulnEvent, error) {
	var ev models.VulnEvent
	var err error

	switch rule.EventType {
	case dtos.EventTypeFalsePositive:
		ev, err = models.NewFalsePositiveEvent(
			vuln.CalculateHash(),
			dtos.VulnTypeDependencyVuln,
			rule.CreatedByID,
			rule.Justification,
			rule.MechanicalJustification,
			"",
			true,
			nil,
		), nil

	case dtos.EventTypeAccepted:
		ev, err = models.NewAcceptedEvent(
			vuln.CalculateHash(),
			dtos.VulnTypeDependencyVuln,
			rule.CreatedByID,
			rule.Justification,
			true,
			nil,
		), nil

	default:
		ev, err = models.VulnEvent{}, fmt.Errorf("unsupported event type from VEX rule: %s", rule.EventType)
	}
	ev.VexRuleID = &rule.ID
	if err != nil {
		return models.VulnEvent{}, fmt.Errorf("failed to create event from VEX rule: %w", err)
	}

	return ev, nil
}

func (s *VEXRuleService) ApplyRulesToExisting(ctx context.Context, tx shared.DB, rules []models.VEXRule, vulns []models.DependencyVuln) ([]models.DependencyVuln, error) {

	vulnsByRule := s.matchRulesToVulns(ctx, rules, vulns)
	ruleMap := make(map[string]*models.VEXRule)
	for i := range rules {
		ruleMap[rules[i].ID] = &rules[i]
	}

	// Collect all vulns to update (deduplicated by ID)
	vulnMap := make(map[uuid.UUID]models.DependencyVuln)
	eventsByVuln := make(map[uuid.UUID][]models.VulnEvent)

	for ruleID, matchingVulns := range vulnsByRule {
		rule := ruleMap[ruleID]
		for _, vuln := range matchingVulns {
			ev, err := createVulnEventFromVEXRule(vuln, rule)
			if err != nil {
				slog.Error("failed to create event from VEX rule", "error", err)
				continue
			}

			// Skip duplicate events unless force reapply is enabled
			if isVexEventAlreadyApplied(vuln, ev) {
				continue
			}

			vulnID := vuln.ID
			vulnMap[vulnID] = vuln
			eventsByVuln[vulnID] = append(eventsByVuln[vulnID], ev)
		}
	}

	if len(vulnMap) == 0 {
		return vulns, nil
	}

	// Apply all events to vulns and collect updated vulns and events
	updatedVulns := make([]models.DependencyVuln, 0, len(vulnMap))
	allEvents := make([]models.VulnEvent, 0)

	for vulnID, vuln := range vulnMap {
		updatedVuln := vuln
		for _, ev := range eventsByVuln[vulnID] {
			statemachine.Apply(&updatedVuln, ev)
			allEvents = append(allEvents, ev)
		}
		updatedVulns = append(updatedVulns, updatedVuln)
	}

	// Save all updated vulns and events in one batch
	if err := s.dependencyVulnRepository.SaveBatchBestEffort(ctx, tx, updatedVulns); err != nil {
		return nil, fmt.Errorf("failed to save updated vulns: %w", err)
	}

	if err := s.vulnEventRepository.SaveBatchBestEffort(ctx, tx, allEvents); err != nil {
		return nil, fmt.Errorf("failed to save events: %w", err)
	}

	logAction := "applied"
	slog.Info(logAction+" VEX rules to existing vulnerabilities",
		"rulesApplied", len(rules),
		"vulnsUpdated", len(updatedVulns),
		"eventsCreated", len(allEvents))
	return updatedVulns, nil
}

// ApplyRulesToExistingVulns applies multiple VEX rules to all existing vulnerabilities
// that match each rule's path pattern and CVE. This is more efficient than applying
// rules one by one as it batches database queries and saves.
func (s *VEXRuleService) ApplyRulesToExistingVulns(ctx context.Context, tx shared.DB, rules []models.VEXRule) ([]models.DependencyVuln, error) {
	if len(rules) == 0 {
		return nil, nil
	}
	// Find all vulns matching all rules at once
	// we need to fetch with events right here to make sure we can identify vex rules which were already applied.
	vulns, err := s.dependencyVulnRepository.GetAllOpenVulnsByAssetID(ctx, tx, rules[0].AssetID)

	if err != nil {
		return nil, fmt.Errorf("failed to fetch existing vulns for asset: %w", err)
	}
	return s.ApplyRulesToExisting(ctx, tx, rules, vulns)
}

func isVexEventAlreadyApplied(vuln models.DependencyVuln, event models.VulnEvent) bool {
	events := vuln.GetEvents()
	if len(events) == 0 {
		return false
	}
	var ev models.VulnEvent
	found := false

	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Type == dtos.EventTypeRawRiskAssessmentUpdated {
			continue
		}
		ev = events[i]
		found = true
		break
	}

	if !found {
		return false
	}

	if ev.Type != event.Type {
		return false
	}

	if ev.Justification == nil || event.Justification == nil {
		return ev.Justification == nil && event.Justification == nil
	}

	return *ev.Justification == *event.Justification
}

// IngestVEXRules syncs the given rules for a single source and applies them to existing
// vulns. This is the format-agnostic ingestion entry point: callers run the appropriate
// transformer (CycloneDX/CSAF/OpenVEX) to produce the rules, then hand them here.
func (s *VEXRuleService) IngestVEXRules(ctx context.Context, tx shared.DB, asset models.Asset, rules []models.VEXRule) error {
	addedRules, err := s.syncRulesForSource(ctx, tx, asset, rules)
	if err != nil {
		return fmt.Errorf("failed to sync VEX rules: %w", err)
	}
	_, err = s.ApplyRulesToExistingVulns(ctx, tx, addedRules)
	return err
}

// syncRulesForSource sets the Enabled flag based on ParanoidMode and syncs the rules for the
// given source, returning the rules that were newly added.
func (s *VEXRuleService) syncRulesForSource(ctx context.Context, tx shared.DB, asset models.Asset, rules []models.VEXRule) ([]models.VEXRule, error) {
	// Rules are enabled if ParanoidMode is disabled
	enabled := !asset.ParanoidMode
	for i := range rules {
		rules[i].Enabled = enabled
	}
	addedRules, _, err := s.syncVEXRulesFromSource(ctx, tx, asset.ID, rules)
	return addedRules, err
}

// SyncVEXRulesFromSource syncs VEX rules from a specific source.
// It fetches existing rules for the given asset and vexSource, compares them with
// the new rules, adds new ones and removes ones that no longer exist.
func (s *VEXRuleService) syncVEXRulesFromSource(ctx context.Context, tx shared.DB, assetID uuid.UUID, newRules []models.VEXRule) ([]models.VEXRule, []models.VEXRule, error) {
	// read the source from the first rule to ensure consistency
	if len(newRules) == 0 {
		return nil, nil, nil
	}
	vexSource := newRules[0].VexSource
	// Fetch existing rules for this asset and vexSource
	existingRules, err := s.vexRuleRepository.FindByAssetAndVexSource(ctx, tx, assetID, vexSource)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch existing VEX rules: %w", err)
	}

	result := utils.CompareSlices(newRules, existingRules, func(a models.VEXRule) string {
		return a.ID
	})

	rulesToAdd := result.OnlyInA
	rulesToRemove := result.OnlyInB

	// Add new rules
	if len(rulesToAdd) > 0 {
		if err := s.vexRuleRepository.UpsertBatch(ctx, tx, rulesToAdd); err != nil {
			return nil, nil, fmt.Errorf("failed to add new VEX rules: %w", err)
		}
		slog.Info("added new VEX rules from source",
			"assetID", assetID,
			"vexSource", vexSource,
			"count", len(rulesToAdd))
	}

	// Remove old rules
	if len(rulesToRemove) > 0 {
		if err := s.vexRuleRepository.DeleteBatch(ctx, tx, rulesToRemove); err != nil {
			return nil, nil, fmt.Errorf("failed to remove old VEX rules: %w", err)
		}
		slog.Info("removed old VEX rules from source",
			"assetID", assetID,
			"vexSource", vexSource,
			"count", len(rulesToRemove))
	}

	return rulesToAdd, rulesToRemove, nil
}

func (s *VEXRuleService) matchRulesToVulns(ctx context.Context, rules []models.VEXRule, vulns []models.DependencyVuln) map[string][]models.DependencyVuln {
	ctx, span := servicesTracer.Start(ctx, "VEXRuleService.matchRulesToVulns")
	defer span.End()

	result := make(map[string][]models.DependencyVuln)

	// CEL-based rules are evaluated against every vulnerability, regardless of CVE ID.
	var celRules []models.VEXRule

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if rule.CELExpression != "" {
			celRules = append(celRules, rule)
		}
	}
	span.SetAttributes(
		attribute.Int("rules.cel_total", len(celRules)),
		attribute.Int("vulns.total", len(vulns)),
		attribute.Int("evaluations.total", len(celRules)*len(vulns)),
	)

	for _, vuln := range vulns {
		matches, err := vexrules.EvalRules(ctx, celRules, vuln)
		if err != nil {
			slog.Error("failed to evaluate CEL expressions for VEX rules", "error", err)
			continue
		}
		for _, rule := range celRules {
			if matches[rule.ID] {
				result[rule.ID] = append(result[rule.ID], vuln)
			}
		}
	}
	return result
}
