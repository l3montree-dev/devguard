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
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/statemachine"
	"github.com/l3montree-dev/devguard/utils"
)

type VEXRuleService struct {
	vexRuleRepository        shared.VEXRuleRepository
	dependencyVulnRepository shared.DependencyVulnRepository
	vulnEventRepository      shared.VulnEventRepository
}

var _ shared.VEXRuleService = (*VEXRuleService)(nil)

var vexRuleCelEnv = sync.OnceValues(func() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Variable("vuln", cel.AnyType),
		cel.Function("matchesPattern",

			cel.Overload(
				"matchesPattern_vuln_list",
				[]*cel.Type{cel.DynType, cel.ListType(cel.StringType)},
				cel.BoolType,
				cel.BinaryBinding(func(lhs, rhs ref.Val) ref.Val {
					path, err := stringListField(lhs, "vulnerabilityPath")
					if err != nil {
						return types.NewErr("matchesPattern: invalid vuln.vulnerabilityPath: %v", err)
					}
					artifactPurls, err := stringListField(lhs, "artifactPurls")
					if err != nil {
						return types.NewErr("matchesPattern: invalid vuln.artifactPurls: %v", err)
					}
					pattern, err := toStringList(rhs)
					if err != nil {
						return types.NewErr("matchesPattern: invalid pattern argument: %v", err)
					}
					matches := dtos.PathPattern(pattern).Matches(path, artifactPurls)
					return types.Bool(matches)
				}),
			),
		),
	)
})

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

func (s *VEXRuleService) Update(ctx context.Context, tx shared.DB, rule *models.VEXRule) error {
	rule.SetPathPattern(rule.PathPattern)
	return s.vexRuleRepository.Update(ctx, tx, rule)
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

func (s *VEXRuleService) FindByAssetIDAndCVE(ctx context.Context, tx shared.DB, assetID uuid.UUID, cveID string) ([]models.VEXRule, error) {
	return s.vexRuleRepository.FindByAssetIDAndCVE(ctx, tx, assetID, cveID)
}

func (s *VEXRuleService) FindByAssetIDAndVulnID(ctx context.Context, tx shared.DB, assetID uuid.UUID, vulnID uuid.UUID) ([]models.VEXRule, error) {
	// Fetch the vulnerability to get its CVEID and path
	vuln, err := s.dependencyVulnRepository.Read(ctx, tx, vulnID)
	if err != nil {
		return nil, fmt.Errorf("failed to find vulnerability: %w", err)
	}

	// Find rules for this CVE
	rules, err := s.vexRuleRepository.FindByAssetIDAndCVE(ctx, tx, assetID, vuln.CVEID)
	if err != nil {
		return nil, err
	}

	// Filter rules to only those matching the vulnerability path pattern
	artifactIdentities := vuln.ArtifactPurls()
	var matchingRules []models.VEXRule
	for _, rule := range rules {
		pattern := dtos.PathPattern(rule.PathPattern)
		if pattern.Matches(vuln.VulnerabilityPath, artifactIdentities) {
			matchingRules = append(matchingRules, rule)
		}
	}

	return matchingRules, nil
}

func (s *VEXRuleService) FindByID(ctx context.Context, tx shared.DB, id string) (models.VEXRule, error) {
	return s.vexRuleRepository.FindByID(ctx, tx, id)
}

// CountMatchingVulns returns the number of dependency vulnerabilities that match a VEX rule
func (s *VEXRuleService) CountMatchingVulns(ctx context.Context, tx shared.DB, rule models.VEXRule) (int, error) {
	vulns, err := s.dependencyVulnRepository.GetByAssetID(ctx, tx, rule.AssetID)
	if err != nil {
		return 0, fmt.Errorf("failed to count matching vulns: %w", err)
	}
	matching := matchRulesToVulns([]models.VEXRule{rule}, vulns)

	return len(matching[rule.ID]), nil
}

// CountMatchingVulnsForRules returns the number of matching vulnerabilities for each rule in a single batch query
// Returns a map of rule ID to count
func (s *VEXRuleService) CountMatchingVulnsForRules(ctx context.Context, tx shared.DB, rules []models.VEXRule) (map[string]int, error) {
	if len(rules) == 0 {
		return make(map[string]int), nil
	}

	result := make(map[string]int)
	assetID := rules[0].AssetID

	vulns, err := s.dependencyVulnRepository.GetByAssetID(ctx, tx, assetID)

	vulnsByRule := matchRulesToVulns(rules, vulns)
	if err != nil {
		return nil, fmt.Errorf("failed to count matching vulns: %w", err)
	}

	for _, rule := range rules {
		if vulns, ok := vulnsByRule[rule.ID]; ok {
			result[rule.ID] = len(vulns)
		} else {
			result[rule.ID] = 0
		}
	}

	return result, nil
}

// CreateVulnEventFromVEXRule creates a VulnEvent based on a VEX rule and vulnerability.
// The event type is determined by the rule's EventType field.
func createVulnEventFromVEXRule(vuln models.DependencyVuln, rule *models.VEXRule) (models.VulnEvent, error) {
	switch rule.EventType {
	case dtos.EventTypeFalsePositive:
		return models.NewFalsePositiveEvent(
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
		return models.NewCommentEvent(
			vuln.CalculateHash(),
			dtos.VulnTypeDependencyVuln,
			rule.CreatedByID,
			rule.Justification,
			true,
			nil,
		), nil

	default:
		return models.VulnEvent{}, fmt.Errorf("unsupported event type from VEX rule: %s", rule.EventType)
	}
}

func (s *VEXRuleService) ApplyRulesToExisting(ctx context.Context, tx shared.DB, rules []models.VEXRule, vulns []models.DependencyVuln) ([]models.DependencyVuln, error) {
	return s.applyRulesToExistingInternal(ctx, tx, rules, vulns)
}

func (s *VEXRuleService) applyRulesToExistingInternal(ctx context.Context, tx shared.DB, rules []models.VEXRule, vulns []models.DependencyVuln) ([]models.DependencyVuln, error) {
	vulnsByRule := matchRulesToVulns(rules, vulns)
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
				slog.Error("failed to create event from VEX rule", "error", err, "cveID", rule.CVEID)
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
	vulns, err := s.dependencyVulnRepository.GetByAssetID(ctx, tx, rules[0].AssetID)

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

func matchVulnsToRules(vulns []models.DependencyVuln, rules []models.VEXRule) map[uuid.UUID][]models.VEXRule {
	result := make(map[uuid.UUID][]models.VEXRule)
	// Filter by each rule's cve and path pattern - only match ENABLED rules
	// group by vuln ID
	m := make(map[string][]models.DependencyVuln)
	for _, vuln := range vulns {
		m[vuln.CVEID] = append(m[vuln.CVEID], vuln)
	}

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		vulnsForCVE := m[rule.CVEID]
		for _, vuln := range vulnsForCVE {
			pattern := dtos.PathPattern(rule.PathPattern)
			if pattern.Matches(vuln.VulnerabilityPath, vuln.ArtifactPurls()) {
				result[vuln.ID] = append(result[vuln.ID], rule)
			}
		}
	}
	return result
}

func toStringList(val ref.Val) ([]string, error) {
	native, err := val.ConvertToNative(reflect.TypeOf([]string{}))
	if err != nil {
		return nil, err
	}
	return native.([]string), nil
}

func stringListField(mapVal ref.Val, key string) ([]string, error) {
	mapper, ok := mapVal.(traits.Mapper)
	if !ok {
		return nil, fmt.Errorf("expected a map, got %s", mapVal.Type().TypeName())
	}
	fieldVal, found := mapper.Find(types.String(key))
	if !found || fieldVal == nil {
		return nil, nil
	}
	if types.IsError(fieldVal) {
		return nil, fmt.Errorf("field %q: %v", key, fieldVal)
	}
	return toStringList(fieldVal)
}

func (s *VEXRuleService) EvalCELExpression(ctx context.Context, rule models.VEXRule, vuln models.DependencyVuln) (bool, error) {
	if rule.CELExpression == "" {
		return false, nil
	}

	celEnv, err := vexRuleCelEnv()
	if err != nil {
		return false, fmt.Errorf("failed to create CEL environment: %w", err)
	}

	ast, iss := celEnv.Compile(rule.CELExpression)
	if iss != nil && iss.Err() != nil {
		return false, fmt.Errorf("failed to compile CEL expression: %w", iss.Err())
	}

	prg, err := celEnv.Program(ast)
	if err != nil {
		return false, fmt.Errorf("failed to build CEL program: %w", err)
	}

	m, err := json.Marshal(vuln)
	if err != nil {
		return false, fmt.Errorf("failed to marshal vuln to JSON: %w", err)
	}

	var vulnMap map[string]any
	if err := json.Unmarshal(m, &vulnMap); err != nil {
		return false, fmt.Errorf("failed to unmarshal JSON to map: %w", err)
	}
	// artifactPurls is derived (vuln.ArtifactPurls()), not a JSON field of
	// DependencyVuln, so it has to be added to the map explicitly for
	// matchesPattern(vuln, pattern) to see it.
	vulnMap["artifactPurls"] = vuln.ArtifactPurls()

	out, _, err := prg.Eval(map[string]any{
		"vuln": vulnMap,
	})

	if err != nil {
		return false, fmt.Errorf("failed to evaluate CEL expression: %w", err)
	}

	result, ok := out.Value().(bool)
	if !ok {
		return false, fmt.Errorf("CEL expression did not evaluate to a bool, got %T", out.Value())
	}
	return result, nil
}

func matchRulesToVulns(rules []models.VEXRule, vulns []models.DependencyVuln) map[string][]models.DependencyVuln {
	result := make(map[string][]models.DependencyVuln)
	// Filter by each rule's cve and path pattern - only match ENABLED rules
	// group by cve id
	m := make(map[string][]models.VEXRule)
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		m[rule.CVEID] = append(m[rule.CVEID], rule)
	}

	for _, vuln := range vulns {
		rulesForCVE := m[vuln.CVEID]
		for _, rule := range rulesForCVE {
			pattern := dtos.PathPattern(rule.PathPattern)
			if pattern.Matches(vuln.VulnerabilityPath, vuln.ArtifactPurls()) {
				result[rule.ID] = append(result[rule.ID], vuln)
			}
		}
	}
	return result
}
