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
	"strings"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/statemachine"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
)

type VEXRuleService struct {
	vexRuleRepository         shared.VEXRuleRepository
	systemVEXRuleRepository   shared.SystemVEXRuleRepository
	dependencyVulnRepository  shared.DependencyVulnRepository
	vulnEventRepository       shared.VulnEventRepository
	cveRepository             shared.CveRepository
	cveRelationshipRepository shared.CVERelationshipRepository
	cveRelationshipService    shared.CVERelationshipService
}

var _ shared.VEXRuleService = (*VEXRuleService)(nil)

func NewVEXRuleService(
	vexRuleRepository shared.VEXRuleRepository,
	systemVEXRuleRepository shared.SystemVEXRuleRepository,
	dependencyVulnRepository shared.DependencyVulnRepository,
	vulnEventRepository shared.VulnEventRepository,
	cveRepository shared.CveRepository,
	cveRelationshipRepository shared.CVERelationshipRepository,
	cveRelationshipService shared.CVERelationshipService,
) *VEXRuleService {
	return &VEXRuleService{
		vexRuleRepository:         vexRuleRepository,
		systemVEXRuleRepository:   systemVEXRuleRepository,
		dependencyVulnRepository:  dependencyVulnRepository,
		vulnEventRepository:       vulnEventRepository,
		cveRepository:             cveRepository,
		cveRelationshipRepository: cveRelationshipRepository,
		cveRelationshipService:    cveRelationshipService,
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

func (s *VEXRuleService) DeleteByAssetVersion(ctx context.Context, tx shared.DB, assetID uuid.UUID, assetVersionName string) error {
	return s.vexRuleRepository.DeleteByAssetVersion(ctx, tx, assetID, assetVersionName)
}

func (s *VEXRuleService) FindByAssetVersion(ctx context.Context, tx shared.DB, assetID uuid.UUID, assetVersionName string) ([]models.VEXRule, error) {
	return s.vexRuleRepository.FindByAssetVersion(ctx, tx, assetID, assetVersionName)
}

func (s *VEXRuleService) FindByAssetVersionPaged(ctx context.Context, tx shared.DB, assetID uuid.UUID, assetVersionName string, pageInfo shared.PageInfo, search string, filterQuery []shared.FilterQuery, sortQuery []shared.SortQuery) (shared.Paged[models.VEXRule], error) {
	return s.vexRuleRepository.FindByAssetVersionPaged(ctx, tx, assetID, assetVersionName, pageInfo, search, filterQuery, sortQuery)
}

func (s *VEXRuleService) FindByAssetVersionAndCVE(ctx context.Context, tx shared.DB, assetID uuid.UUID, assetVersionName string, cveID string) ([]models.VEXRule, error) {
	return s.vexRuleRepository.FindByAssetVersionAndCVE(ctx, tx, assetID, assetVersionName, cveID)
}

func (s *VEXRuleService) FindByAssetVersionAndVulnID(ctx context.Context, tx shared.DB, assetID uuid.UUID, assetVersionName string, vulnID uuid.UUID) ([]models.VEXRule, error) {
	// Fetch the vulnerability to get its CVEID and path
	vuln, err := s.dependencyVulnRepository.Read(ctx, tx, vulnID)
	if err != nil {
		return nil, fmt.Errorf("failed to find vulnerability: %w", err)
	}

	cveAliasMap, err := s.cveRelationshipService.CreateAliasRelationshipMapBatch(ctx, tx, []string{vuln.CVEID})
	if err != nil {
		slog.Info("Failed to find CVE Aliases, continuing without")
	}
	var cveAliases []string
	for alias := range cveAliasMap[vuln.CVEID] {
		cveAliases = append(cveAliases, alias)
	}
	cveAliases = append(cveAliases, vuln.CVEID)

	// Find rules for this CVE and aliases
	rules, err := s.vexRuleRepository.FindByAssetVersionAndCVEAliases(ctx, tx, assetID, assetVersionName, cveAliases)
	if err != nil {
		return nil, err
	}

	// Filter rules to only those matching the vulnerability path pattern
	artifactIdentities := vuln.ArtifactPurls()
	var matchingRules []models.VEXRule
	for _, rule := range rules {
		pattern := dtos.PathPattern(rule.PathPattern)
		if pattern.MatchesSuffixForArtifacts(vuln.VulnerabilityPath, artifactIdentities) {
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
	vulns, err := s.dependencyVulnRepository.GetDependencyVulnsByAssetVersion(ctx, tx, rule.AssetVersionName, rule.AssetID, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to count matching vulns: %w", err)
	}
	matching := s.MatchRulesToVulns(ctx, tx, []models.VEXRule{rule}, vulns)

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
	assetVersionName := rules[0].AssetVersionName

	vulns, err := s.dependencyVulnRepository.GetDependencyVulnsByAssetVersion(ctx, tx, assetVersionName, assetID, nil)

	vulnsByRule := s.MatchRulesToVulns(ctx, tx, rules, vulns)
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
	return s.applyRulesToExistingInternal(ctx, tx, rules, vulns, false)
}

// ApplyRulesToExistingForce applies rules to existing vulns ignoring duplicate checks
func (s *VEXRuleService) ApplyRulesToExistingForce(ctx context.Context, tx shared.DB, rules []models.VEXRule, vulns []models.DependencyVuln) ([]models.DependencyVuln, error) {
	return s.applyRulesToExistingInternal(ctx, tx, rules, vulns, true)
}

func (s *VEXRuleService) applyRulesToExistingInternal(ctx context.Context, tx shared.DB, rules []models.VEXRule, vulns []models.DependencyVuln, forceReapply bool) ([]models.DependencyVuln, error) {
	vulnsByRule := s.MatchRulesToVulns(ctx, tx, rules, vulns)
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
			if !forceReapply && isVexEventAlreadyApplied(vuln, ev) {
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
	if forceReapply {
		logAction = "reapplied"
	}
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
	assetDeduplicationMap := make(map[string]bool)
	assetTuples := []struct {
		AssetID          string
		AssetVersionName string
	}{}

	for _, rule := range rules {
		assetIDString := rule.AssetID.String()
		compositeKey := assetIDString + rule.AssetVersionName
		if !assetDeduplicationMap[compositeKey] {
			assetDeduplicationMap[compositeKey] = true
			assetTuples = append(assetTuples, struct {
				AssetID          string
				AssetVersionName string
			}{AssetID: assetIDString, AssetVersionName: rule.AssetVersionName})
		}
	}

	// Find all vulns matching all rules at once
	vulns, err := s.dependencyVulnRepository.GetAllOpenVulnsByAssetVersionNameAndAssetIDBatch(ctx, tx, assetTuples)

	if err != nil {
		return nil, fmt.Errorf("failed to fetch existing vulns for asset: %w", err)
	}
	return s.ApplyRulesToExisting(ctx, tx, rules, vulns)
}

// ApplyRulesToExistingVulnsForce applies rules to existing vulns ignoring duplicate checks
func (s *VEXRuleService) ApplyRulesToExistingVulnsForce(ctx context.Context, tx shared.DB, rules []models.VEXRule) ([]models.DependencyVuln, error) {
	if len(rules) == 0 {
		return nil, nil
	}
	// Find all vulns matching all rules at once
	vulns, err := s.dependencyVulnRepository.GetAllOpenVulnsByAssetVersionNameAndAssetID(ctx, tx, nil, rules[0].AssetVersionName, rules[0].AssetID)

	if err != nil {
		return nil, fmt.Errorf("failed to fetch existing vulns for asset: %w", err)
	}
	return s.ApplyRulesToExistingForce(ctx, tx, rules, vulns)
}

func isVexEventAlreadyApplied(vuln models.DependencyVuln, event models.VulnEvent) bool {
	for _, ev := range vuln.GetEvents() {
		if ev.Type == event.Type && (ev.Justification == nil && event.Justification == nil || *ev.Justification == *event.Justification) {
			return true
		}
	}
	return false
}

// IngestVEXRules syncs the given rules for a single source and applies them to existing
// vulns. This is the format-agnostic ingestion entry point: callers run the appropriate
// transformer (CycloneDX/CSAF/OpenVEX) to produce the rules, then hand them here.
func (s *VEXRuleService) IngestVEXRules(ctx context.Context, tx shared.DB, asset models.Asset, assetVersion models.AssetVersion, rules []models.VEXRule) error {
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
			if pattern.MatchesSuffixForArtifacts(vuln.VulnerabilityPath, vuln.ArtifactPurls()) {
				result[vuln.ID] = append(result[vuln.ID], rule)
			}
		}
	}
	return result
}

func (s *VEXRuleService) MatchRulesToVulns(ctx context.Context, tx shared.DB, rules []models.VEXRule, vulns []models.DependencyVuln) map[string][]models.DependencyVuln {
	result := make(map[string][]models.DependencyVuln)
	// Prepare aliases
	// Relationship field of rules cannot be preloaded since the preload assumes that the CVEID is the source_cve in the relationship
	// Therefore it cannot find the relationships
	// We try to find the relationships manually and create a many-to-many crossreference so each CVE will always find each alias
	ruleCVEIDs := utils.Map(rules, func(rule models.VEXRule) string { return rule.CVEID })

	cveAliasMap, err := s.cveRelationshipService.CreateAliasRelationshipMapBatch(ctx, tx, ruleCVEIDs)
	if err != nil {
		slog.Info("could not find aliases to create cross relations", "err", err)
	}
	// Filter by each rule's cve and path pattern - only match ENABLED rules
	// group by cve id
	m := make(map[string][]models.VEXRule)
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		m[rule.CVEID] = append(m[rule.CVEID], rule)
		// Prepare for aliases
		for aliasCVEID := range cveAliasMap[rule.CVEID] {
			m[aliasCVEID] = append(m[aliasCVEID], rule)
		}
	}

	for _, vuln := range vulns {
		rulesForCVE := m[vuln.CVEID]

		for _, rule := range rulesForCVE {
			pattern := dtos.PathPattern(rule.PathPattern)
			if vuln.Vulnerability.AssetID == rule.AssetID &&
				vuln.Vulnerability.AssetVersionName == rule.AssetVersionName &&
				pattern.MatchesSuffixForArtifacts(vuln.VulnerabilityPath, vuln.ArtifactPurls()) {
				result[rule.ID] = append(result[rule.ID], vuln)
			}
		}
	}
	return result
}

func (s *VEXRuleService) UpdateSystemVEXRulesFromStaticSources(ctx context.Context, reports []*transformer.VexReportOpenVEX) error {
	systemVEXRulesMap := make(map[string]bool)
	var systemVEXRules []models.SystemVEXRule
	includedCVEsMap := make(map[string]bool)
	var includedCVEs []string

	for _, report := range reports {
		if report.Source == "" {
			slog.Info("OpenVEX report contains no source. Skipping this report")
			continue
		}
		if report.Report == nil {
			slog.Info("OpenVEX report contains no report information. Skipping this report")
			continue
		}

		parsedVEXRules, err := transformer.OpenVEXToRules(report.Report, uuid.Nil, "main", report.Source)
		if err != nil {
			slog.Info("Error while parsing OpenVEX report", "error", err, "report", report.Report.ID)
			continue
		}
		for _, parsedRule := range parsedVEXRules {
			// This clause uses a map for deduplication
			if _, exists := systemVEXRulesMap[parsedRule.ID]; !exists {
				systemVEXRule := transformer.VEXRuleToSystemVEXRule(parsedRule)
				systemVEXRulesMap[parsedRule.ID] = true
				systemVEXRules = append(systemVEXRules, systemVEXRule)
				if _, cveExists := includedCVEsMap[parsedRule.CVEID]; !cveExists {
					includedCVEs = append(includedCVEs, parsedRule.CVEID)
				}
			}
		}
	}
	//Check if CVEs are already in database since database can take some time to be established
	// If there are a lot of CVEs in a project, the lookup might fail for having
	// more than 65535 keys
	const cveBatchSize = 1000

	existingCVEMap := make(map[string]models.CVE)

	for start := 0; start < len(includedCVEs); start += cveBatchSize {
		end := start + cveBatchSize
		if end > len(includedCVEs) {
			end = len(includedCVEs)
		}

		batch := includedCVEs[start:end]
		found, err := s.cveRepository.FindCVEs(ctx, nil, batch)
		if err != nil {
			return fmt.Errorf("failed to fetch existing CVEs: %w", err)
		}

		for _, cve := range found {
			existingCVEMap[strings.ToLower(strings.TrimSpace(cve.CVE))] = cve
		}
	}

	filteredRules := make([]models.SystemVEXRule, 0, len(systemVEXRules))
	for _, rule := range systemVEXRules {
		cveKey := strings.ToLower(strings.TrimSpace(rule.CVEID))
		if _, exists := existingCVEMap[cveKey]; !exists {
			// Might SPAM logs
			slog.Info("skipping system VEX rule because CVE does not exist in database yet",
				"cveID", rule.CVEID,
				"vexSource", rule.VexSource,
				"ruleID", rule.ID,
			)
			continue
		}
		filteredRules = append(filteredRules, rule)
	}

	if len(filteredRules) == 0 {
		slog.Info("no system VEX rules left after CVE filtering")
		return nil
	}

	//Bulk Upload of valid VEXRules
	err := s.systemVEXRuleRepository.UpsertBatch(ctx, nil, filteredRules)
	if err != nil {
		return fmt.Errorf("Error while inserting extracted VEXRules into database: %s", err)
	}
	slog.Info("updated system VEXRules", "fetched", len(systemVEXRules), "filtered", len(filteredRules))

	return nil
}
