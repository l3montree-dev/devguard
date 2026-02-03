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
	"fmt"
	"log/slog"
	"slices"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/normalize"
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

func (s *VEXRuleService) Create(tx shared.DB, rule *models.VEXRule) error {
	// Ensure the ID is calculated from composite key components
	rule.EnsureID()
	if err := s.vexRuleRepository.Create(tx, rule); err != nil {
		return fmt.Errorf("failed to create VEX rule: %w", err)
	}

	return nil
}

func (s *VEXRuleService) Begin() shared.DB {
	return s.vexRuleRepository.Begin()
}

func (s *VEXRuleService) Update(tx shared.DB, rule *models.VEXRule) error {
	rule.SetPathPattern(rule.PathPattern)
	return s.vexRuleRepository.Update(tx, rule)
}

func (s *VEXRuleService) Delete(tx shared.DB, rule models.VEXRule) error {
	return s.vexRuleRepository.Delete(tx, rule)
}

func (s *VEXRuleService) DeleteByAssetVersion(tx shared.DB, assetID uuid.UUID, assetVersionName string) error {
	return s.vexRuleRepository.DeleteByAssetVersion(tx, assetID, assetVersionName)
}

func (s *VEXRuleService) FindByAssetVersion(tx shared.DB, assetID uuid.UUID, assetVersionName string) ([]models.VEXRule, error) {
	return s.vexRuleRepository.FindByAssetVersion(tx, assetID, assetVersionName)
}

func (s *VEXRuleService) FindByID(tx shared.DB, id string) (models.VEXRule, error) {
	return s.vexRuleRepository.FindByID(tx, id)
}

// CountMatchingVulns returns the number of dependency vulnerabilities that match a VEX rule
func (s *VEXRuleService) CountMatchingVulns(tx shared.DB, rule models.VEXRule) (int, error) {
	vulns, err := s.dependencyVulnRepository.GetDependencyVulnsByAssetVersion(tx, rule.AssetVersionName, rule.AssetID, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to count matching vulns: %w", err)
	}
	matching := matchRulesToVulns([]models.VEXRule{rule}, vulns)

	return len(matching[&rule]), nil
}

// CountMatchingVulnsForRules returns the number of matching vulnerabilities for each rule in a single batch query
// Returns a map of rule ID to count
func (s *VEXRuleService) CountMatchingVulnsForRules(tx shared.DB, rules []models.VEXRule) (map[string]int, error) {
	if len(rules) == 0 {
		return make(map[string]int), nil
	}

	result := make(map[string]int)
	assetID := rules[0].AssetID
	assetVersionName := rules[0].AssetVersionName

	vulns, err := s.dependencyVulnRepository.GetDependencyVulnsByAssetVersion(tx, assetVersionName, assetID, nil)

	vulnsByRule := matchRulesToVulns(rules, vulns)
	if err != nil {
		return nil, fmt.Errorf("failed to count matching vulns: %w", err)
	}

	for _, rule := range rules {
		rulePtr := &rule
		if vulns, ok := vulnsByRule[rulePtr]; ok {
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
		), nil

	case dtos.EventTypeAccepted:
		return models.NewCommentEvent(
			vuln.CalculateHash(),
			dtos.VulnTypeDependencyVuln,
			rule.CreatedByID,
			rule.Justification,
			true,
		), nil

	default:
		return models.VulnEvent{}, fmt.Errorf("unsupported event type from VEX rule: %s", rule.EventType)
	}
}

func (s *VEXRuleService) ApplyRulesToExisting(tx shared.DB, rules []models.VEXRule, vulns []models.DependencyVuln) ([]models.DependencyVuln, error) {
	vulnsByRule := matchRulesToVulns(rules, vulns)

	// Collect all vulns to update (deduplicated by ID)
	vulnMap := make(map[string]models.DependencyVuln)
	eventsByVuln := make(map[string][]models.VulnEvent)

	for rule, matchingVulns := range vulnsByRule {
		for _, vuln := range matchingVulns {
			ev, err := createVulnEventFromVEXRule(vuln, rule)
			if err != nil {
				slog.Error("failed to create event from VEX rule", "error", err, "cveID", rule.CVEID)
				continue
			}

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
	if err := s.dependencyVulnRepository.SaveBatchBestEffort(tx, updatedVulns); err != nil {
		return nil, fmt.Errorf("failed to save updated vulns: %w", err)
	}

	if err := s.vulnEventRepository.SaveBatchBestEffort(tx, allEvents); err != nil {
		return nil, fmt.Errorf("failed to save events: %w", err)
	}

	slog.Info("applied VEX rules to existing vulnerabilities",
		"rulesApplied", len(rules),
		"vulnsUpdated", len(updatedVulns),
		"eventsCreated", len(allEvents))
	return updatedVulns, nil
}

// ApplyRulesToExistingVulns applies multiple VEX rules to all existing vulnerabilities
// that match each rule's path pattern and CVE. This is more efficient than applying
// rules one by one as it batches database queries and saves.
func (s *VEXRuleService) ApplyRulesToExistingVulns(tx shared.DB, rules []models.VEXRule) ([]models.DependencyVuln, error) {
	if len(rules) == 0 {
		return nil, nil
	}
	// Find all vulns matching all rules at once
	vulns, err := s.dependencyVulnRepository.GetAllOpenVulnsByAssetVersionNameAndAssetID(tx, nil, rules[0].AssetVersionName, rules[0].AssetID)

	if err != nil {
		return nil, fmt.Errorf("failed to fetch existing vulns for asset: %w", err)
	}
	return s.ApplyRulesToExisting(tx, rules, vulns)
}

func isVexEventAlreadyApplied(vuln models.DependencyVuln, event models.VulnEvent) bool {
	for _, ev := range vuln.GetEvents() {
		if ev.Type == event.Type && ev.Justification == event.Justification {
			return true
		}
	}
	return false
}

func (s *VEXRuleService) IngestVexes(tx shared.DB, asset models.Asset, assetVersion models.AssetVersion, vexReports []*normalize.VexReport) error {
	// Collect all rules from all VEX reports to batch process them
	allAddedRules := make([]models.VEXRule, 0)

	// Rules are enabled if ParanoidMode is disabled
	enabled := !asset.ParanoidMode

	for _, vexReport := range vexReports {
		rules, err := s.parseVEXRulesInBOM(asset.ID, assetVersion.Name, vexReport)
		if err != nil {
			return fmt.Errorf("failed to parse VEX rules from SBOM (source %s): %w", vexReport.Source, err)
		}
		// Set Enabled on all rules based on ParanoidMode
		for i := range rules {
			rules[i].Enabled = enabled
		}
		addedRules, _, err := s.syncVEXRulesFromSource(tx, asset.ID, vexReport.Source, rules)
		if err != nil {
			return fmt.Errorf("failed to sync VEX rules from source %s: %w", vexReport.Source, err)
		}
		allAddedRules = append(allAddedRules, addedRules...)
	}

	// Apply all enabled rules to existing vulns in a single batch
	_, err := s.ApplyRulesToExistingVulns(tx, allAddedRules)
	return err
}

func (s *VEXRuleService) IngestVEX(tx shared.DB, asset models.Asset, assetVersion models.AssetVersion, vexReport *normalize.VexReport) error {
	rules, err := s.parseVEXRulesInBOM(asset.ID, assetVersion.Name, vexReport)
	if err != nil {
		return fmt.Errorf("failed to parse VEX rules from SBOM: %w", err)
	}

	// Rules are enabled if ParanoidMode is disabled
	enabled := !asset.ParanoidMode
	for i := range rules {
		rules[i].Enabled = enabled
	}

	addedRules, _, err := s.syncVEXRulesFromSource(tx, asset.ID, vexReport.Source, rules)
	if err != nil {
		return fmt.Errorf("failed to sync VEX rules from source: %w", err)
	}

	// Apply all enabled rules to existing vulns in a single batch
	_, err = s.ApplyRulesToExistingVulns(tx, addedRules)
	return err
}

func (s *VEXRuleService) parseVEXRulesInBOM(assetID uuid.UUID, assetVersionName string, report *normalize.VexReport) ([]models.VEXRule, error) {
	// we are only interested in the vulnerabilities
	bom := report.Report
	// for creating vex rules we need to find the starting path to the components
	// we ONLY USE METADATA COMPONENT FOR THAT
	if bom.Metadata == nil || bom.Metadata.Component == nil {
		slog.Info("no metadata component found in SBOM, skipping VEX rule creation")
		return nil, fmt.Errorf("no metadata component found in SBOM")
	}

	// try to parse the root component purl if it exists
	var componentPurl packageurl.PackageURL
	if bom.Metadata.Component.PackageURL == "" {
		return nil, fmt.Errorf("no package URL found in metadata component")
	}

	var err error
	componentPurl, err = packageurl.FromString(bom.Metadata.Component.PackageURL)
	if err != nil {
		slog.Info("failed to parse metadata component PURL, continuing anyway", "purl", bom.Metadata.Component.PackageURL, "error", err)
	}

	refToPurl := make(map[string]packageurl.PackageURL)

	if bom.Components == nil || len(*bom.Components) == 0 {
		return nil, fmt.Errorf("no components inside sbom")
	}
	// Build ref-to-purl mapping from components if they exist
	for _, comp := range *bom.Components {
		if comp.PackageURL == "" {
			continue
		}
		purl, err := packageurl.FromString(comp.PackageURL)
		if err != nil {
			slog.Info("failed to parse component PURL, skipping component for VEX rule creation", "purl", comp.PackageURL, "error", err)
			continue
		}
		refToPurl[comp.BOMRef] = purl
	}

	if bom.Vulnerabilities == nil {
		return nil, fmt.Errorf("no vulns inside sbom")
	}

	rules := make([]models.VEXRule, 0, len(*bom.Vulnerabilities))
	for _, vuln := range *bom.Vulnerabilities {
		cveID := extractCVE(vuln.ID)
		if cveID == "" && vuln.Source != nil && vuln.Source.URL != "" {
			cveID = extractCVE(vuln.Source.URL)
		}
		if cveID == "" {
			continue
		}

		eventType, err := mapCDXToEventType(vuln.Analysis)
		if err != nil {
			slog.Info("unable to map CycloneDX vulnerability analysis to event type, skipping VEX rule creation for this vuln", "cveID", cveID, "error", err)
			continue
		}

		justification := ""
		if vuln.Analysis != nil && vuln.Analysis.Detail != "" {
			justification = vuln.Analysis.Detail
		}

		if vuln.Affects == nil || len(*vuln.Affects) == 0 || (*vuln.Affects)[0].Ref == "" {
			continue
		}
		ref := (*vuln.Affects)[0].Ref

		// try to get the purl from the mapping first
		purl := refToPurl[ref]

		// if not found in mapping, try to parse the ref directly as a PURL
		if purl.String() == "" {
			parsedPurl, err := packageurl.FromString(ref)
			if err != nil {
				slog.Info("no component PURL found for vuln affect Ref and unable to parse as PURL, skipping VEX rule creation for this vuln", "ref", ref, "cveID", cveID, "error", err)
				continue
			}
			purl = parsedPurl
		}

		// now create the path pattern
		var pathPattern dtos.PathPattern
		if componentPurl.String() != "" {
			pathPattern = dtos.PathPattern{componentPurl.String(), dtos.PathPatternWildcard, purl.ToString()}
		} else {
			// If no metadata component PURL, use the affected package directly
			pathPattern = dtos.PathPattern{purl.ToString()}
		}

		rule := models.VEXRule{
			AssetID:          assetID,
			AssetVersionName: assetVersionName,
			CVEID:            cveID,
			VexSource:        report.Source,
			Justification:    justification,
			EventType:        eventType,
			PathPattern:      pathPattern,
			CreatedByID:      "system", // system user
		}
		rule.SetPathPattern(rule.PathPattern) // compute the hash
		rules = append(rules, rule)
	}

	return rules, nil
}

// SyncVEXRulesFromSource syncs VEX rules from a specific source.
// It fetches existing rules for the given asset and vexSource, compares them with
// the new rules, adds new ones and removes ones that no longer exist.
func (s *VEXRuleService) syncVEXRulesFromSource(tx shared.DB, assetID uuid.UUID, vexSource string, newRules []models.VEXRule) ([]models.VEXRule, []models.VEXRule, error) {
	// Fetch existing rules for this asset and vexSource
	existingRules, err := s.vexRuleRepository.FindByAssetAndVexSource(tx, assetID, vexSource)
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
		if err := s.vexRuleRepository.UpsertBatch(tx, rulesToAdd); err != nil {
			return nil, nil, fmt.Errorf("failed to add new VEX rules: %w", err)
		}
		slog.Info("added new VEX rules from source",
			"assetID", assetID,
			"vexSource", vexSource,
			"count", len(rulesToAdd))
	}

	// Remove old rules
	if len(rulesToRemove) > 0 {
		if err := s.vexRuleRepository.DeleteBatch(tx, rulesToRemove); err != nil {
			return nil, nil, fmt.Errorf("failed to remove old VEX rules: %w", err)
		}
		slog.Info("removed old VEX rules from source",
			"assetID", assetID,
			"vexSource", vexSource,
			"count", len(rulesToRemove))
	}

	return rulesToAdd, rulesToRemove, nil
}

// map CycloneDX Analysis State / Response to internal status strings used by CreateVulnEventAndApply
func mapCDXToVulnStatus(a *cdx.VulnerabilityAnalysis) string {
	if a == nil {
		return ""
	}
	switch a.State {
	case cdx.IASResolved:
		return "fixed"
	case cdx.IASFalsePositive:
		return "falsePositive"
	case cdx.IASExploitable:
		// check if wont fix
		if a.Response != nil {
			if slices.Contains(*a.Response, cdx.IARWillNotFix) {
				return "accepted"
			}
		}
		return "open"
	case cdx.IASInTriage:
		return "open"
	default:
		// fallback to response mapping if state is empty
		if a.Response != nil && len(*a.Response) > 0 {
			// take first response
			switch (*a.Response)[0] {
			case cdx.IARUpdate:
				return "fixed"
			case cdx.IARWillNotFix:
				return "accepted"
			default:
				return ""
			}
		}
		return ""
	}
}

func mapCDXToEventType(a *cdx.VulnerabilityAnalysis) (dtos.VulnEventType, error) {
	if a == nil {
		return "", fmt.Errorf("vulnerability analysis is nil")
	}
	switch a.State {
	case cdx.IASResolved:
		return dtos.EventTypeFixed, nil
	case cdx.IASFalsePositive:
		return dtos.EventTypeFalsePositive, nil
	case cdx.IASExploitable:
		// check if wont fix
		if a.Response != nil {
			if slices.Contains(*a.Response, cdx.IARWillNotFix) {
				return dtos.EventTypeAccepted, nil
			} else if slices.Contains(*a.Response, cdx.IARUpdate) {
				return dtos.EventTypeComment, nil
			}
		}
		return dtos.EventTypeDetected, nil
	case cdx.IASInTriage:
		return dtos.EventTypeDetected, nil
	case cdx.IASNotAffected:
		return dtos.EventTypeFalsePositive, nil

	default:
		// fallback to response mapping if state is empty
		if a.Response != nil && len(*a.Response) > 0 {
			// take first response
			switch (*a.Response)[0] {
			case cdx.IARWillNotFix:
				return dtos.EventTypeAccepted, nil
			default:
				return "", fmt.Errorf("unknown vulnerability analysis response: %s", (*a.Response)[0])
			}
		}
		return "", fmt.Errorf("unknown vulnerability analysis state: %s", a.State)
	}
}

// helper to extract cve id from CycloneDX vulnerability id or source url
func extractCVE(s string) string {
	if s == "" {
		return ""
	}
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "http") {
		parts := strings.Split(s, "/")
		return parts[len(parts)-1]
	}
	return s
}

func matchRulesToVulns(rules []models.VEXRule, vulns []models.DependencyVuln) map[*models.VEXRule][]models.DependencyVuln {
	result := make(map[*models.VEXRule][]models.DependencyVuln)
	// Filter by each rule's cve and path pattern - only match ENABLED rules
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		pattern := dtos.PathPattern(rule.PathPattern)
		var matched []models.DependencyVuln
		for _, vuln := range vulns {
			if vuln.CVEID == rule.CVEID && pattern.MatchesSuffix(vuln.VulnerabilityPath) {
				matched = append(matched, vuln)
			}
		}
		result[&rule] = matched
	}

	return result
}
