// Copyright (C) 2024 Tim Bastin, l3montree GmbH
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
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/integrations/commonint"
	"github.com/l3montree-dev/devguard/monitoring"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/statemachine"
	"github.com/l3montree-dev/devguard/vulndb"

	"github.com/l3montree-dev/devguard/database/models"

	"github.com/l3montree-dev/devguard/utils"
)

type DependencyVulnService struct {
	dependencyVulnRepository    shared.DependencyVulnRepository
	vulnEventRepository         shared.VulnEventRepository
	falsePositiveRuleRepository shared.FalsePositiveRuleRepository

	thirdPartyIntegration shared.IntegrationAggregate
}

func NewDependencyVulnService(dependencyVulnRepository shared.DependencyVulnRepository, vulnEventRepository shared.VulnEventRepository, falsePositiveRuleRepository shared.FalsePositiveRuleRepository, thirdPartyIntegration shared.IntegrationAggregate) *DependencyVulnService {
	return &DependencyVulnService{
		dependencyVulnRepository:    dependencyVulnRepository,
		vulnEventRepository:         vulnEventRepository,
		falsePositiveRuleRepository: falsePositiveRuleRepository,
		thirdPartyIntegration:       thirdPartyIntegration,
	}
}

func (s *DependencyVulnService) UserFixedDependencyVulns(tx shared.DB, userID string, dependencyVulns []models.DependencyVuln, assetVersion models.AssetVersion, asset models.Asset, upstream dtos.UpstreamState) error {
	if len(dependencyVulns) == 0 {
		return nil
	}

	// create a new VulnEvent for each fixed dependencyVuln
	events := make([]models.VulnEvent, len(dependencyVulns))

	for i, dependencyVuln := range dependencyVulns {
		ev := models.NewFixedEvent(dependencyVuln.CalculateHash(), dtos.VulnTypeDependencyVuln, userID, dependencyVuln.GetScannerIDsOrArtifactNames(), upstream)
		// apply the event on the dependencyVuln
		statemachine.Apply(&dependencyVulns[i], ev)
		events[i] = ev
	}

	err := s.dependencyVulnRepository.SaveBatchBestEffort(tx, dependencyVulns)
	if err != nil {
		return err
	}
	return s.vulnEventRepository.SaveBatchBestEffort(tx, events)
}

func (s *DependencyVulnService) UserDetectedExistingVulnOnDifferentBranch(tx shared.DB, scannerID string, dependencyVulns []statemachine.BranchVulnMatch[*models.DependencyVuln], assetVersion models.AssetVersion, asset models.Asset) error {
	if len(dependencyVulns) == 0 {
		return nil
	}

	vulns := utils.Map(dependencyVulns, func(el statemachine.BranchVulnMatch[*models.DependencyVuln]) models.DependencyVuln {
		return *el.CurrentBranchVuln
	})

	events := utils.Map(dependencyVulns, func(el statemachine.BranchVulnMatch[*models.DependencyVuln]) []models.VulnEvent {
		return el.EventsToCopy
	})

	err := s.dependencyVulnRepository.SaveBatchBestEffort(tx, vulns)
	if err != nil {
		return err
	}

	return s.vulnEventRepository.SaveBatchBestEffort(tx, utils.Flat(events))
}

func (s *DependencyVulnService) UserDetectedDependencyVulns(tx shared.DB, artifactName string, dependencyVulns []models.DependencyVuln, assetVersion models.AssetVersion, asset models.Asset, upstream dtos.UpstreamState) error {
	if len(dependencyVulns) == 0 {
		return nil
	}

	// create a new VulnEvent for each detected dependencyVuln
	events := make([]models.VulnEvent, len(dependencyVulns))
	e := shared.Environmental{
		ConfidentialityRequirements: string(asset.ConfidentialityRequirement),
		IntegrityRequirements:       string(asset.IntegrityRequirement),
		AvailabilityRequirements:    string(asset.AvailabilityRequirement),
	}

	for i, dependencyVuln := range dependencyVulns {
		depth := max(len(dependencyVuln.VulnerabilityPath), 1)
		riskReport := vulndb.RawRisk(dependencyVuln.CVE, e, depth)
		ev := models.NewDetectedEvent(dependencyVuln.CalculateHash(), dtos.VulnTypeDependencyVuln, "system", riskReport, artifactName, upstream)
		// apply the event on the dependencyVuln
		statemachine.Apply(&dependencyVulns[i], ev)
		events[i] = ev
	}

	// run the updates in the transaction to keep a valid state
	err := s.dependencyVulnRepository.SaveBatchBestEffort(tx, dependencyVulns)
	if err != nil {
		return err
	}
	err = s.vulnEventRepository.SaveBatchBestEffort(tx, events)
	if err != nil {
		return err
	}

	// Apply existing false positive rules to newly detected vulns
	s.applyFalsePositiveRulesToNewVulns(tx, asset.ID, dependencyVulns)

	return nil
}

// applyFalsePositiveRulesToNewVulns checks existing false positive rules and applies
// them to newly detected vulnerabilities that match the path pattern.
func (s *DependencyVulnService) applyFalsePositiveRulesToNewVulns(tx shared.DB, assetID uuid.UUID, vulns []models.DependencyVuln) {
	// Get existing false positive rules for this asset
	rules, err := s.falsePositiveRuleRepository.FindByAssetID(tx, assetID)
	if err != nil {
		slog.Error("could not get false positive rules", "err", err, "assetID", assetID)
		return
	}

	if len(rules) == 0 {
		return
	}

	for i := range vulns {
		vuln := &vulns[i]

		// Skip if already false positive
		if vuln.State == dtos.VulnStateFalsePositive {
			continue
		}

		// Check each rule
		for _, rule := range rules {
			if len(rule.PathPattern) == 0 {
				continue
			}

			// Skip if CVE doesn't match
			if vuln.CVEID != rule.CVEID {
				continue
			}

			if pathPatternMatches(vuln.VulnerabilityPath, rule.PathPattern) {
				// Apply the rule
				ev := models.NewFalsePositiveEvent(
					vuln.CalculateHash(),
					dtos.VulnTypeDependencyVuln,
					rule.CreatedByID,
					rule.Justification,
					rule.MechanicalJustification,
					vuln.GetScannerIDsOrArtifactNames(),
					dtos.UpstreamStateInternal,
				)

				if err := s.dependencyVulnRepository.ApplyAndSave(tx, vuln, &ev); err != nil {
					slog.Error("could not apply false positive rule to new vuln", "err", err, "vulnID", vuln.ID)
				} else {
					slog.Info("applied false positive rule to new vuln", "vulnID", vuln.ID, "rulePattern", rule.PathPattern)
				}
				break // Only apply first matching rule
			}
		}
	}
}

// pathPatternMatches checks if a vulnerability path matches the given pattern.
func pathPatternMatches(vulnPath []string, pattern []string) bool {
	if len(pattern) == 0 || len(vulnPath) < len(pattern) {
		return false
	}

	// Check if the suffix matches
	startIdx := len(vulnPath) - len(pattern)
	for i, elem := range pattern {
		if vulnPath[startIdx+i] != elem {
			return false
		}
	}

	return true
}

func (s *DependencyVulnService) UserDetectedDependencyVulnInAnotherArtifact(tx shared.DB, vulnerabilities []models.DependencyVuln, scannerID string) error {
	if len(vulnerabilities) == 0 {
		return nil
	}

	for i := range vulnerabilities {
		alreadyAssociated := false
		for _, a := range vulnerabilities[i].Artifacts {
			if a.ArtifactName == scannerID {
				alreadyAssociated = true
				break
			}
		}
		if !alreadyAssociated {
			vulnerabilities[i].Artifacts = append(vulnerabilities[i].Artifacts, models.Artifact{
				ArtifactName:     scannerID,
				AssetVersionName: vulnerabilities[i].AssetVersionName,
				AssetID:          vulnerabilities[i].AssetID,
			})
			if err := tx.Exec("INSERT INTO artifact_dependency_vulns (artifact_artifact_name, artifact_asset_version_name, artifact_asset_id, dependency_vuln_id) VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING",
				scannerID, vulnerabilities[i].AssetVersionName, vulnerabilities[i].AssetID, vulnerabilities[i].CalculateHash()).Error; err != nil {
				return err
			}
		}
	}

	err := s.dependencyVulnRepository.SaveBatchBestEffort(tx, vulnerabilities)
	if err != nil {
		return err
	}
	return nil
}

func (s *DependencyVulnService) UserDidNotDetectDependencyVulnInArtifactAnymore(tx shared.DB, vulnerabilities []models.DependencyVuln, scannerID string) error {
	if len(vulnerabilities) == 0 {
		return nil
	}

	for i := range vulnerabilities {
		filtered := make([]models.Artifact, 0, len(vulnerabilities[i].Artifacts))
		for _, a := range vulnerabilities[i].Artifacts {
			if a.ArtifactName != scannerID {
				filtered = append(filtered, a)
			}
		}
		vulnerabilities[i].Artifacts = filtered
		if err := tx.Exec("DELETE FROM artifact_dependency_vulns WHERE dependency_vuln_id = ? AND artifact_artifact_name = ? AND artifact_asset_version_name = ? AND artifact_asset_id = ?",
			vulnerabilities[i].CalculateHash(), scannerID, vulnerabilities[i].AssetVersionName, vulnerabilities[i].AssetID).Error; err != nil {
			return err
		}
	}
	err := s.dependencyVulnRepository.SaveBatchBestEffort(tx, vulnerabilities)
	if err != nil {
		return err
	}
	return nil
}

func (s *DependencyVulnService) RecalculateRawRiskAssessment(tx shared.DB, userID string, dependencyVulns []models.DependencyVuln, justification string, asset models.Asset) ([]models.DependencyVuln, error) {
	if len(dependencyVulns) == 0 {
		return nil, nil
	}

	env := shared.Environmental{
		ConfidentialityRequirements: string(asset.ConfidentialityRequirement),
		IntegrityRequirements:       string(asset.IntegrityRequirement),
		AvailabilityRequirements:    string(asset.AvailabilityRequirement),
	}

	// create a new VulnEvent for each updated dependencyVuln

	events := make([]models.VulnEvent, 0)

	for i, dependencyVuln := range dependencyVulns {
		oldRiskAssessment := dependencyVuln.RawRiskAssessment
		depth := max(len(dependencyVuln.VulnerabilityPath), 1)
		newRiskAssessment := vulndb.RawRisk(dependencyVuln.CVE, env, depth)

		if oldRiskAssessment == nil || *oldRiskAssessment != newRiskAssessment.Risk {
			ev := models.NewRawRiskAssessmentUpdatedEvent(dependencyVuln.CalculateHash(), dtos.VulnTypeDependencyVuln, userID, justification, oldRiskAssessment, newRiskAssessment)
			// apply the event on the dependencyVuln
			statemachine.Apply(&dependencyVulns[i], ev)
			events = append(events, ev)
		} else {
			// only update the last calculated time
			dependencyVulns[i].RiskRecalculatedAt = time.Now()
		}
	}

	// saving the dependencyVulns and the events HAS to be done in the same transaction
	// it is crucial to maintain a consistent audit log of events
	if tx == nil {
		err := s.dependencyVulnRepository.Transaction(func(tx shared.DB) error {
			if err := s.dependencyVulnRepository.SaveBatchBestEffort(tx, dependencyVulns); err != nil {
				return fmt.Errorf("could not save dependencyVulns: %v", err)
			}
			if err := s.vulnEventRepository.SaveBatchBestEffort(tx, events); err != nil {
				return fmt.Errorf("could not save events: %v", err)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("could not recalculate raw risk assessment: %v", err)
		}
		return dependencyVulns, nil
	}

	err := s.dependencyVulnRepository.SaveBatchBestEffort(tx, dependencyVulns)
	if err != nil {
		return nil, fmt.Errorf("could not save dependencyVulns: %v", err)
	}

	err = s.vulnEventRepository.SaveBatchBestEffort(tx, events)
	if err != nil {
		return nil, fmt.Errorf("could not save events: %v", err)
	}
	return dependencyVulns, nil
}

func (s *DependencyVulnService) CreateVulnEventAndApply(tx shared.DB, assetID uuid.UUID, userID string, dependencyVuln *models.DependencyVuln, vulnEventType dtos.VulnEventType, justification string, mechanicalJustification dtos.MechanicalJustificationType, assetVersionName string, upstream dtos.UpstreamState) (models.VulnEvent, error) {
	if tx == nil {
		var ev models.VulnEvent
		var err error
		// we are not part of a parent transaction - create a new one
		err = s.dependencyVulnRepository.Transaction(func(d shared.DB) error {
			ev, err = s.createVulnEventAndApply(d, assetID, userID, dependencyVuln, vulnEventType, justification, mechanicalJustification, upstream)
			return err
		})
		return ev, err
	}
	return s.createVulnEventAndApply(tx, assetID, userID, dependencyVuln, vulnEventType, justification, mechanicalJustification, upstream)
}

func (s *DependencyVulnService) createVulnEventAndApply(tx shared.DB, assetID uuid.UUID, userID string, dependencyVuln *models.DependencyVuln, vulnEventType dtos.VulnEventType, justification string, mechanicalJustification dtos.MechanicalJustificationType, upstream dtos.UpstreamState) (models.VulnEvent, error) {
	var ev models.VulnEvent
	switch vulnEventType {
	case dtos.EventTypeAccepted:
		ev = models.NewAcceptedEvent(dependencyVuln.CalculateHash(), dtos.VulnTypeDependencyVuln, userID, justification, upstream)
	case dtos.EventTypeFalsePositive:
		ev = models.NewFalsePositiveEvent(dependencyVuln.CalculateHash(), dtos.VulnTypeDependencyVuln, userID, justification, mechanicalJustification, dependencyVuln.GetScannerIDsOrArtifactNames(), upstream)
	case dtos.EventTypeDetected:
		ev = models.NewDetectedEvent(dependencyVuln.CalculateHash(), dtos.VulnTypeDependencyVuln, userID, dtos.RiskCalculationReport{
			Risk: utils.OrDefault(dependencyVuln.RawRiskAssessment, 0),
		}, "", upstream)
	case dtos.EventTypeReopened:
		ev = models.NewReopenedEvent(dependencyVuln.CalculateHash(), dtos.VulnTypeDependencyVuln, userID, justification, upstream)
	case dtos.EventTypeComment:
		ev = models.NewCommentEvent(dependencyVuln.CalculateHash(), dtos.VulnTypeDependencyVuln, userID, justification, upstream)
	case dtos.EventTypeFixed:
		ev = models.NewFixedEvent(dependencyVuln.CalculateHash(), dtos.VulnTypeDependencyVuln, userID, dependencyVuln.GetScannerIDsOrArtifactNames(), upstream)
	}

	// Apply the event to the original vuln
	err := s.dependencyVulnRepository.ApplyAndSave(tx, dependencyVuln, &ev)
	if err != nil {
		return ev, err
	}

	return ev, nil
}

func (s *DependencyVulnService) SyncAllIssues(org models.Org, project models.Project, asset models.Asset, assetVersion models.AssetVersion) error {
	// get all dependencyVulns for the assetVersion
	vulnList, err := s.dependencyVulnRepository.GetDependencyVulnsByAssetVersion(nil, assetVersion.Name, asset.ID, nil)
	if err != nil {
		return fmt.Errorf("could not get dependencyVulns by asset version: %w", err)
	}

	if len(vulnList) == 0 {
		slog.Info("no dependency vulnerabilities found for asset version", "assetVersionName", assetVersion.Name)
		return nil
	}

	// Check for duplicate vulnerability IDs in the list
	seen := make(map[string]int)
	for _, vuln := range vulnList {
		seen[vuln.ID]++
	}
	for id, count := range seen {
		if count > 1 {
			slog.Warn("duplicate vulnerability detected in vulnList", "vulnID", id, "count", count, "assetVersion", assetVersion.Name)
		}
	}

	return s.SyncIssues(org, project, asset, assetVersion, vulnList)
}

func (s *DependencyVulnService) SyncIssues(org models.Org, project models.Project, asset models.Asset, assetVersion models.AssetVersion, vulnList []models.DependencyVuln) error {
	// Deduplicate vulnerabilities by ID to prevent creating multiple tickets
	vulnMap := make(map[string]models.DependencyVuln)
	for _, vuln := range vulnList {
		if _, exists := vulnMap[vuln.ID]; !exists {
			vulnMap[vuln.ID] = vuln
		}
	}

	errgroup := utils.ErrGroup[any](10)
	for _, vulnerability := range vulnMap {
		if vulnerability.TicketID == nil {
			// ask if we should create an issue AFTER checking if a ticket already exists - this way, we keep manually created tickets up to date.
			if !commonint.ShouldCreateIssues(assetVersion) || !commonint.ShouldCreateThisIssue(asset, &vulnerability) {
				continue
			}
			errgroup.Go(func() (any, error) {
				err := s.createIssue(vulnerability, asset, assetVersion.Slug, org.Slug, project.Slug, "Risk exceeds predefined threshold", "system")
				return nil, err
			})
		} else {
			errgroup.Go(func() (any, error) {
				err := s.updateIssue(asset, assetVersion.Slug, vulnerability)
				return nil, err
			})
		}
	}

	_, err := errgroup.WaitAndCollect()
	return err
}

// function to remove duplicate code from the different cases of the createIssuesForVulns function
func (s *DependencyVulnService) createIssue(vulnerability models.DependencyVuln, asset models.Asset, assetVersionSlug string, orgSlug string, projectSlug string, justification string, userID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return s.thirdPartyIntegration.CreateIssue(ctx, asset, assetVersionSlug, &vulnerability, projectSlug, orgSlug, justification, userID)
}

func (s *DependencyVulnService) updateIssue(asset models.Asset, assetVersionSlug string, vulnerability models.DependencyVuln) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := s.thirdPartyIntegration.UpdateIssue(ctx, asset, assetVersionSlug, &vulnerability)
	if err != nil {
		return err
	}
	monitoring.TicketUpdatedAmount.Inc()
	return nil
}
