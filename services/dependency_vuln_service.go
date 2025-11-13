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
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/common"
	"github.com/l3montree-dev/devguard/monitoring"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/vulndb"

	"github.com/l3montree-dev/devguard/database/models"

	"github.com/l3montree-dev/devguard/utils"
)

type DependencyVulnService struct {
	dependencyVulnRepository shared.DependencyVulnRepository
	vulnEventRepository      shared.VulnEventRepository

	assetVersionRepository shared.AssetVersionRepository
	assetRepository        shared.AssetRepository
	cveRepository          shared.CveRepository
	projectRepository      shared.ProjectRepository
	organizationRepository shared.OrganizationRepository
	thirdPartyIntegration  shared.ThirdPartyIntegration
}

func NewDependencyVulnService(dependencyVulnRepository shared.DependencyVulnRepository, vulnEventRepository shared.VulnEventRepository, assetRepository shared.AssetRepository, cveRepository shared.CveRepository, orgRepository shared.OrganizationRepository, projectRepository shared.ProjectRepository, thirdPartyIntegration shared.ThirdPartyIntegration, assetVersionRepository shared.AssetVersionRepository) *DependencyVulnService {
	return &DependencyVulnService{
		dependencyVulnRepository: dependencyVulnRepository,
		vulnEventRepository:      vulnEventRepository,
		assetRepository:          assetRepository,
		cveRepository:            cveRepository,
		projectRepository:        projectRepository,
		organizationRepository:   orgRepository,
		thirdPartyIntegration:    thirdPartyIntegration,
		assetVersionRepository:   assetVersionRepository,
	}
}

func (s *DependencyVulnService) UserFixedDependencyVulns(tx shared.DB, userID string, dependencyVulns []models.DependencyVuln, assetVersion models.AssetVersion, asset models.Asset, upstream models.UpstreamState) error {
	if len(dependencyVulns) == 0 {
		return nil
	}

	// create a new VulnEvent for each fixed dependencyVuln
	events := make([]models.VulnEvent, len(dependencyVulns))

	for i, dependencyVuln := range dependencyVulns {
		ev := models.NewFixedEvent(dependencyVuln.CalculateHash(), models.VulnTypeDependencyVuln, userID, dependencyVuln.GetScannerIDsOrArtifactNames(), upstream)
		// apply the event on the dependencyVuln
		ev.Apply(&dependencyVulns[i])
		events[i] = ev
	}

	err := s.dependencyVulnRepository.SaveBatch(tx, dependencyVulns)
	if err != nil {
		return err
	}
	return s.vulnEventRepository.SaveBatch(tx, events)
}

func (s *DependencyVulnService) UserDetectedExistingVulnOnDifferentBranch(tx shared.DB, scannerID string, dependencyVulns []models.DependencyVuln, alreadyExistingEvents [][]models.VulnEvent, assetVersion models.AssetVersion, asset models.Asset) error {
	if len(dependencyVulns) == 0 {
		return nil
	}

	events := make([][]models.VulnEvent, len(dependencyVulns))

	for i, dependencyVuln := range dependencyVulns {
		// copy all events for this vulnerability
		if len(alreadyExistingEvents[i]) != 0 {
			events[i] = utils.Map(alreadyExistingEvents[i], func(el models.VulnEvent) models.VulnEvent {
				el.VulnID = dependencyVuln.CalculateHash()
				el.ID = uuid.Nil
				return el
			})
		}
		// replay all events on the dependencyVuln
		// but sort them by the time they were created ascending
		slices.SortStableFunc(events[i], func(a, b models.VulnEvent) int {
			if a.CreatedAt.Before(b.CreatedAt) {
				return -1
			} else if a.CreatedAt.After(b.CreatedAt) {
				return 1
			}
			return 0
		})
		for _, ev := range events[i] {
			ev.Apply(&dependencyVulns[i])
		}
	}

	err := s.dependencyVulnRepository.SaveBatch(tx, dependencyVulns)
	if err != nil {
		return err
	}

	return s.vulnEventRepository.SaveBatch(tx, utils.Flat(events))

}

func (s *DependencyVulnService) UserDetectedDependencyVulns(tx shared.DB, artifactName string, dependencyVulns []models.DependencyVuln, assetVersion models.AssetVersion, asset models.Asset, upstream models.UpstreamState) error {
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
		riskReport := vulndb.RawRisk(*dependencyVuln.CVE, e, *dependencyVuln.ComponentDepth)
		ev := models.NewDetectedEvent(dependencyVuln.CalculateHash(), models.VulnTypeDependencyVuln, "system", riskReport, artifactName, upstream)
		// apply the event on the dependencyVuln
		ev.Apply(&dependencyVulns[i])
		events[i] = ev
	}

	// run the updates in the transaction to keep a valid state
	err := s.dependencyVulnRepository.SaveBatch(tx, dependencyVulns)
	if err != nil {
		return err
	}
	return s.vulnEventRepository.SaveBatch(tx, events)
}

func (s *DependencyVulnService) RecalculateAllRawRiskAssessments() error {

	now := time.Now()
	slog.Info("recalculating all raw risk assessments", "time", now)

	userID := "system"
	justification := "System recalculated raw risk assessment"

	assetVersions, err := s.assetVersionRepository.All()
	if err != nil {
		return fmt.Errorf("could not get all assets: %v", err)
	}

	for _, assetVersion := range assetVersions {
		monitoring.RecalculateAllRawRiskAssessmentsAssetVersionsAmount.Inc()
		// get all dependencyVulns of the asset
		dependencyVulns, err := s.dependencyVulnRepository.GetDependencyVulnsByAssetVersion(nil, assetVersion.Name, assetVersion.AssetID, nil)
		if len(dependencyVulns) == 0 {
			continue
		}

		if err != nil {
			return fmt.Errorf("could not get all dependencyVulns by asset id: %v", err)
		}

		err = s.RecalculateRawRiskAssessment(nil, userID, dependencyVulns, justification, assetVersion.Asset)
		if err != nil {
			return fmt.Errorf("could not recalculate raw risk assessment: %v", err)
		}

		monitoring.RecalculateAllRawRiskAssessmentsAssetVersionsUpdatedAmount.Inc()
	}

	return nil

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

	err := s.dependencyVulnRepository.SaveBatch(tx, vulnerabilities)
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
	err := s.dependencyVulnRepository.SaveBatch(tx, vulnerabilities)
	if err != nil {
		return err
	}
	return nil
}

func (s *DependencyVulnService) RecalculateRawRiskAssessment(tx shared.DB, userID string, dependencyVulns []models.DependencyVuln, justification string, asset models.Asset) error {
	if len(dependencyVulns) == 0 {
		return nil
	}

	env := shared.Environmental{
		ConfidentialityRequirements: string(asset.ConfidentialityRequirement),
		IntegrityRequirements:       string(asset.IntegrityRequirement),
		AvailabilityRequirements:    string(asset.AvailabilityRequirement),
	}

	// create a new VulnEvent for each updated dependencyVuln

	events := make([]models.VulnEvent, 0)

	for i, dependencyVuln := range dependencyVulns {
		if dependencyVuln.CVEID == nil || dependencyVuln.CVE == nil {
			continue
		}

		oldRiskAssessment := dependencyVuln.RawRiskAssessment
		newRiskAssessment := vulndb.RawRisk(*dependencyVuln.CVE, env, *dependencyVuln.ComponentDepth)

		if oldRiskAssessment == nil || *oldRiskAssessment != newRiskAssessment.Risk {
			ev := models.NewRawRiskAssessmentUpdatedEvent(dependencyVuln.CalculateHash(), models.VulnTypeDependencyVuln, userID, justification, oldRiskAssessment, newRiskAssessment)
			// apply the event on the dependencyVuln
			ev.Apply(&dependencyVulns[i])
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
			if err := s.dependencyVulnRepository.SaveBatch(tx, dependencyVulns); err != nil {
				return fmt.Errorf("could not save dependencyVulns: %v", err)
			}
			if err := s.vulnEventRepository.SaveBatch(tx, events); err != nil {
				return fmt.Errorf("could not save events: %v", err)
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("could not recalculate raw risk assessment: %v", err)
		}
		return nil
	}

	err := s.dependencyVulnRepository.SaveBatch(tx, dependencyVulns)
	if err != nil {
		return fmt.Errorf("could not save dependencyVulns: %v", err)
	}

	err = s.vulnEventRepository.SaveBatch(tx, events)
	if err != nil {
		return fmt.Errorf("could not save events: %v", err)
	}
	return nil
}

func (s *DependencyVulnService) CreateVulnEventAndApply(tx shared.DB, assetID uuid.UUID, userID string, dependencyVuln *models.DependencyVuln, vulnEventType models.VulnEventType, justification string, mechanicalJustification models.MechanicalJustificationType, assetVersionName string, upstream models.UpstreamState) (models.VulnEvent, error) {
	if tx == nil {
		var ev models.VulnEvent
		var err error
		// we are not part of a parent transaction - create a new one
		err = s.dependencyVulnRepository.Transaction(func(d shared.DB) error {
			ev, err = s.createVulnEventAndApply(tx, userID, dependencyVuln, vulnEventType, justification, mechanicalJustification, upstream)
			return err
		})
		return ev, err
	}
	return s.createVulnEventAndApply(tx, userID, dependencyVuln, vulnEventType, justification, mechanicalJustification, upstream)
}

func (s *DependencyVulnService) createVulnEventAndApply(tx shared.DB, userID string, dependencyVuln *models.DependencyVuln, vulnEventType models.VulnEventType, justification string, mechanicalJustification models.MechanicalJustificationType, upstream models.UpstreamState) (models.VulnEvent, error) {
	var ev models.VulnEvent
	switch vulnEventType {
	case models.EventTypeAccepted:
		ev = models.NewAcceptedEvent(dependencyVuln.CalculateHash(), models.VulnTypeDependencyVuln, userID, justification, upstream)
	case models.EventTypeFalsePositive:
		ev = models.NewFalsePositiveEvent(dependencyVuln.CalculateHash(), models.VulnTypeDependencyVuln, userID, justification, mechanicalJustification, dependencyVuln.GetScannerIDsOrArtifactNames(), upstream)
	case models.EventTypeDetected:
		ev = models.NewDetectedEvent(dependencyVuln.CalculateHash(), models.VulnTypeDependencyVuln, userID, common.RiskCalculationReport{}, "", upstream)
	case models.EventTypeReopened:
		ev = models.NewReopenedEvent(dependencyVuln.CalculateHash(), models.VulnTypeDependencyVuln, userID, justification, upstream)
	case models.EventTypeComment:
		ev = models.NewCommentEvent(dependencyVuln.CalculateHash(), models.VulnTypeDependencyVuln, userID, justification)
	}

	err := s.dependencyVulnRepository.ApplyAndSave(tx, dependencyVuln, &ev)
	return ev, err
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

	return s.SyncIssues(org, project, asset, assetVersion, vulnList)
}

func (s *DependencyVulnService) SyncIssues(org models.Org, project models.Project, asset models.Asset, assetVersion models.AssetVersion, vulnList []models.DependencyVuln) error {
	errgroup := utils.ErrGroup[any](10)
	for _, vulnerability := range vulnList {
		if vulnerability.TicketID == nil {
			// ask if we should create an issue AFTER checking if a ticket already exists - this way, we keep manually created tickets up to date.
			if !ShouldCreateIssues(assetVersion) || !ShouldCreateThisIssue(asset, &vulnerability) {
				continue
			}
			errgroup.Go(func() (any, error) {
				return s.createIssue(vulnerability, asset, assetVersion.Slug, org.Slug, project.Slug, "Risk exceeds predefined threshold", "system"), nil
			})
		} else {
			errgroup.Go(func() (any, error) {
				return s.updateIssue(asset, assetVersion.Slug, vulnerability), nil
			})
		}
	}

	_, err := errgroup.WaitAndCollect()
	return err
}

// function to remove duplicate code from the different cases of the createIssuesForVulns function
func (s *DependencyVulnService) createIssue(vulnerability models.DependencyVulnService, asset models.Asset, assetVersionSlug string, orgSlug string, projectSlug string, justification string, userID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return s.thirdPartyIntegration.CreateIssue(ctx, asset, assetVersionSlug, &vulnerability, projectSlug, orgSlug, justification, userID)
}

func (s *DependencyVulnService) updateIssue(asset models.Asset, assetVersionSlug string, vulnerability models.DependencyVulnService) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := s.thirdPartyIntegration.UpdateIssue(ctx, asset, assetVersionSlug, &vulnerability)
	if err != nil {
		return err
	}
	monitoring.TicketUpdatedAmount.Inc()
	return nil
}
