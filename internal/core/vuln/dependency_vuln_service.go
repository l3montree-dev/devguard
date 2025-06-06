// Copyright (C) 2024 Tim Bastin, l3montree UG (haftungsbeschränkt)
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

package vuln

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/monitoring"

	"github.com/l3montree-dev/devguard/internal/core/risk"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
)

type service struct {
	dependencyVulnRepository core.DependencyVulnRepository
	vulnEventRepository      core.VulnEventRepository

	assetVersionRepository core.AssetVersionRepository
	assetRepository        core.AssetRepository
	cveRepository          core.CveRepository
	projectRepository      core.ProjectRepository
	organizationRepository core.OrganizationRepository
	thirdPartyIntegration  core.ThirdPartyIntegration
}

func NewService(dependencyVulnRepository core.DependencyVulnRepository, vulnEventRepository core.VulnEventRepository, assetRepository core.AssetRepository, cveRepository core.CveRepository, orgRepository core.OrganizationRepository, projectRepository core.ProjectRepository, thirdPartyIntegration core.ThirdPartyIntegration, assetVersionRepository core.AssetVersionRepository) *service {
	return &service{
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

func (s *service) UserFixedDependencyVulns(tx core.DB, userID string, dependencyVulns []models.DependencyVuln, assetVersion models.AssetVersion, asset models.Asset) error {
	if len(dependencyVulns) == 0 {
		return nil
	}

	// create a new VulnEvent for each fixed dependencyVuln
	events := make([]models.VulnEvent, len(dependencyVulns))

	for i, dependencyVuln := range dependencyVulns {
		ev := models.NewFixedEvent(dependencyVuln.CalculateHash(), models.VulnTypeDependencyVuln, userID, dependencyVuln.ScannerIDs)
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

func (s *service) UserDetectedExistingVulnOnDifferentBranch(tx core.DB, userID, scannerID string, dependencyVulns []models.DependencyVuln, alreadyExistingEvents [][]models.VulnEvent, assetVersion models.AssetVersion, asset models.Asset) error {
	if len(dependencyVulns) == 0 {
		return nil
	}

	e := core.Environmental{
		ConfidentialityRequirements: string(asset.ConfidentialityRequirement),
		IntegrityRequirements:       string(asset.IntegrityRequirement),
		AvailabilityRequirements:    string(asset.AvailabilityRequirement),
	}

	events := make([][]models.VulnEvent, len(dependencyVulns))

	for i, dependencyVuln := range dependencyVulns {
		// copy all events for this vulnerability
		if len(alreadyExistingEvents[i]) != 0 {
			events[i] = utils.Map(utils.Filter(alreadyExistingEvents[i], func(ev models.VulnEvent) bool {
				return ev.IsScanUnreleatedEvent()
			}), func(el models.VulnEvent) models.VulnEvent {
				el.VulnID = dependencyVuln.CalculateHash()
				return el
			})
		}
		riskReport := risk.RawRisk(*dependencyVuln.CVE, e, *dependencyVuln.ComponentDepth)
		ev := models.NewDetectedOnAnotherBranchEvent(dependencyVuln.CalculateHash(), models.VulnTypeDependencyVuln, userID, riskReport, scannerID, assetVersion.Name)
		events[i] = append(events[i], ev)
		// replay all events on the dependencyVuln
		for _, ev := range alreadyExistingEvents[i] {
			ev.Apply(&dependencyVulns[i])
		}
	}

	err := s.dependencyVulnRepository.SaveBatch(tx, dependencyVulns)
	if err != nil {
		return err
	}

	return s.vulnEventRepository.SaveBatch(tx, utils.Flat(events))

}

func (s *service) UserDetectedDependencyVulns(tx core.DB, userID, scannerID string, dependencyVulns []models.DependencyVuln, assetVersion models.AssetVersion, asset models.Asset) error {
	if len(dependencyVulns) == 0 {
		return nil
	}

	// create a new VulnEvent for each detected dependencyVuln
	events := make([]models.VulnEvent, len(dependencyVulns))
	e := core.Environmental{
		ConfidentialityRequirements: string(asset.ConfidentialityRequirement),
		IntegrityRequirements:       string(asset.IntegrityRequirement),
		AvailabilityRequirements:    string(asset.AvailabilityRequirement),
	}

	for i, dependencyVuln := range dependencyVulns {
		riskReport := risk.RawRisk(*dependencyVuln.CVE, e, *dependencyVuln.ComponentDepth)
		ev := models.NewDetectedEvent(dependencyVuln.CalculateHash(), models.VulnTypeDependencyVuln, userID, riskReport, scannerID)
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

func (s *service) RecalculateAllRawRiskAssessments() error {

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
		dependencyVulns, err := s.dependencyVulnRepository.GetDependencyVulnsByAssetVersion(nil, assetVersion.Name, assetVersion.AssetID, "")
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

func (s *service) UserDetectedDependencyVulnWithAnotherScanner(tx core.DB, vulnerabilities []models.DependencyVuln, userID string, scannerID string) error {
	if len(vulnerabilities) == 0 {
		return nil
	}

	// create a new VulnEvent for each fixed dependencyVuln
	events := make([]models.VulnEvent, len(vulnerabilities))

	for i := range vulnerabilities {
		ev := models.NewAddedScannerEvent(vulnerabilities[i].CalculateHash(), models.VulnTypeDependencyVuln, userID, scannerID)
		ev.Apply(&vulnerabilities[i])
		events[i] = ev
	}

	err := s.dependencyVulnRepository.SaveBatch(tx, vulnerabilities)
	if err != nil {
		return err
	}

	return s.vulnEventRepository.SaveBatch(tx, events)

}

func (s *service) UserDidNotDetectDependencyVulnWithScannerAnymore(tx core.DB, vulnerabilities []models.DependencyVuln, userID string, scannerID string) error {
	if len(vulnerabilities) == 0 {
		return nil
	}

	events := make([]models.VulnEvent, len(vulnerabilities))
	for i := range vulnerabilities {
		ev := models.NewRemovedScannerEvent(vulnerabilities[i].CalculateHash(), models.VulnTypeDependencyVuln, userID, scannerID)
		ev.Apply(&vulnerabilities[i])
		events[i] = ev
	}
	err := s.dependencyVulnRepository.SaveBatch(tx, vulnerabilities)
	if err != nil {
		return err
	}
	// save the events
	return s.vulnEventRepository.SaveBatch(tx, events)
}

func (s *service) RecalculateRawRiskAssessment(tx core.DB, userID string, dependencyVulns []models.DependencyVuln, justification string, asset models.Asset) error {
	if len(dependencyVulns) == 0 {
		return nil
	}

	env := core.Environmental{
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
		newRiskAssessment := risk.RawRisk(*dependencyVuln.CVE, env, *dependencyVuln.ComponentDepth)

		if *oldRiskAssessment != newRiskAssessment.Risk {
			ev := models.NewRawRiskAssessmentUpdatedEvent(dependencyVuln.CalculateHash(), models.VulnTypeDependencyVuln, userID, justification, oldRiskAssessment, newRiskAssessment)
			// apply the event on the dependencyVuln
			ev.Apply(&dependencyVulns[i])
			events = append(events, ev)

			slog.Info("recalculated raw risk assessment", "cve", dependencyVuln.CVE)

		} else {
			// only update the last calculated time
			dependencyVulns[i].RiskRecalculatedAt = time.Now()
		}
	}

	// saving the dependencyVulns and the events HAS to be done in the same transaction
	// it is crucial to maintain a consistent audit log of events
	if tx == nil {
		err := s.dependencyVulnRepository.Transaction(func(tx core.DB) error {
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

func (s *service) UpdateDependencyVulnState(tx core.DB, assetID uuid.UUID, userID string, dependencyVuln *models.DependencyVuln, statusType string, justification string, mechanicalJustification models.MechanicalJustificationType, assetVersionName string) (models.VulnEvent, error) {
	if tx == nil {

		var ev models.VulnEvent
		var err error
		// we are not part of a parent transaction - create a new one
		err = s.dependencyVulnRepository.Transaction(func(d core.DB) error {
			ev, err = s.updateDependencyVulnState(tx, userID, dependencyVuln, statusType, justification, mechanicalJustification)
			return err
		})
		return ev, err
	}
	return s.updateDependencyVulnState(tx, userID, dependencyVuln, statusType, justification, mechanicalJustification)
}

func (s *service) updateDependencyVulnState(tx core.DB, userID string, dependencyVuln *models.DependencyVuln, statusType string, justification string, mechanicalJustification models.MechanicalJustificationType) (models.VulnEvent, error) {
	var ev models.VulnEvent
	switch models.VulnEventType(statusType) {
	case models.EventTypeAccepted:
		ev = models.NewAcceptedEvent(dependencyVuln.CalculateHash(), models.VulnTypeDependencyVuln, userID, justification)
	case models.EventTypeFalsePositive:
		ev = models.NewFalsePositiveEvent(dependencyVuln.CalculateHash(), models.VulnTypeDependencyVuln, userID, justification, mechanicalJustification, dependencyVuln.ScannerIDs)
	case models.EventTypeReopened:
		ev = models.NewReopenedEvent(dependencyVuln.CalculateHash(), models.VulnTypeDependencyVuln, userID, justification)
	case models.EventTypeComment:
		ev = models.NewCommentEvent(dependencyVuln.CalculateHash(), models.VulnTypeDependencyVuln, userID, justification)
	}

	err := s.dependencyVulnRepository.ApplyAndSave(tx, dependencyVuln, &ev)
	return ev, err
}

func (s *service) SyncAllIssues(org models.Org, project models.Project, asset models.Asset, assetVersion models.AssetVersion) error {
	// get all dependencyVulns for the assetVersion
	vulnList, err := s.dependencyVulnRepository.GetDependencyVulnsByAssetVersion(nil, assetVersion.Name, asset.ID, "")
	if err != nil {
		return fmt.Errorf("could not get dependencyVulns by asset version: %w", err)
	}

	if len(vulnList) == 0 {
		slog.Info("no dependency vulnerabilities found for asset version", "assetVersionName", assetVersion.Name)
		return nil
	}

	return s.SyncIssues(org, project, asset, assetVersion, vulnList)
}

func (s *service) SyncIssues(org models.Org, project models.Project, asset models.Asset, assetVersion models.AssetVersion, vulnList []models.DependencyVuln) error {
	errgroup := utils.ErrGroup[any](10)
	for _, vulnerability := range vulnList {
		if vulnerability.TicketID == nil {
			// ask if we should create an issue AFTER checking if a ticket already exists - this way, we keep manually created tickets up to date.
			if !ShouldCreateIssues(assetVersion) || !ShouldCreateThisIssue(asset, &vulnerability) {
				continue
			}
			errgroup.Go(func() (any, error) {
				return s.createIssue(vulnerability, asset, assetVersion.Name, org.Slug, project.Slug, "Risk exceeds predefined threshold", "system"), nil
			})
		} else {
			errgroup.Go(func() (any, error) {
				return s.updateIssue(asset, vulnerability), nil
			})
		}
	}

	_, err := errgroup.WaitAndCollect()
	return err
}

// function to remove duplicate code from the different cases of the createIssuesForVulns function
func (s *service) createIssue(vulnerability models.DependencyVuln, asset models.Asset, assetVersionName string, orgSlug string, projectSlug string, justification string, userID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return s.thirdPartyIntegration.CreateIssue(ctx, asset, assetVersionName, &vulnerability, projectSlug, orgSlug, justification, userID)
}

func (s *service) updateIssue(asset models.Asset, vulnerability models.DependencyVuln) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := s.thirdPartyIntegration.UpdateIssue(ctx, asset, &vulnerability)
	if err != nil {
		return err
	}
	monitoring.TicketUpdatedAmount.Inc()
	return nil
}
