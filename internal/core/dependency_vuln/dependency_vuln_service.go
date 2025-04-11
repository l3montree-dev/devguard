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

package dependency_vuln

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"

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

func (s *service) UserFixedDependencyVulns(tx core.DB, userID string, dependencyVulns []models.DependencyVuln, assetVersion models.AssetVersion, asset models.Asset, doRiskManagement bool) error {
	if len(dependencyVulns) == 0 {
		return nil
	}

	// create a new VulnEvent for each fixed dependencyVuln
	events := make([]models.VulnEvent, len(dependencyVulns))

	for i, dependencyVuln := range dependencyVulns {
		ev := models.NewFixedEvent(dependencyVuln.CalculateHash(), userID)
		// apply the event on the dependencyVuln
		ev.Apply(&dependencyVulns[i])
		events[i] = ev
	}

	if doRiskManagement {
		err := s.dependencyVulnRepository.SaveBatch(tx, dependencyVulns)
		if err != nil {
			return err
		}
		return s.vulnEventRepository.SaveBatch(tx, events)
	}

	return nil
}

func (s *service) UserDetectedDependencyVulns(tx core.DB, userID string, dependencyVulns []models.DependencyVuln, assetVersion models.AssetVersion, asset models.Asset, doRiskManagement bool) error {
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
		ev := models.NewDetectedEvent(dependencyVuln.CalculateHash(), userID, riskReport)
		// apply the event on the dependencyVuln
		ev.Apply(&dependencyVulns[i])
		events[i] = ev
	}

	if doRiskManagement {
		// run the updates in the transaction to keep a valid state
		err := s.dependencyVulnRepository.SaveBatch(tx, dependencyVulns)
		if err != nil {
			return err
		}
		return s.vulnEventRepository.SaveBatch(tx, events)
	}

	return nil
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
		// get all dependencyVulns of the asset
		dependencyVulns, err := s.dependencyVulnRepository.GetDependencyVulnsByAssetVersion(nil, assetVersion.Name, assetVersion.AssetID)
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
		if s.ShouldCreateIssue(assetVersion) {
			err = s.CreateIssuesForVulns(assetVersion.Asset, dependencyVulns)
			if err != nil {
				return err
			}
		}

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
		ev := models.NewAddedScannerEvent(vulnerabilities[i].CalculateHash(), userID, scannerID)
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
		ev := models.NewRemovedScannerEvent(vulnerabilities[i].CalculateHash(), userID, scannerID)
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

	// get all cveIds of the dependencyVulns
	cveIds := utils.Filter(utils.Map(dependencyVulns, func(f models.DependencyVuln) string {
		return utils.SafeDereference(f.CVEID)
	}), func(s string) bool {
		return s != ""
	})

	cves, err := s.cveRepository.FindCVEs(nil, cveIds)
	if err != nil {
		return fmt.Errorf("could not get all cves: %v", err)
	}
	// create a map of cveId -> cve
	cveMap := make(map[string]models.CVE)
	for _, cve := range cves {
		cveMap[cve.CVE] = cve
	}

	for i, dependencyVuln := range dependencyVulns {
		if dependencyVuln.CVEID == nil {
			continue
		}
		cveID := *dependencyVuln.CVEID
		cve, ok := cveMap[cveID]
		if !ok {
			slog.Info("could not find cve", "cve", cveID)
			continue
		}

		oldRiskAssessment := dependencyVuln.RawRiskAssessment
		newRiskAssessment := risk.RawRisk(cve, env, *dependencyVuln.ComponentDepth)

		if *oldRiskAssessment != newRiskAssessment.Risk {
			ev := models.NewRawRiskAssessmentUpdatedEvent(dependencyVuln.CalculateHash(), userID, justification, oldRiskAssessment, newRiskAssessment)
			// apply the event on the dependencyVuln
			ev.Apply(&dependencyVulns[i])
			events = append(events, ev)

			slog.Info("recalculated raw risk assessment", "cve", cve.CVE)
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

	err = s.dependencyVulnRepository.SaveBatch(tx, dependencyVulns)
	if err != nil {
		return fmt.Errorf("could not save dependencyVulns: %v", err)
	}

	err = s.vulnEventRepository.SaveBatch(tx, events)
	if err != nil {
		return fmt.Errorf("could not save events: %v", err)
	}
	return nil
}

func (s *service) UpdateDependencyVulnState(tx core.DB, assetID uuid.UUID, userID string, dependencyVuln *models.DependencyVuln, statusType string, justification string, assetVersionName string) (models.VulnEvent, error) {
	if tx == nil {

		var ev models.VulnEvent
		var err error
		// we are not part of a parent transaction - create a new one
		err = s.dependencyVulnRepository.Transaction(func(d core.DB) error {
			ev, err = s.updateDependencyVulnState(tx, userID, dependencyVuln, statusType, justification)
			return err
		})
		return ev, err
	}
	return s.updateDependencyVulnState(tx, userID, dependencyVuln, statusType, justification)
}

func (s *service) updateDependencyVulnState(tx core.DB, userID string, dependencyVuln *models.DependencyVuln, statusType string, justification string) (models.VulnEvent, error) {
	var ev models.VulnEvent
	switch models.VulnEventType(statusType) {
	case models.EventTypeAccepted:
		ev = models.NewAcceptedEvent(dependencyVuln.CalculateHash(), userID, justification)
	case models.EventTypeFalsePositive:
		ev = models.NewFalsePositiveEvent(dependencyVuln.CalculateHash(), userID, justification)
	case models.EventTypeReopened:
		ev = models.NewReopenedEvent(dependencyVuln.CalculateHash(), userID, justification)
	case models.EventTypeComment:
		ev = models.NewCommentEvent(dependencyVuln.CalculateHash(), userID, justification)
	}

	err := s.dependencyVulnRepository.ApplyAndSave(tx, dependencyVuln, &ev)
	return ev, err
}

// function to check whether the provided vulnerabilities in a given asset exceeds their respective thresholds and create a ticket for it if they do so
func (s *service) CreateIssuesForVulns(asset models.Asset, vulnList []models.DependencyVuln) error {
	riskThreshold := asset.RiskAutomaticTicketThreshold
	cvssThreshold := asset.CVSSAutomaticTicketThreshold

	//Check if no automatic Issues are wanted by the user
	if riskThreshold == nil && cvssThreshold == nil {
		return nil
	}

	project, err := s.projectRepository.Read(asset.ProjectID)
	if err != nil {
		return err
	}

	org, err := s.organizationRepository.Read(project.OrganizationID)
	if err != nil {
		return err
	}

	repoID, err := core.GetRepositoryIdFromAssetAndProject(project, asset)
	if err != nil {
		return nil //We don't want to return an error if the user has not yet linked his repo with devguard
	}

	//Determine whether to scan for both risk and cvss or just 1 of them
	if riskThreshold != nil && cvssThreshold != nil {

		for _, vulnerability := range vulnList {
			if vulnerability.TicketID == nil {
				if *vulnerability.RawRiskAssessment >= *riskThreshold || vulnerability.CVE.CVSS >= float32(*cvssThreshold) {

					err := s.createIssue(vulnerability.ID, asset, vulnerability.AssetVersionName, repoID, org.Slug, project.Slug)
					if err != nil {
						return err
					}
				}
			}
		}
	} else {
		if riskThreshold != nil {
			for _, vulnerability := range vulnList {
				if vulnerability.TicketID == nil {
					if *vulnerability.RawRiskAssessment >= *riskThreshold {
						err := s.createIssue(vulnerability.ID, asset, vulnerability.AssetVersionName, repoID, org.Slug, project.Slug)
						if err != nil {
							return err
						}
					}

				}
			}
		} else if cvssThreshold != nil {
			for _, vulnerability := range vulnList {
				if vulnerability.TicketID == nil {
					if vulnerability.CVE.CVSS >= float32(*cvssThreshold) {
						err := s.createIssue(vulnerability.ID, asset, vulnerability.AssetVersionName, repoID, org.Slug, project.Slug)
						if err != nil {
							return err
						}

					}
				}
			}
		}
	}
	return nil
}

// function to remove duplicate code from the different cases of the createIssuesForVulns function
func (s *service) createIssue(cveName string, asset models.Asset, assetVersionName string, repoId string, orgSlug string, projectSlug string) error {

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := s.thirdPartyIntegration.CreateIssue(ctx, asset, assetVersionName, repoId, cveName, projectSlug, orgSlug)
	if err != nil {
		return err
	}

	return nil
}

func (s *service) ShouldCreateIssue(assetVersion models.AssetVersion) bool {
	//if the vulnerability was found anywhere else than the default branch we don't want to create an issue
	return assetVersion.DefaultBranch
}
