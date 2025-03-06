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

package dependencyVuln

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"

	"github.com/l3montree-dev/devguard/internal/core/risk"
	"github.com/l3montree-dev/devguard/internal/database"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/utils"
)

type assetRepository interface {
	GetAllAssetsFromDB() ([]models.Asset, error)
}

type dependencyVulnRepository interface {
	SaveBatch(db core.DB, dependencyVulns []models.DependencyVuln) error
	Save(db core.DB, dependencyVulns *models.DependencyVuln) error
	Transaction(txFunc func(core.DB) error) error
	Begin() core.DB

	GetDependencyVulnsByAssetVersion(tx core.DB, assetVersionName string, assetID uuid.UUID) ([]models.DependencyVuln, error)
	GetAllVulnsByAssetID(tx core.DB, assetID uuid.UUID) ([]models.DependencyVuln, error)
}

type vulnEventRepository interface {
	SaveBatch(db core.DB, events []models.VulnEvent) error
	Save(db core.DB, event *models.VulnEvent) error
}
type cveRepository interface {
	FindCVE(tx database.DB, cveId string) (models.CVE, error)
	FindCVEs(tx database.DB, cveIds []string) ([]models.CVE, error)
}
type service struct {
	dependencyVulnRepository dependencyVulnRepository
	vulnEventRepository      vulnEventRepository

	assetRepository assetRepository
	cveRepository   cveRepository
}

func NewService(dependencyVulnRepository dependencyVulnRepository, vulnEventRepository vulnEventRepository, assetRepository assetRepository, cveRepository cveRepository) *service {
	return &service{
		dependencyVulnRepository: dependencyVulnRepository,
		vulnEventRepository:      vulnEventRepository,
		assetRepository:          assetRepository,
		cveRepository:            cveRepository,
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

func (s *service) RecalculateAllRawRiskAssessments(thirdPartyIntegrations core.ThirdPartyIntegration) error {
	now := time.Now()
	slog.Info("recalculating all raw risk assessments", "time", now)

	userID := "system"
	justification := "System recalculated raw risk assessment"

	assets, err := s.assetRepository.GetAllAssetsFromDB()
	if err != nil {
		return fmt.Errorf("could not get all assets: %v", err)
	}

	err = s.dependencyVulnRepository.Transaction(func(tx core.DB) error {
		for _, asset := range assets {
			// get all dependencyVulns of the asset
			dependencyVulns, err := s.dependencyVulnRepository.GetAllVulnsByAssetID(tx, asset.ID)
			if len(dependencyVulns) == 0 {
				continue
			}

			if err != nil {
				return fmt.Errorf("could not get all dependencyVulns by asset id: %v", err)
			}

			err = s.RecalculateRawRiskAssessment(tx, userID, dependencyVulns, justification, asset)
			if err != nil {
				return fmt.Errorf("could not recalculate raw risk assessment: %v", err)
			}
			createIssuesForVulns(tx, thirdPartyIntegrations, asset, dependencyVulns)

		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("could not recalculate raw risk assessment: %v", err)
	}
	return nil

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

		if err != nil {
			slog.Info("error getting cve", "err", err)
			continue
		}

		oldRiskAssessment := dependencyVuln.RawRiskAssessment
		newRiskAssessment := risk.RawRisk(cve, env, *dependencyVuln.ComponentDepth)

		if *oldRiskAssessment != newRiskAssessment.Risk {
			ev := models.NewRawRiskAssessmentUpdatedEvent(dependencyVuln.CalculateHash(), userID, justification, newRiskAssessment)
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

	return s.applyAndSave(tx, dependencyVuln, &ev)
}

func (s *service) ApplyAndSave(tx core.DB, dependencyVuln *models.DependencyVuln, VulnEvent *models.VulnEvent) error {
	if tx == nil {
		// we are not part of a parent transaction - create a new one
		return s.dependencyVulnRepository.Transaction(func(d core.DB) error {
			_, err := s.applyAndSave(d, dependencyVuln, VulnEvent)
			return err
		})
	}

	_, err := s.applyAndSave(tx, dependencyVuln, VulnEvent)
	return err
}

func (s *service) applyAndSave(tx core.DB, dependencyVuln *models.DependencyVuln, ev *models.VulnEvent) (models.VulnEvent, error) {
	// apply the event on the dependencyVuln
	ev.Apply(dependencyVuln)

	// run the updates in the transaction to keep a valid state
	err := s.dependencyVulnRepository.Save(tx, dependencyVuln)
	if err != nil {
		return models.VulnEvent{}, err
	}
	if err := s.vulnEventRepository.Save(tx, ev); err != nil {
		return models.VulnEvent{}, err
	}
	dependencyVuln.Events = append(dependencyVuln.Events, *ev)
	return *ev, nil
}

func createIssuesForVulns(db core.DB, thirdPartyIntegration core.ThirdPartyIntegration, asset models.Asset, vulnList []models.DependencyVuln) error {
	riskThreshold := asset.RiskAutomaticTicketThreshold
	cvssThreshold := asset.CVSSAutomaticTicketThreshold

	if riskThreshold == nil && cvssThreshold == nil {
		fmt.Printf("Both null")
		return nil
	}

	projectRepository := repositories.NewProjectRepository(db)
	organizationRepository := repositories.NewOrgRepository(db)

	project, err := projectRepository.Read(asset.ProjectID)
	if err != nil {
		return err
	}
	org, err := organizationRepository.Read(project.OrganizationID)
	if err != nil {
		return err
	}

	repoID, err := core.GetRepositoryIdFromAssetAndProject(project, asset)
	if err != nil {
		return err
	}
	if riskThreshold != nil && cvssThreshold != nil {
		fmt.Printf("Both")
		for _, vulnerability := range vulnList {
			if *vulnerability.RawRiskAssessment >= *asset.RiskAutomaticTicketThreshold || vulnerability.CVE.CVSS >= float32(*asset.CVSSAutomaticTicketThreshold) {
				err := setUpIssueCreation(thirdPartyIntegration, vulnerability.CVE.CVE, asset, repoID, org.Slug, project.Slug)
				if err != nil {
					return err
				}
			}

		}
	} else {
		if riskThreshold != nil {
			fmt.Printf("Only risk")
			for _, vulnerability := range vulnList {
				fmt.Printf("\n%f > %f\n ", *vulnerability.RawRiskAssessment, *asset.RiskAutomaticTicketThreshold)
				if *vulnerability.RawRiskAssessment >= *asset.RiskAutomaticTicketThreshold {
					err := setUpIssueCreation(thirdPartyIntegration, vulnerability.CVE.CVE, asset, repoID, org.Slug, project.Slug)
					if err != nil {
						return err
					}

				}
			}
		} else if cvssThreshold != nil {
			fmt.Printf("Only cvss")
			for _, vulnerability := range vulnList {
				fmt.Printf("\n%f > %f\n ", vulnerability.CVE.CVSS, float32(*asset.CVSSAutomaticTicketThreshold))
				if vulnerability.CVE.CVSS >= float32(*asset.CVSSAutomaticTicketThreshold) {
					err := setUpIssueCreation(thirdPartyIntegration, vulnerability.CVE.CVE, asset, repoID, org.Slug, project.Slug)
					if err != nil {
						return err
					}

				}
			}
		}

	}
	return nil
}

func setUpIssueCreation(thirdPartyIntegration core.ThirdPartyIntegration, cveName string, asset models.Asset, repoId string, orgSlug string, projectSlug string) error {

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := thirdPartyIntegration.CreateIssue(ctx, asset, repoId, cveName, projectSlug, orgSlug)
	if err != nil {
		return err
	}

	return nil
}
