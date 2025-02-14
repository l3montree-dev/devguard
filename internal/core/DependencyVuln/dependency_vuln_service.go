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

package DependencyVuln

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/risk"
	"github.com/l3montree-dev/devguard/internal/database"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
)

type assetRepository interface {
	Update(tx core.DB, asset *models.Asset) error
	GetAllAssetsFromDB() ([]models.Asset, error)
}

type vulnRepository interface {
	SaveBatch(db core.DB, vulns []models.DependencyVulnerability) error
	Save(db core.DB, vulns *models.DependencyVulnerability) error
	Transaction(txFunc func(core.DB) error) error
	Begin() core.DB
	GetAllVulnsByAssetID(tx core.DB, assetID uuid.UUID) ([]models.DependencyVulnerability, error)
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
	vulnRepository      vulnRepository
	vulnEventRepository vulnEventRepository

	assetRepository assetRepository
	cveRepository   cveRepository
}

func NewService(vulnRepository vulnRepository, vulnEventRepository vulnEventRepository, assetRepository assetRepository, cveRepository cveRepository) *service {
	return &service{
		vulnRepository:      vulnRepository,
		vulnEventRepository: vulnEventRepository,
		assetRepository:     assetRepository,
		cveRepository:       cveRepository,
	}
}

func (s *service) UserFixedVulns(tx core.DB, userID string, vulns []models.DependencyVulnerability, doRiskManagement bool) error {
	if len(vulns) == 0 {
		return nil
	}
	// create a new vulnevent for each fixed vuln
	events := make([]models.VulnEvent, len(vulns))
	for i, vuln := range vulns {
		ev := models.NewFixedEvent(vuln.CalculateHash(), userID)
		// apply the event on the vuln
		ev.Apply(&vulns[i])
		events[i] = ev
	}

	if doRiskManagement {
		err := s.vulnRepository.SaveBatch(tx, vulns)
		if err != nil {
			return err
		}
		return s.vulnEventRepository.SaveBatch(tx, events)
	}

	return nil
}

func (s *service) UserDetectedVulns(tx core.DB, userID string, vulns []models.DependencyVulnerability, asset models.Asset, doRiskManagement bool) error {
	if len(vulns) == 0 {
		return nil
	}

	// create a new vulnevent for each detected vuln
	events := make([]models.VulnEvent, len(vulns))
	e := core.Environmental{
		ConfidentialityRequirements: string(asset.ConfidentialityRequirement),
		IntegrityRequirements:       string(asset.IntegrityRequirement),
		AvailabilityRequirements:    string(asset.AvailabilityRequirement),
	}

	for i, vuln := range vulns {
		riskReport := risk.RawRisk(*vuln.CVE, e, *vuln.ComponentDepth)
		ev := models.NewDetectedEvent(vuln.CalculateHash(), userID, riskReport)
		// apply the event on the vuln
		ev.Apply(&vulns[i])
		events[i] = ev
	}

	if doRiskManagement {
		// run the updates in the transaction to keep a valid state
		err := s.vulnRepository.SaveBatch(tx, vulns)
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

	assets, err := s.assetRepository.GetAllAssetsFromDB()
	if err != nil {
		return fmt.Errorf("could not get all assets: %v", err)
	}

	err = s.vulnRepository.Transaction(func(tx core.DB) error {
		for _, asset := range assets {
			// get all vulns of the asset
			vulns, err := s.vulnRepository.GetAllVulnsByAssetID(tx, asset.ID)
			if len(vulns) == 0 {
				continue
			}

			if err != nil {
				return fmt.Errorf("could not get all vulns by asset id: %v", err)
			}

			err = s.RecalculateRawRiskAssessment(tx, userID, vulns, justification, asset)
			if err != nil {
				return fmt.Errorf("could not recalculate raw risk assessment: %v", err)
			}

		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("could not recalculate raw risk assessment: %v", err)
	}
	return nil

}

func (s *service) RecalculateRawRiskAssessment(tx core.DB, userID string, vulns []models.DependencyVulnerability, justification string, asset models.Asset) error {
	if len(vulns) == 0 {
		return nil
	}

	env := core.Environmental{
		ConfidentialityRequirements: string(asset.ConfidentialityRequirement),
		IntegrityRequirements:       string(asset.IntegrityRequirement),
		AvailabilityRequirements:    string(asset.AvailabilityRequirement),
	}

	// create a new vulnevent for each updated vuln

	events := make([]models.VulnEvent, 0)

	// get all cveIds of the vulns
	cveIds := utils.Filter(utils.Map(vulns, func(f models.DependencyVulnerability) string {
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

	for i, vuln := range vulns {
		if vuln.CVEID == nil {
			continue
		}
		cveID := *vuln.CVEID
		cve, ok := cveMap[cveID]
		if !ok {
			slog.Info("could not find cve", "cve", cveID)
			continue
		}

		if err != nil {
			slog.Info("error getting cve", "err", err)
			continue
		}

		oldRiskAssessment := vuln.RawRiskAssessment
		newRiskAssessment := risk.RawRisk(cve, env, *vuln.ComponentDepth)

		if *oldRiskAssessment != newRiskAssessment.Risk {
			ev := models.NewRawRiskAssessmentUpdatedEvent(vuln.CalculateHash(), userID, justification, newRiskAssessment)
			// apply the event on the vuln
			ev.Apply(&vulns[i])
			events = append(events, ev)

			slog.Info("recalculated raw risk assessment", "cve", cve.CVE)
		} else {
			// only update the last calculated time
			vulns[i].RiskRecalculatedAt = time.Now()
		}
	}

	// saving the vulns and the events HAS to be done in the same transaction
	// it is crucial to maintain a consistent audit log of events
	if tx == nil {
		err := s.vulnRepository.Transaction(func(tx core.DB) error {
			if err := s.vulnRepository.SaveBatch(tx, vulns); err != nil {
				return fmt.Errorf("could not save vulns: %v", err)
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

	err = s.vulnRepository.SaveBatch(tx, vulns)
	if err != nil {
		return fmt.Errorf("could not save vulns: %v", err)
	}

	err = s.vulnEventRepository.SaveBatch(tx, events)
	if err != nil {
		return fmt.Errorf("could not save events: %v", err)
	}
	return nil
}

func (s *service) UpdateVulnState(tx core.DB, userID string, vuln *models.DependencyVulnerability, statusType string, justification string) (models.VulnEvent, error) {
	if tx == nil {
		var ev models.VulnEvent
		var err error
		// we are not part of a parent transaction - create a new one
		err = s.vulnRepository.Transaction(func(d core.DB) error {
			ev, err = s.updateVulnState(d, userID, vuln, statusType, justification)
			return err
		})
		return ev, err
	}
	return s.updateVulnState(tx, userID, vuln, statusType, justification)
}

func (s *service) updateVulnState(tx core.DB, userID string, vuln *models.DependencyVulnerability, statusType string, justification string) (models.VulnEvent, error) {
	var ev models.VulnEvent
	switch models.VulnEventType(statusType) {
	case models.EventTypeAccepted:
		ev = models.NewAcceptedEvent(vuln.CalculateHash(), userID, justification)
	case models.EventTypeFalsePositive:
		ev = models.NewFalsePositiveEvent(vuln.CalculateHash(), userID, justification)
	case models.EventTypeReopened:
		ev = models.NewReopenedEvent(vuln.CalculateHash(), userID, justification)
	case models.EventTypeComment:
		ev = models.NewCommentEvent(vuln.CalculateHash(), userID, justification)
	}

	return s.applyAndSave(tx, vuln, &ev)
}

func (s *service) ApplyAndSave(tx core.DB, vuln *models.DependencyVulnerability, vulnEvent *models.VulnEvent) error {
	if tx == nil {
		// we are not part of a parent transaction - create a new one
		return s.vulnRepository.Transaction(func(d core.DB) error {
			_, err := s.applyAndSave(d, vuln, vulnEvent)
			return err
		})
	}

	_, err := s.applyAndSave(tx, vuln, vulnEvent)
	return err
}

func (s *service) applyAndSave(tx core.DB, vuln *models.DependencyVulnerability, ev *models.VulnEvent) (models.VulnEvent, error) {
	// apply the event on the vuln
	ev.Apply(vuln)

	// run the updates in the transaction to keep a valid state
	err := s.vulnRepository.Save(tx, vuln)
	if err != nil {
		return models.VulnEvent{}, err
	}
	if err := s.vulnEventRepository.Save(tx, ev); err != nil {
		return models.VulnEvent{}, err
	}
	vuln.Events = append(vuln.Events, *ev)
	return *ev, nil
}
