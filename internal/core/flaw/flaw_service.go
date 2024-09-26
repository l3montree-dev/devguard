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

package flaw

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
)

type assetRepository interface {
	Update(tx core.DB, asset *models.Asset) error
	GetAllAssetsFromDB() ([]models.Asset, error)
}

type flawRepository interface {
	SaveBatch(db core.DB, flaws []models.Flaw) error
	Save(db core.DB, flaws *models.Flaw) error
	Transaction(txFunc func(core.DB) error) error
	Begin() core.DB
	GetAllFlawsByAssetID(tx core.DB, assetID uuid.UUID) ([]models.Flaw, error)
}

type flawEventRepository interface {
	SaveBatch(db core.DB, events []models.FlawEvent) error
	Save(db core.DB, event *models.FlawEvent) error
}
type cveRepository interface {
	FindCVE(tx database.DB, cveId string) (models.CVE, error)
}
type service struct {
	flawRepository      flawRepository
	flawEventRepository flawEventRepository
	assetRepository     assetRepository
	cveRepository       cveRepository
}

func NewService(flawRepository flawRepository, flawEventRepository flawEventRepository, assetRepository assetRepository, cveRepository cveRepository) *service {
	return &service{
		flawRepository:      flawRepository,
		flawEventRepository: flawEventRepository,
		assetRepository:     assetRepository,
		cveRepository:       cveRepository,
	}
}

// expect a transaction to be passed
func (s *service) UserFixedFlaws(tx core.DB, userID string, flaws []models.Flaw) error {
	if len(flaws) == 0 {
		return nil
	}
	// create a new flawevent for each fixed flaw
	events := make([]models.FlawEvent, len(flaws))
	for i, flaw := range flaws {
		ev := models.NewFixedEvent(flaw.CalculateHash(), userID)
		// apply the event on the flaw
		ev.Apply(&flaws[i])
		events[i] = ev
	}

	err := s.flawRepository.SaveBatch(tx, flaws)
	if err != nil {
		return err
	}
	return s.flawEventRepository.SaveBatch(tx, events)
}

// expect a transaction to be passed
func (s *service) UserDetectedFlaws(tx core.DB, userID string, flaws []models.Flaw, asset models.Asset) error {
	if len(flaws) == 0 {
		return nil
	}
	// create a new flawevent for each detected flaw
	events := make([]models.FlawEvent, len(flaws))
	e := core.Environmental{
		ConfidentialityRequirements: string(asset.ConfidentialityRequirement),
		IntegrityRequirements:       string(asset.IntegrityRequirement),
		AvailabilityRequirements:    string(asset.AvailabilityRequirement),
	}

	for i, flaw := range flaws {
		riskReport := risk.RawRisk(*flaw.CVE, e, flaw.GetComponentDepth())

		ev := models.NewDetectedEvent(flaw.CalculateHash(), userID, riskReport)
		// apply the event on the flaw
		ev.Apply(&flaws[i])
		events[i] = ev
	}

	// run the updates in the transaction to keep a valid state
	err := s.flawRepository.SaveBatch(tx, flaws)
	if err != nil {
		return err
	}
	return s.flawEventRepository.SaveBatch(tx, events)
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

	err = s.flawRepository.Transaction(func(tx core.DB) error {
		for _, asset := range assets {
			// get all flaws of the asset
			flaws, err := s.flawRepository.GetAllFlawsByAssetID(tx, asset.ID)
			if len(flaws) == 0 {
				continue
			}

			if err != nil {
				return fmt.Errorf("could not get all flaws by asset id: %v", err)
			}

			err = s.RecalculateRawRiskAssessment(tx, userID, flaws, justification, asset)
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

func (s *service) RecalculateRawRiskAssessment(tx core.DB, userID string, flaws []models.Flaw, justification string, asset models.Asset) error {

	if len(flaws) == 0 {
		return nil
	}

	env := core.Environmental{
		ConfidentialityRequirements: string(asset.ConfidentialityRequirement),
		IntegrityRequirements:       string(asset.IntegrityRequirement),
		AvailabilityRequirements:    string(asset.AvailabilityRequirement),
	}

	// create a new flawevent for each updated flaw

	events := make([]models.FlawEvent, 0)
	for i, flaw := range flaws {
		cviID := flaw.CVEID
		cve, err := s.cveRepository.FindCVE(nil, cviID)
		if err != nil {
			slog.Info("error getting cve", "err", err)
			continue
		}

		oldRiskAssessment := flaw.RawRiskAssessment
		newRiskAssessment := risk.RawRisk(cve, env, flaw.GetComponentDepth())

		if *oldRiskAssessment != newRiskAssessment.Risk {
			ev := models.NewRawRiskAssessmentUpdatedEvent(flaw.CalculateHash(), userID, justification, newRiskAssessment)
			// apply the event on the flaw
			ev.Apply(&flaws[i])
			events = append(events, ev)

			slog.Info("recalculated raw risk assessment", "cve", cve.CVE)
		} else {
			// only update the last calculated time
			flaws[i].RiskRecalculatedAt = time.Now()
		}
	}

	// saving the flaws and the events HAS to be done in the same transaction
	// it is crucial to maintain a consistent audit log of events
	if tx == nil {
		err := s.flawRepository.Transaction(func(tx core.DB) error {
			if err := s.flawRepository.SaveBatch(tx, flaws); err != nil {
				return fmt.Errorf("could not save flaws: %v", err)
			}
			if err := s.flawEventRepository.SaveBatch(tx, events); err != nil {
				return fmt.Errorf("could not save events: %v", err)
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("could not recalculate raw risk assessment: %v", err)
		}
		return nil
	}

	err := s.flawRepository.SaveBatch(tx, flaws)
	if err != nil {
		return fmt.Errorf("could not save flaws: %v", err)
	}

	err = s.flawEventRepository.SaveBatch(tx, events)
	if err != nil {
		return fmt.Errorf("could not save events: %v", err)
	}
	return nil
}

func (s *service) UpdateFlawState(tx core.DB, userID string, flaw *models.Flaw, statusType string, justification string) (models.FlawEvent, error) {
	if tx == nil {
		var ev models.FlawEvent
		var err error
		// we are not part of a parent transaction - create a new one
		err = s.flawRepository.Transaction(func(d core.DB) error {
			ev, err = s.updateFlawState(d, userID, flaw, statusType, justification)
			return err
		})
		return ev, err
	}
	return s.updateFlawState(tx, userID, flaw, statusType, justification)
}

func (s *service) updateFlawState(tx core.DB, userID string, flaw *models.Flaw, statusType string, justification string) (models.FlawEvent, error) {
	var ev models.FlawEvent
	switch models.FlawEventType(statusType) {
	case models.EventTypeAccepted:
		ev = models.NewAcceptedEvent(flaw.CalculateHash(), userID, justification)
	case models.EventTypeFalsePositive:
		ev = models.NewFalsePositiveEvent(flaw.CalculateHash(), userID, justification)
	case models.EventTypeReopened:
		ev = models.NewReopenedEvent(flaw.CalculateHash(), userID, justification)
	case models.EventTypeComment:
		ev = models.NewCommentEvent(flaw.CalculateHash(), userID, justification)
	}

	return s.applyAndSave(tx, flaw, &ev)
}

func (s *service) ApplyAndSave(tx core.DB, flaw *models.Flaw, flawEvent *models.FlawEvent) error {
	if tx == nil {
		// we are not part of a parent transaction - create a new one
		return s.flawRepository.Transaction(func(d core.DB) error {
			_, err := s.applyAndSave(d, flaw, flawEvent)
			return err
		})
	}

	_, err := s.applyAndSave(tx, flaw, flawEvent)
	return err
}

func (s *service) applyAndSave(tx core.DB, flaw *models.Flaw, ev *models.FlawEvent) (models.FlawEvent, error) {
	// apply the event on the flaw
	ev.Apply(flaw)

	// run the updates in the transaction to keep a valid state
	err := s.flawRepository.Save(tx, flaw)
	if err != nil {
		return models.FlawEvent{}, err
	}
	if err := s.flawEventRepository.Save(tx, ev); err != nil {
		return models.FlawEvent{}, err
	}
	flaw.Events = append(flaw.Events, *ev)
	return *ev, nil
}

type leaderElector interface {
	IfLeader(ctx context.Context, fn func() error)
}

func (service *service) StartRiskRecalculationDaemon(leaderElector leaderElector) {
	leaderElector.IfLeader(context.Background(), func() error {
		err := service.RecalculateAllRawRiskAssessments()
		if err != nil {
			slog.Error("could not recalculate risk assessments", "err", err)
		}
		time.Sleep(1 * time.Hour)
		return nil
	})
}
