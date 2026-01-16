package services

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/monitoring"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/statemachine"
	"github.com/l3montree-dev/devguard/utils"
)

type firstPartyVulnService struct {
	firstPartyVulnRepository shared.FirstPartyVulnRepository
	vulnEventRepository      shared.VulnEventRepository
	assetRepository          shared.AssetRepository

	thirdPartyIntegration shared.IntegrationAggregate
}

func NewFirstPartyVulnService(firstPartyVulnRepository shared.FirstPartyVulnRepository, vulnEventRepository shared.VulnEventRepository, assetRepository shared.AssetRepository, thirdPartyIntegration shared.IntegrationAggregate) *firstPartyVulnService {
	return &firstPartyVulnService{
		firstPartyVulnRepository: firstPartyVulnRepository,
		vulnEventRepository:      vulnEventRepository,
		assetRepository:          assetRepository,
		thirdPartyIntegration:    thirdPartyIntegration,
	}
}

var _ shared.FirstPartyVulnService = (*firstPartyVulnService)(nil)

func (s *firstPartyVulnService) UserFixedFirstPartyVulns(tx shared.DB, userID string, firstPartyVulns []models.FirstPartyVuln) error {

	if len(firstPartyVulns) == 0 {
		return nil
	}

	events := make([]models.VulnEvent, len(firstPartyVulns))
	for i, vuln := range firstPartyVulns {
		ev := models.NewFixedEvent(vuln.CalculateHash(), dtos.VulnTypeFirstPartyVuln, userID, vuln.ScannerIDs, dtos.UpstreamStateInternal)

		statemachine.Apply(&firstPartyVulns[i], ev)
		events[i] = ev
	}

	err := s.firstPartyVulnRepository.SaveBatch(tx, firstPartyVulns)
	if err != nil {
		return err
	}
	return s.vulnEventRepository.SaveBatch(tx, events)

}

func (s *firstPartyVulnService) UserDetectedFirstPartyVulns(tx shared.DB, userID, scannerID string, firstPartyVulns []models.FirstPartyVuln) error {
	if len(firstPartyVulns) == 0 {
		return nil
	}
	// create a new dependencyVulnevent for each fixed dependencyVuln
	events := make([]models.VulnEvent, len(firstPartyVulns))
	for i, firstPartyVuln := range firstPartyVulns {
		ev := models.NewDetectedEvent(firstPartyVuln.CalculateHash(), dtos.VulnTypeFirstPartyVuln, userID, dtos.RiskCalculationReport{}, scannerID, dtos.UpstreamStateInternal)
		// apply the event on the dependencyVuln
		statemachine.Apply(&firstPartyVulns[i], ev)
		events[i] = ev
	}

	err := s.firstPartyVulnRepository.SaveBatch(tx, firstPartyVulns)
	if err != nil {
		return err
	}
	return s.vulnEventRepository.SaveBatch(tx, events)
}

func (s *firstPartyVulnService) UserDetectedExistingFirstPartyVulnOnDifferentBranch(tx shared.DB, scannerID string, firstPartyVulns []statemachine.BranchVulnMatch[*models.FirstPartyVuln], assetVersion models.AssetVersion, asset models.Asset) error {
	if len(firstPartyVulns) == 0 {
		return nil
	}

	vulns := utils.Map(firstPartyVulns, func(el statemachine.BranchVulnMatch[*models.FirstPartyVuln]) models.FirstPartyVuln {
		return *el.CurrentBranchVuln
	})

	events := utils.Map(firstPartyVulns, func(el statemachine.BranchVulnMatch[*models.FirstPartyVuln]) []models.VulnEvent {
		return el.EventsToCopy
	})

	err := s.firstPartyVulnRepository.SaveBatchBestEffort(tx, vulns)
	if err != nil {
		return err
	}

	return s.vulnEventRepository.SaveBatchBestEffort(tx, utils.Flat(events))
}

func (s *firstPartyVulnService) UpdateFirstPartyVulnState(tx shared.DB, userID string, firstPartyVuln *models.FirstPartyVuln, statusType string, justification string, mechanicalJustification dtos.MechanicalJustificationType) (models.VulnEvent, error) {
	if tx == nil {
		var ev models.VulnEvent
		var err error
		// we are not part of a parent transaction - create a new one
		err = s.firstPartyVulnRepository.Transaction(func(d shared.DB) error {
			ev, err = s.updateFirstPartyVulnState(d, userID, firstPartyVuln, statusType, justification, mechanicalJustification)
			return err
		})
		return ev, err
	}
	return s.updateFirstPartyVulnState(tx, userID, firstPartyVuln, statusType, justification, mechanicalJustification)
}

func (s *firstPartyVulnService) updateFirstPartyVulnState(tx shared.DB, userID string, firstPartyVuln *models.FirstPartyVuln, statusType string, justification string, mechanicalJustification dtos.MechanicalJustificationType) (models.VulnEvent, error) {
	var ev models.VulnEvent
	switch dtos.VulnEventType(statusType) {
	case dtos.EventTypeAccepted:
		ev = models.NewAcceptedEvent(firstPartyVuln.CalculateHash(), dtos.VulnTypeFirstPartyVuln, userID, justification, dtos.UpstreamStateInternal)
	case dtos.EventTypeFalsePositive:
		ev = models.NewFalsePositiveEvent(firstPartyVuln.CalculateHash(), dtos.VulnTypeFirstPartyVuln, userID, justification, mechanicalJustification, firstPartyVuln.ScannerIDs, dtos.UpstreamStateInternal)
	case dtos.EventTypeReopened:
		ev = models.NewReopenedEvent(firstPartyVuln.CalculateHash(), dtos.VulnTypeFirstPartyVuln, userID, justification, dtos.UpstreamStateInternal)
	case dtos.EventTypeComment:
		ev = models.NewCommentEvent(firstPartyVuln.CalculateHash(), dtos.VulnTypeFirstPartyVuln, userID, justification, dtos.UpstreamStateInternal)
	}

	return s.applyAndSave(tx, firstPartyVuln, &ev)
}

func (s *firstPartyVulnService) ApplyAndSave(tx shared.DB, firstPartyVuln *models.FirstPartyVuln, vulnEvent *models.VulnEvent) error {
	if tx == nil {
		// we are not part of a parent transaction - create a new one
		return s.firstPartyVulnRepository.Transaction(func(d shared.DB) error {
			_, err := s.applyAndSave(d, firstPartyVuln, vulnEvent)
			return err
		})
	}

	_, err := s.applyAndSave(tx, firstPartyVuln, vulnEvent)
	return err
}

func (s *firstPartyVulnService) applyAndSave(tx shared.DB, firstPartyVuln *models.FirstPartyVuln, ev *models.VulnEvent) (models.VulnEvent, error) {
	// apply the event on the first-party vuln
	statemachine.Apply(firstPartyVuln, *ev)

	// run the updates in the transaction to keep a valid state
	err := s.firstPartyVulnRepository.Save(tx, firstPartyVuln)
	if err != nil {
		return models.VulnEvent{}, err
	}
	if err := s.vulnEventRepository.Save(tx, ev); err != nil {
		return models.VulnEvent{}, err
	}
	firstPartyVuln.Events = append(firstPartyVuln.Events, *ev)
	return *ev, nil
}

func (s *firstPartyVulnService) SyncAllIssues(org models.Org, project models.Project, asset models.Asset, assetVersion models.AssetVersion) error {
	// get all first-party for the assetVersion
	vulnList, err := s.firstPartyVulnRepository.ListByScanner(assetVersion.Name, asset.ID, "")
	if err != nil {
		return fmt.Errorf("could not get first-party vulnerability by asset version: %w", err)
	}

	if len(vulnList) == 0 {
		slog.Info("no first-party vulnerabilities found for asset version", "assetVersionName", assetVersion.Name)
		return nil
	}

	return s.SyncIssues(org, project, asset, assetVersion, vulnList)
}

func (s *firstPartyVulnService) SyncIssues(org models.Org, project models.Project, asset models.Asset, assetVersion models.AssetVersion, vulnList []models.FirstPartyVuln) error {
	if len(vulnList) == 0 {
		return nil
	}
	errgroup := utils.ErrGroup[any](10)
	for _, vulnerability := range vulnList {
		if vulnerability.TicketID != nil {
			errgroup.Go(func() (any, error) {
				return s.updateIssue(asset, assetVersion.Slug, vulnerability), nil
			})
		}
	}

	_, err := errgroup.WaitAndCollect()
	return err
}

func (s *firstPartyVulnService) updateIssue(asset models.Asset, assetVersionSlug string, vulnerability models.FirstPartyVuln) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := s.thirdPartyIntegration.UpdateIssue(ctx, asset, assetVersionSlug, &vulnerability)
	if err != nil {
		return err
	}
	monitoring.TicketUpdatedAmount.Inc()
	return nil
}
