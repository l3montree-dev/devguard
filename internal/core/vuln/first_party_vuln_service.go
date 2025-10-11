package vuln

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/monitoring"
	"github.com/l3montree-dev/devguard/internal/utils"
)

type firstPartyVulnService struct {
	firstPartyVulnRepository core.FirstPartyVulnRepository
	vulnEventRepository      core.VulnEventRepository
	assetRepository          core.AssetRepository

	thirdPartyIntegration core.ThirdPartyIntegration
}

func NewFirstPartyVulnService(firstPartyVulnRepository core.FirstPartyVulnRepository, vulnEventRepository core.VulnEventRepository, assetRepository core.AssetRepository, thirdPartyIntegration core.ThirdPartyIntegration) *firstPartyVulnService {
	return &firstPartyVulnService{
		firstPartyVulnRepository: firstPartyVulnRepository,
		vulnEventRepository:      vulnEventRepository,
		assetRepository:          assetRepository,
		thirdPartyIntegration:    thirdPartyIntegration,
	}
}

func (s *firstPartyVulnService) UserFixedFirstPartyVulns(tx core.DB, userID string, firstPartyVulns []models.FirstPartyVuln) error {

	if len(firstPartyVulns) == 0 {
		return nil
	}

	events := make([]models.VulnEvent, len(firstPartyVulns))
	for i, vuln := range firstPartyVulns {
		ev := models.NewFixedEvent(vuln.CalculateHash(), models.VulnTypeFirstPartyVuln, userID, vuln.ScannerIDs, 0)

		ev.Apply(&firstPartyVulns[i])
		events[i] = ev
	}

	err := s.firstPartyVulnRepository.SaveBatch(tx, firstPartyVulns)
	if err != nil {
		return err
	}
	return s.vulnEventRepository.SaveBatch(tx, events)

}

func (s *firstPartyVulnService) UserDetectedFirstPartyVulns(tx core.DB, userID, scannerID string, firstPartyVulns []models.FirstPartyVuln) error {
	if len(firstPartyVulns) == 0 {
		return nil
	}
	// create a new dependencyVulnevent for each fixed dependencyVuln
	events := make([]models.VulnEvent, len(firstPartyVulns))
	for i, firstPartyVuln := range firstPartyVulns {
		ev := models.NewDetectedEvent(firstPartyVuln.CalculateHash(), models.VulnTypeFirstPartyVuln, userID, common.RiskCalculationReport{}, scannerID, 0)
		// apply the event on the dependencyVuln
		ev.Apply(&firstPartyVulns[i])
		events[i] = ev
	}

	err := s.firstPartyVulnRepository.SaveBatch(tx, firstPartyVulns)
	if err != nil {
		return err
	}
	return s.vulnEventRepository.SaveBatch(tx, events)
}

func (s *firstPartyVulnService) UserDetectedExistingFirstPartyVulnOnDifferentBranch(tx core.DB, scannerID string, firstPartyVulns []models.FirstPartyVuln, alreadyExistingEvents [][]models.VulnEvent, assetVersion models.AssetVersion, asset models.Asset) error {
	if len(firstPartyVulns) == 0 {
		return nil
	}

	events := make([][]models.VulnEvent, len(firstPartyVulns))

	for i, firstPartyVuln := range firstPartyVulns {
		// copy all events for this vulnerability
		if len(alreadyExistingEvents[i]) != 0 {
			events[i] = utils.Map(alreadyExistingEvents[i], func(el models.VulnEvent) models.VulnEvent {
				// Create a proper copy of the event
				newEvent := models.VulnEvent{
					Model:                    models.Model{}, // New model with empty ID and timestamps
					Type:                     el.Type,
					VulnID:                   firstPartyVuln.CalculateHash(),
					VulnType:                 el.VulnType,
					UserID:                   el.UserID,
					Justification:            el.Justification,
					MechanicalJustification:  el.MechanicalJustification,
					ArbitraryJSONData:        el.ArbitraryJSONData,
					OriginalAssetVersionName: el.OriginalAssetVersionName,
				}
				newEvent.ID = uuid.Nil
				newEvent.CreatedAt = el.CreatedAt
				newEvent.UpdatedAt = time.Now()
				return newEvent
			})
		}
		// replay all events on the firstPartyVuln
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
			ev.Apply(&firstPartyVulns[i])
		}
	}

	err := s.firstPartyVulnRepository.SaveBatch(tx, firstPartyVulns)
	if err != nil {
		return err
	}

	return s.vulnEventRepository.SaveBatch(tx, utils.Flat(events))
}

func (s *firstPartyVulnService) UpdateFirstPartyVulnState(tx core.DB, userID string, firstPartyVuln *models.FirstPartyVuln, statusType string, justification string, mechanicalJustification models.MechanicalJustificationType) (models.VulnEvent, error) {
	if tx == nil {
		var ev models.VulnEvent
		var err error
		// we are not part of a parent transaction - create a new one
		err = s.firstPartyVulnRepository.Transaction(func(d core.DB) error {
			ev, err = s.updateFirstPartyVulnState(d, userID, firstPartyVuln, statusType, justification, mechanicalJustification)
			return err
		})
		return ev, err
	}
	return s.updateFirstPartyVulnState(tx, userID, firstPartyVuln, statusType, justification, mechanicalJustification)
}

func (s *firstPartyVulnService) updateFirstPartyVulnState(tx core.DB, userID string, firstPartyVuln *models.FirstPartyVuln, statusType string, justification string, mechanicalJustification models.MechanicalJustificationType) (models.VulnEvent, error) {
	var ev models.VulnEvent
	switch models.VulnEventType(statusType) {
	case models.EventTypeAccepted:
		ev = models.NewAcceptedEvent(firstPartyVuln.CalculateHash(), models.VulnTypeFirstPartyVuln, userID, justification, 0)
	case models.EventTypeFalsePositive:
		ev = models.NewFalsePositiveEvent(firstPartyVuln.CalculateHash(), models.VulnTypeFirstPartyVuln, userID, justification, mechanicalJustification, firstPartyVuln.ScannerIDs, 0)
	case models.EventTypeReopened:
		ev = models.NewReopenedEvent(firstPartyVuln.CalculateHash(), models.VulnTypeFirstPartyVuln, userID, justification, 0)
	case models.EventTypeComment:
		ev = models.NewCommentEvent(firstPartyVuln.CalculateHash(), models.VulnTypeFirstPartyVuln, userID, justification)
	}

	return s.applyAndSave(tx, firstPartyVuln, &ev)
}

func (s *firstPartyVulnService) ApplyAndSave(tx core.DB, firstPartyVuln *models.FirstPartyVuln, vulnEvent *models.VulnEvent) error {
	if tx == nil {
		// we are not part of a parent transaction - create a new one
		return s.firstPartyVulnRepository.Transaction(func(d core.DB) error {
			_, err := s.applyAndSave(d, firstPartyVuln, vulnEvent)
			return err
		})
	}

	_, err := s.applyAndSave(tx, firstPartyVuln, vulnEvent)
	return err
}

func (s *firstPartyVulnService) applyAndSave(tx core.DB, firstPartyVuln *models.FirstPartyVuln, ev *models.VulnEvent) (models.VulnEvent, error) {
	// apply the event on the first-party vuln
	ev.Apply(firstPartyVuln)

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
