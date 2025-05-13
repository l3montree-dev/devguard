package vuln

import (
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type firstPartyVulnService struct {
	firstPartyVulnRepository core.FirstPartyVulnRepository
	vulnEventRepository      core.VulnEventRepository

	assetRepository core.AssetRepository
}

func NewFirstPartyVulnService(firstPartyVulnRepository core.FirstPartyVulnRepository, vulnEventRepository core.VulnEventRepository, assetRepository core.AssetRepository) *firstPartyVulnService {
	return &firstPartyVulnService{
		firstPartyVulnRepository: firstPartyVulnRepository,
		vulnEventRepository:      vulnEventRepository,
		assetRepository:          assetRepository,
	}
}

func (s *firstPartyVulnService) UserFixedFirstPartyVulns(tx core.DB, userID string, firstPartyVulns []models.FirstPartyVuln) error {

	if len(firstPartyVulns) == 0 {
		return nil
	}

	events := make([]models.VulnEvent, len(firstPartyVulns))
	for i, vuln := range firstPartyVulns {
		ev := models.NewFixedEvent(vuln.CalculateHash(), models.VulnTypeFirstPartyVuln, userID, vuln.ScannerIDs)

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
		ev := models.NewDetectedEvent(firstPartyVuln.CalculateHash(), models.VulnTypeFirstPartyVuln, userID, common.RiskCalculationReport{}, scannerID)
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
		ev = models.NewAcceptedEvent(firstPartyVuln.CalculateHash(), models.VulnTypeFirstPartyVuln, userID, justification)
	case models.EventTypeFalsePositive:
		ev = models.NewFalsePositiveEvent(firstPartyVuln.CalculateHash(), models.VulnTypeFirstPartyVuln, userID, justification, mechanicalJustification, firstPartyVuln.ScannerIDs)
	case models.EventTypeReopened:
		ev = models.NewReopenedEvent(firstPartyVuln.CalculateHash(), models.VulnTypeFirstPartyVuln, userID, justification)
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
	// apply the event on the dependencyVuln
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
