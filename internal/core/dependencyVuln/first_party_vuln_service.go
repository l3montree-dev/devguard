package dependencyVuln

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/obj"
)

type firstPartyVulnRepository interface {
	repositories.Repository[string, models.FirstPartyVulnerability, core.DB]
	SaveBatch(tx core.DB, vulns []models.FirstPartyVulnerability) error
	Save(tx core.DB, vuln *models.FirstPartyVulnerability) error
	Transaction(txFunc func(core.DB) error) error
	Begin() core.DB
	GetDefaultFirstPartyVulnsByProjectIdPaged(tx core.DB, projectID uuid.UUID, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.FirstPartyVulnerability], error)
	GetDefaultFirstPartyVulnsByOrgIdPaged(tx core.DB, userAllowedProjectIds []string, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.FirstPartyVulnerability], error)
	GetFirstPartyVulnsByAssetIdPagedAndFlat(tx core.DB, assetVersionName string, assetID uuid.UUID, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.FirstPartyVulnerability], error)

	GetByAssetId(tx core.DB, assetId uuid.UUID) ([]models.FirstPartyVulnerability, error)
	GetByAssetVersionPaged(tx core.DB, assetVersionName string, assetID uuid.UUID, pageInfo core.PageInfo, search string, filter []core.FilterQuery, sort []core.SortQuery) (core.Paged[models.FirstPartyVulnerability], map[string]int, error)
}

type firstPartyVulnService struct {
	firstPartyVulnRepository firstPartyVulnRepository
	vulnEventRepository      vulnEventRepository

	assetRepository assetRepository
}

func NewFirstPartyVulnService(firstPartyVulnRepository firstPartyVulnRepository, vulnEventRepository vulnEventRepository, assetRepository assetRepository) *firstPartyVulnService {
	return &firstPartyVulnService{
		firstPartyVulnRepository: firstPartyVulnRepository,
		vulnEventRepository:      vulnEventRepository,
		assetRepository:          assetRepository,
	}
}

func (s *firstPartyVulnService) UserFixedFirstPartyVulns(tx core.DB, userID string, firstPartyVulns []models.FirstPartyVulnerability, doRiskManagement bool) error {

	if len(firstPartyVulns) == 0 {
		return nil
	}

	events := make([]models.VulnEvent, len(firstPartyVulns))
	for i, vuln := range firstPartyVulns {
		ev := models.NewFixedEvent(vuln.CalculateHash(), userID)

		ev.ApplyFirstPartyVulnEvent(&firstPartyVulns[i])
		events[i] = ev
	}

	if doRiskManagement {
		err := s.firstPartyVulnRepository.SaveBatch(tx, firstPartyVulns)
		if err != nil {
			return err
		}
		return s.vulnEventRepository.SaveBatch(tx, events)

	}
	return nil
}

func (s *firstPartyVulnService) UserDetectedFirstPartyVulns(tx core.DB, userID string, firstPartyVulns []models.FirstPartyVulnerability, doRiskManagement bool) error {
	if len(firstPartyVulns) == 0 {
		return nil
	}
	// create a new dependencyVulnevent for each fixed dependencyVuln
	events := make([]models.VulnEvent, len(firstPartyVulns))
	for i, firstPartyVuln := range firstPartyVulns {
		ev := models.NewDetectedEvent(firstPartyVuln.CalculateHash(), userID, obj.RiskCalculationReport{})
		// apply the event on the dependencyVuln
		ev.ApplyFirstPartyVulnEvent(&firstPartyVulns[i])
		events[i] = ev
	}

	if doRiskManagement {
		err := s.firstPartyVulnRepository.SaveBatch(tx, firstPartyVulns)
		if err != nil {
			return err
		}
		return s.vulnEventRepository.SaveBatch(tx, events)
	}

	return nil
}

func (s *firstPartyVulnService) UpdateFirstPartyVulnState(tx core.DB, userID string, firstPartyVuln *models.FirstPartyVulnerability, statusType string, justification string) (models.VulnEvent, error) {
	if tx == nil {
		var ev models.VulnEvent
		var err error
		// we are not part of a parent transaction - create a new one
		err = s.firstPartyVulnRepository.Transaction(func(d core.DB) error {
			ev, err = s.updateFirstPartyVulnState(d, userID, firstPartyVuln, statusType, justification)
			return err
		})
		return ev, err
	}
	return s.updateFirstPartyVulnState(tx, userID, firstPartyVuln, statusType, justification)
}

func (s *firstPartyVulnService) updateFirstPartyVulnState(tx core.DB, userID string, firstPartyVuln *models.FirstPartyVulnerability, statusType string, justification string) (models.VulnEvent, error) {
	var ev models.VulnEvent
	switch models.VulnEventType(statusType) {
	case models.EventTypeAccepted:
		ev = models.NewAcceptedEvent(firstPartyVuln.CalculateHash(), userID, justification)
	case models.EventTypeFalsePositive:
		ev = models.NewFalsePositiveEvent(firstPartyVuln.CalculateHash(), userID, justification)
	case models.EventTypeReopened:
		ev = models.NewReopenedEvent(firstPartyVuln.CalculateHash(), userID, justification)
	case models.EventTypeComment:
		ev = models.NewCommentEvent(firstPartyVuln.CalculateHash(), userID, justification)
	}

	return s.applyAndSave(tx, firstPartyVuln, &ev)
}

func (s *firstPartyVulnService) ApplyAndSave(tx core.DB, firstPartyVuln *models.FirstPartyVulnerability, vulnEvent *models.VulnEvent) error {
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

func (s *firstPartyVulnService) applyAndSave(tx core.DB, firstPartyVuln *models.FirstPartyVulnerability, ev *models.VulnEvent) (models.VulnEvent, error) {
	// apply the event on the dependencyVuln
	ev.ApplyFirstPartyVulnEvent(firstPartyVuln)

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
