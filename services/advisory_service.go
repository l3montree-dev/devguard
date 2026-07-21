package services

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/statemachine"
)

type AdvisoryService struct {
	advisoryRepository shared.AdvisoryRepository
}

func NewAdvisoryService(advisoryRepository shared.AdvisoryRepository) *AdvisoryService {
	return &AdvisoryService{
		advisoryRepository: advisoryRepository,
	}
}

var _ shared.AdvisoryService = (*AdvisoryService)(nil)

func (s *AdvisoryService) Create(ctx context.Context, tx shared.DB, advisory *models.Advisory) error {
	return s.advisoryRepository.Create(ctx, tx, advisory)
}

func (s *AdvisoryService) ReadAll(ctx context.Context, tx shared.DB, assetID uuid.UUID, filter []shared.FilterQuery, pagnation shared.PageInfo) (shared.Paged[models.Advisory], error) {
	return s.advisoryRepository.ReadAll(ctx, tx, assetID, filter, pagnation)
}

func (s *AdvisoryService) ReadAdvisory(ctx context.Context, tx shared.DB, id uuid.UUID) (models.Advisory, error) {
	return s.advisoryRepository.ReadAdvisory(ctx, tx, id)
}

func (s *AdvisoryService) Update(ctx context.Context, tx shared.DB, id uuid.UUID, advisory *models.Advisory, currentVisibility string) error {
	if currentVisibility != advisory.Visibility {
		if err := statemachine.CheckStateTransition(currentVisibility, advisory.Visibility); err != nil {
			return fmt.Errorf("invalid state change from %q to %q: %w", currentVisibility, advisory.Visibility, err)
		}
	}
	return s.advisoryRepository.Update(ctx, tx, id, advisory)
}

func (s *AdvisoryService) Delete(ctx context.Context, tx shared.DB, id uuid.UUID) error {
	advisory, err := s.advisoryRepository.ReadAdvisory(ctx, tx, id)
	if err != nil {
		return err
	}
	if err := statemachine.CanDelete(advisory.Visibility); err != nil {
		return err
	}
	return s.advisoryRepository.Delete(ctx, tx, id)
}

func (s *AdvisoryService) CreateVulnEventAndApply(ctx context.Context, tx shared.DB, userID string, advisory *models.Advisory, vulnEventType dtos.VulnEventType, justification string, mechanicalJustification dtos.MechanicalJustificationType, userAgent *string) (models.VulnEvent, error) {
	return s.createVulnEventAndApply(ctx, tx, userID, advisory, vulnEventType, justification, mechanicalJustification, userAgent)
}

func (s *AdvisoryService) createVulnEventAndApply(ctx context.Context, tx shared.DB, userID string, advisory *models.Advisory, vulnEventType dtos.VulnEventType, justification string, mechanicalJustification dtos.MechanicalJustificationType, userAgent *string) (models.VulnEvent, error) {
	var ev models.VulnEvent
	switch vulnEventType {
	case dtos.EventTypeCreated:
		ev = models.NewCreatedSecurityAdvisoryEvent(advisory.ID, dtos.VulnTypeSecurityAdvisory, userID, false, userAgent)
	case dtos.EventTypeComment:
		ev = models.NewCommentEvent(advisory.ID, dtos.VulnTypeSecurityAdvisory, userID, justification, false, userAgent)
	case dtos.EventTypePublish:
		ev = models.NewPublishedSecurityAdvisoryEvent(advisory.ID, dtos.VulnTypeSecurityAdvisory, userID, false, userAgent)
	case dtos.EventTypeWithdraw:
		ev = models.NewWithdrawnSecurityAdvisoryEvent(advisory.ID, dtos.VulnTypeSecurityAdvisory, userID, false, userAgent)
	}

	// Apply the event to the original vuln
	err := s.advisoryRepository.ApplyAndSave(ctx, tx, advisory, &ev)
	if err != nil {
		return ev, err
	}

	return ev, nil
}
