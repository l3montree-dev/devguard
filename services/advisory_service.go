package services

import (
	"context"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
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

func (s *AdvisoryService) Create(ctx context.Context, advisory *models.Advisory) error {
	return s.advisoryRepository.Create(ctx, nil, advisory)
}

func (s *AdvisoryService) ReadAll(ctx context.Context, assetID uuid.UUID) ([]models.Advisory, error) {
	advisories, err := s.advisoryRepository.ReadAll(ctx, nil, assetID)
	if err != nil {
		return nil, err
	}
	return advisories, nil
}

func (s *AdvisoryService) ReadAdvisory(ctx context.Context, id uuid.UUID) (models.Advisory, error) {
	return s.advisoryRepository.ReadAdvisory(ctx, nil, id)
}

func (s *AdvisoryService) Update(ctx context.Context, id uuid.UUID, advisory *models.Advisory) error {
	return s.advisoryRepository.Update(ctx, nil, id, advisory)
}

func (s *AdvisoryService) Delete(ctx context.Context, id uuid.UUID) error {
	return s.advisoryRepository.Delete(ctx, nil, id)
}
