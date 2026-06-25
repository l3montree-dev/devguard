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

func (s *AdvisoryService) ReadName(ctx context.Context) ([]models.Advisory, error) {
	advisoryNames, err := s.advisoryRepository.ReadName(ctx, nil)
	if err != nil {
		return nil, err
	}
	return advisoryNames, nil
}

func (s *AdvisoryService) UpdateName(ctx context.Context, id uuid.UUID, name string) error {
	return s.advisoryRepository.UpdateName(ctx, nil, id, name)
}

func (s *AdvisoryService) DeleteName(ctx context.Context, id uuid.UUID) error {
	return s.advisoryRepository.DeleteName(ctx, nil, id)
}
