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

func (s *AdvisoryService) CreateName(ctx context.Context, name string) error {
	return s.advisoryRepository.CreateName(ctx, nil, name)
}

func (s *AdvisoryService) ReadName(ctx context.Context) ([]models.Advisory, error) {
	advisory_names, err := s.advisoryRepository.ReadName(ctx, nil)
	if err != nil {
		return nil, err
	}
	return advisory_names, nil
}

func (s *AdvisoryService) UpdateName(ctx context.Context, id uuid.UUID, name string) error {
	return s.advisoryRepository.UpdateName(ctx, nil, id, name)
}

func (s *AdvisoryService) DeleteName(ctx context.Context, id uuid.UUID) error {
	return s.advisoryRepository.DeleteName(ctx, nil, id)
}
