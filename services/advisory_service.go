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

func (s *AdvisoryService) Create(ctx context.Context, tx shared.DB, advisory *models.Advisory) error {
	return s.advisoryRepository.Create(ctx, tx, advisory)
}

func (s *AdvisoryService) ReadAll(ctx context.Context, tx shared.DB, assetID uuid.UUID, filter []shared.FilterQuery, pagnation shared.PageInfo) (shared.Paged[models.Advisory], error) {
	return s.advisoryRepository.ReadAll(ctx, tx, assetID, filter, pagnation)
}

func (s *AdvisoryService) ReadAdvisory(ctx context.Context, tx shared.DB, id int64) (models.Advisory, error) {
	return s.advisoryRepository.ReadAdvisory(ctx, tx, id)
}

func (s *AdvisoryService) Update(ctx context.Context, tx shared.DB, id int64, advisory *models.Advisory) error {
	return s.advisoryRepository.Update(ctx, tx, id, advisory)
}

func (s *AdvisoryService) Delete(ctx context.Context, tx shared.DB, id int64) error {
	return s.advisoryRepository.Delete(ctx, tx, id)
}
