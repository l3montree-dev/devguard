package services

import (
	"context"

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
