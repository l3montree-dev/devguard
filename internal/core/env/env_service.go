package env

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/core"
)

type DomainService struct {
	repository Repository
}

type Service interface {
	CreateDefaultEnvForApp(tx core.DB, assetID uuid.UUID) ([]Model, error)
}

func NewDomainService(repository Repository) *DomainService {
	return &DomainService{
		repository: repository,
	}
}

func (s *DomainService) CreateDefaultEnvForApp(tx core.DB, assetID uuid.UUID) ([]Model, error) {
	// create a default development and production environment
	devEnv := Model{
		Name:    "Development",
		AssetID: assetID,
		Slug:    "development",
	}

	prodEnv := Model{
		Name:      "Production",
		AssetID:   assetID,
		Slug:      "production",
		IsDefault: true,
	}

	// create the environments
	err := s.repository.Create(tx, &devEnv)
	if err != nil {
		return []Model{}, err
	}

	err = s.repository.Create(tx, &prodEnv)
	if err != nil {
		return []Model{}, err
	}

	return []Model{
		devEnv,
		prodEnv,
	}, nil
}
