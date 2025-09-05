package artifact

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type service struct {
	artifactRepository core.ArtifactRepository
}

func NewService(artifactRepository core.ArtifactRepository) *service {
	return &service{
		artifactRepository: artifactRepository,
	}
}

func (s *service) GetArtifactNamesByAssetIDAndAssetVersionName(assetID uuid.UUID, assetVersionName string) ([]models.Artifact, error) {
	artifacts, err := s.artifactRepository.GetByAssetIDAndAssetVersionName(assetID, assetVersionName)
	if err != nil {
		return nil, err
	}

	return artifacts, nil
}

func (s *service) SaveArtifact(artifact *models.Artifact) error {
	return s.artifactRepository.Save(nil, artifact)
}

func (s *service) DeleteArtifact(artifactName string, assetVersionName string, assetID uuid.UUID) error {
	return s.artifactRepository.DeleteArtifact(artifactName, assetVersionName, assetID)
}
