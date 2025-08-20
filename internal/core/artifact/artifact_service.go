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

func (s *service) GetArtifactNamesByAssetIDAndAssetVersionName(assetID uuid.UUID, assetVersionName string) ([]string, error) {
	artifacts, err := s.artifactRepository.GetByAssetIDAndAssetVersionName(assetID, assetVersionName)
	if err != nil {
		return nil, err
	}

	artifactNames := make([]string, len(artifacts))
	for i, artifact := range artifacts {
		artifactNames[i] = artifact.ArtifactName
	}

	return artifactNames, nil
}

func (s *service) SaveArtifact(artifact models.Artifact) error {
	return s.artifactRepository.Save(nil, &artifact)
}
