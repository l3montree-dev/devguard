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

func (s *service) DeleteArtifact(assetID uuid.UUID, assetVersionName string, artifactName string) error {
	return s.artifactRepository.DeleteArtifact(assetID, assetVersionName, artifactName)
}

func (s *service) AddUpstreamURLs(artifact *models.Artifact, upstreamURLs []string) error {
	return s.artifactRepository.AddUpstreamURLs(artifact, upstreamURLs)
}

func (s *service) RemoveUpstreamURLs(artifact *models.Artifact, upstreamURLs []string) error {
	return s.artifactRepository.RemoveUpstreamURLs(artifact, upstreamURLs)
}

func (s *service) ReadArtifact(name string, assetVersionName string, assetID uuid.UUID) (models.Artifact, error) {
	return s.artifactRepository.ReadArtifact(name, assetVersionName, assetID)
}
