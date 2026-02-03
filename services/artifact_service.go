package services

import (
	"log/slog"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
)

type ArtifactService struct {
	csafService            shared.CSAFService
	artifactRepository     shared.ArtifactRepository
	cveRepository          shared.CveRepository
	componentRepository    shared.ComponentRepository
	assetVersionRepository shared.AssetVersionRepository
	assetVersionService    shared.AssetVersionService
	dependencyVulnService  shared.DependencyVulnService
	scanService            shared.ScanService
}

func NewArtifactService(artifactRepository shared.ArtifactRepository,
	csafService shared.CSAFService,
	cveRepository shared.CveRepository, componentRepository shared.ComponentRepository, assetVersionRepository shared.AssetVersionRepository, assetVersionService shared.AssetVersionService, dependencyVulnService shared.DependencyVulnService, scanService shared.ScanService) *ArtifactService {
	return &ArtifactService{
		csafService:            csafService,
		artifactRepository:     artifactRepository,
		cveRepository:          cveRepository,
		componentRepository:    componentRepository,
		assetVersionRepository: assetVersionRepository,
		assetVersionService:    assetVersionService,
		dependencyVulnService:  dependencyVulnService,
		scanService:            scanService,
	}
}

func (s *ArtifactService) GetArtifactsByAssetIDAndAssetVersionName(assetID uuid.UUID, assetVersionName string) ([]models.Artifact, error) {
	artifacts, err := s.artifactRepository.GetByAssetIDAndAssetVersionName(assetID, assetVersionName)
	if err != nil {
		return nil, err
	}

	return artifacts, nil
}

func (s *ArtifactService) SaveArtifact(artifact *models.Artifact) error {
	return s.artifactRepository.Save(nil, artifact)
}

func (s *ArtifactService) DeleteArtifact(assetID uuid.UUID, assetVersionName string, artifactName string) error {
	assetVersion := models.AssetVersion{
		AssetID: assetID,
		Name:    assetVersionName,
	}

	// Execute deletion in a transaction
	return s.componentRepository.GetDB(nil).Transaction(func(tx *gorm.DB) error {
		// Load the full SBOM graph before deletion
		wholeAssetGraph, err := s.assetVersionService.LoadFullSBOMGraph(assetVersion)
		if err != nil {
			slog.Error("failed to load full SBOM for artifact deletion", "assetID", assetID, "assetVersionName", assetVersionName, "error", err)
			return err
		}

		// Delete the artifact and its subtree from the graph
		diff := wholeAssetGraph.DeleteArtifactFromGraph(artifactName)

		// Use HandleStateDiff to properly delete component dependencies
		if err := s.componentRepository.HandleStateDiff(tx, assetVersion, wholeAssetGraph, diff); err != nil {
			slog.Error("failed to handle state diff for artifact deletion", "assetID", assetID, "assetVersionName", assetVersionName, "artifactName", artifactName, "error", err)
			return err
		}

		// Delete the artifact record itself
		err = s.artifactRepository.DeleteArtifact(tx, assetID, assetVersionName, artifactName)
		if err != nil {
			slog.Error("failed to delete artifact record", "assetID", assetID, "assetVersionName", assetVersionName, "artifactName", artifactName, "error", err)
			return err
		}

		slog.Info("artifact deleted successfully", "assetID", assetID, "assetVersionName", assetVersionName, "artifactName", artifactName)
		return nil
	})
}

func (s *ArtifactService) ReadArtifact(name string, assetVersionName string, assetID uuid.UUID) (models.Artifact, error) {
	return s.artifactRepository.ReadArtifact(name, assetVersionName, assetID)
}
