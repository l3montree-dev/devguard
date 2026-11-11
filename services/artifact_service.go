package services

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/events"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
)

type ArtifactService struct {
	csafService              shared.CSAFService
	artifactRepository       shared.ArtifactRepository
	cveRepository            shared.CveRepository
	componentRepository      shared.ComponentRepository
	sbomRepository           shared.SBOMRepository
	assetVersionRepository   shared.AssetVersionRepository
	assetVersionService      shared.AssetVersionService
	dependencyVulnService    shared.DependencyVulnService
	dependencyVulnRepository shared.DependencyVulnRepository
	scanService              shared.ScanService
	broker                   events.Broker
}

var _ shared.ArtifactService = (*ArtifactService)(nil) // Ensure ArtifactService implements shared.ArtifactService interface

func NewArtifactService(artifactRepository shared.ArtifactRepository,
	csafService shared.CSAFService,
	cveRepository shared.CveRepository, componentRepository shared.ComponentRepository, sbomRepository shared.SBOMRepository, assetVersionRepository shared.AssetVersionRepository, assetVersionService shared.AssetVersionService, dependencyVulnService shared.DependencyVulnService, dependencyVulnRepository shared.DependencyVulnRepository, scanService shared.ScanService, broker events.Broker) *ArtifactService {
	return &ArtifactService{
		csafService:              csafService,
		artifactRepository:       artifactRepository,
		cveRepository:            cveRepository,
		componentRepository:      componentRepository,
		sbomRepository:           sbomRepository,
		assetVersionRepository:   assetVersionRepository,
		assetVersionService:      assetVersionService,
		dependencyVulnService:    dependencyVulnService,
		dependencyVulnRepository: dependencyVulnRepository,
		scanService:              scanService,
		broker:                   broker,
	}
}

func (s *ArtifactService) GetArtifactsByAssetVersionID(ctx context.Context, tx shared.DB, assetVersionID uuid.UUID) ([]models.Artifact, error) {
	artifacts, err := s.artifactRepository.GetByAssetVersionID(ctx, tx, assetVersionID)
	if err != nil {
		return nil, err
	}

	return artifacts, nil
}

func (s *ArtifactService) FindOrCreateArtifact(ctx context.Context, tx shared.DB, artifact *models.Artifact) error {
	return s.artifactRepository.FindOrCreate(ctx, tx, artifact)
}

func (s *ArtifactService) DeleteArtifact(ctx context.Context, assetVersion models.AssetVersion, artifactName string) error {
	// Execute deletion in a transaction
	if err := s.componentRepository.GetDB(ctx, nil).Transaction(func(tx *gorm.DB) error {
		// Drop this artifact's SBOMs. Only the pointers go: the subtrees stay
		// for the garbage collector, since other artifacts may share them.
		if err := s.sbomRepository.DeleteByArtifact(ctx, tx, assetVersion.ID, artifactName); err != nil {
			slog.Error("failed to delete sboms for artifact", "assetID", assetVersion.AssetID, "assetVersionName", assetVersion.Name, "artifactName", artifactName, "error", err)
			return err
		}

		// Delete the artifact record itself
		err := s.artifactRepository.DeleteArtifact(ctx, tx, assetVersion.ID, artifactName)
		if err != nil {
			slog.Error("failed to delete artifact record", "assetID", assetVersion.AssetID, "assetVersionName", assetVersion.Name, "artifactName", artifactName, "error", err)
			return err
		}

		slog.Info("artifact deleted successfully", "assetID", assetVersion.AssetID, "assetVersionName", assetVersion.Name, "artifactName", artifactName)
		return nil
	}); err != nil {
		return err
	}

	// after the commit - the cleanup has to see the committed state
	events.NotifyArtifactDeleted(ctx, s.broker, assetVersion.AssetID)

	return nil
}

func (s *ArtifactService) ReadArtifact(ctx context.Context, tx shared.DB, name string, assetVersionID uuid.UUID) (models.Artifact, error) {
	return s.artifactRepository.ReadArtifact(ctx, tx, name, assetVersionID)
}

// GatherVexInformation returns the unfixed dependency vulns for an asset
// version, trimming each vuln's Artifacts down to the requested artifact (if
// any). Each asset version's own state is authoritative for VEX export - it
// is never overridden based on another branch's state.
func (s *ArtifactService) GatherVexInformation(ctx context.Context, assetVersion models.AssetVersion, artifact *models.Artifact) ([]models.DependencyVuln, error) {
	var artifactID *uuid.UUID
	if artifact != nil {
		artifactID = &artifact.ID
	}
	dependencyVulns, err := s.dependencyVulnRepository.ListUnfixedByAssetAndAssetVersion(ctx, nil, assetVersion.ID, artifactID)
	if err != nil {
		return nil, err
	}

	if artifact != nil {
		for i := range dependencyVulns {
			dependencyVulns[i].Artifacts = utils.Filter(dependencyVulns[i].Artifacts, func(a models.Artifact) bool {
				return a.ID == artifact.ID
			})
		}
	}

	return dependencyVulns, nil
}
