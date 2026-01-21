// Copyright (C) 2025 l3montree GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package services

import (
	"log/slog"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/l3montree-dev/devguard/vulndb/scan"
)

type scanService struct {
	sbomScanner           shared.SBOMScanner
	assetVersionService   shared.AssetVersionService
	dependencyVulnService shared.DependencyVulnService
	artifactService       shared.ArtifactService
	statisticsService     shared.StatisticsService
	// mark public to let it be overridden in tests
	utils.FireAndForgetSynchronizer
}

func NewScanService(db shared.DB, cveRepository shared.CveRepository, assetVersionService shared.AssetVersionService, dependencyVulnService shared.DependencyVulnService, artifactService shared.ArtifactService, statisticsService shared.StatisticsService, synchronizer utils.FireAndForgetSynchronizer) *scanService {
	purlComparer := scan.NewPurlComparer(db)
	scanner := scan.NewSBOMScanner(purlComparer, cveRepository)
	return &scanService{
		sbomScanner:               scanner,
		assetVersionService:       assetVersionService,
		dependencyVulnService:     dependencyVulnService,
		artifactService:           artifactService,
		statisticsService:         statisticsService,
		FireAndForgetSynchronizer: synchronizer}
}

var _ shared.ScanService = &scanService{}

func (s *scanService) ScanNormalizedSBOM(tx shared.DB, org models.Org, project models.Project, asset models.Asset, assetVersion models.AssetVersion, artifact models.Artifact, normalizedBom *normalize.SBOMGraph, userID string) ([]models.DependencyVuln, []models.DependencyVuln, []models.DependencyVuln, error) {
	// remove all other artifacts from the bom
	err := normalizedBom.ScopeToArtifact(artifact.ArtifactName)
	if err != nil {
		slog.Error("could not scope bom to artifact", "err", err)
		return nil, nil, nil, err
	}
	vulns, err := s.sbomScanner.Scan(normalizedBom)

	if err != nil {
		slog.Error("could not scan file", "err", err)
		return nil, nil, nil, err
	}

	// handle the scan result
	opened, closed, newState, err := s.assetVersionService.HandleScanResult(tx, org, project, asset, &assetVersion, normalizedBom, vulns, artifact.ArtifactName, userID, dtos.UpstreamStateInternal)
	if err != nil {
		slog.Error("could not handle scan result", "err", err)
		return nil, nil, nil, err
	}

	return opened, closed, newState, nil
}
