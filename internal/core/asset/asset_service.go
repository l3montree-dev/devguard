// Copyright (C) 2024 Tim Bastin, l3montree UG (haftungsbeschränkt)
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

package asset

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type service struct {
	assetRepository          core.AssetRepository
	dependencyVulnRepository core.DependencyVulnRepository
	dependencyVulnService    core.DependencyVulnService
	httpClient               *http.Client
}

func NewService(assetRepository core.AssetRepository, dependencyVulnRepository core.DependencyVulnRepository, dependencyVulnService core.DependencyVulnService) *service {
	return &service{
		assetRepository:          assetRepository,
		dependencyVulnRepository: dependencyVulnRepository,
		dependencyVulnService:    dependencyVulnService,
		httpClient:               &http.Client{},
	}
}

func (s *service) GetByAssetID(assetID uuid.UUID) (models.Asset, error) {
	return s.assetRepository.Read(assetID)
}

func (s *service) UpdateAssetRequirements(asset models.Asset, responsible string, justification string) error {
	err := s.dependencyVulnRepository.Transaction(func(tx core.DB) error {

		err := s.assetRepository.Save(tx, &asset)
		if err != nil {
			slog.Info("error saving asset", "err", err)
			return fmt.Errorf("could not save asset: %v", err)
		}
		// get the dependencyVulns
		dependencyVulns, err := s.dependencyVulnRepository.GetAllVulnsByAssetID(tx, asset.GetID())
		if err != nil {
			slog.Info("error getting dependencyVulns", "err", err)
			return fmt.Errorf("could not get dependencyVulns: %v", err)
		}

		err = s.dependencyVulnService.RecalculateRawRiskAssessment(tx, responsible, dependencyVulns, justification, asset)
		if err != nil {
			slog.Info("error updating raw risk assessment", "err", err)
			return fmt.Errorf("could not update raw risk assessment: %v", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("could not update asset: %v", err)
	}

	return nil
}

func (s *service) GetCVSSBadgeSVG(CVSS models.AssetRiskDistribution) string {

	if CVSS.AssetVersionName == "" {
		return core.GetBadgeSVG("CVSS", []core.BadgeValues{})
	}

	values := []core.BadgeValues{
		{Key: "C", Value: CVSS.Critical, Color: "#8B0000"},
		{Key: "H", Value: CVSS.High, Color: "#B22222"},
		{Key: "M", Value: CVSS.Medium, Color: "#CD5C5C"},
		{Key: "L", Value: CVSS.Low, Color: "#F08080"},
	}
	return core.GetBadgeSVG("CVSS", values)
}
