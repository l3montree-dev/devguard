// Copyright (C) 2024 Tim Bastin, l3montree GmbH
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
	"github.com/l3montree-dev/devguard/internal/database"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/labstack/echo/v4"
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

func (s *service) CreateAsset(asset models.Asset) (*models.Asset, error) {

	newAsset := asset

	if newAsset.Name == "" || newAsset.Slug == "" {
		return nil, echo.NewHTTPError(409, "assets with an empty name or an empty slug are not allowed").WithInternal(fmt.Errorf("assets with an empty name or an empty slug are not allowed"))
	}
	err := s.assetRepository.Create(nil, &newAsset)

	if err != nil {
		if database.IsDuplicateKeyError(err) {
			// get the asset by slug and project id unscoped
			asset, err := s.assetRepository.ReadBySlugUnscoped(newAsset.ProjectID, newAsset.Slug)
			if err != nil {
				return nil, echo.NewHTTPError(500, "could not read asset").WithInternal(err)
			}

			if err = s.assetRepository.Activate(nil, newAsset.GetID()); err != nil {
				return nil, echo.NewHTTPError(500, "could not activate asset").WithInternal(err)
			}
			slog.Info("Asset activated", "assetSlug", asset.Slug, "projectID", asset.ProjectID)
			newAsset = asset
		} else {
			return nil, echo.NewHTTPError(500, "could not create asset").WithInternal(err)
		}
	}

	return &newAsset, nil

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

func (s *service) GetCVSSBadgeSVG(results []models.ArtifactRiskHistory) string {

	if len(results) == 0 {
		return core.GetBadgeSVG("CVSS", []core.BadgeValues{
			{Key: "unknown", Value: 0, Color: "#808080"},
		})
	} else {

		CVSS := results[0].Distribution

		if CVSS.Critical == 0 && CVSS.High == 0 && CVSS.Medium == 0 && CVSS.Low == 0 {
			return core.GetBadgeSVG("CVSS", []core.BadgeValues{
				{Key: "all clear", Value: 0, Color: "#008000"},
			})
		}

		values := []core.BadgeValues{
			{Key: "C", Value: CVSS.Critical, Color: "#8B0000"},
			{Key: "H", Value: CVSS.High, Color: "#B22222"},
			{Key: "M", Value: CVSS.Medium, Color: "#CD5C5C"},
			{Key: "L", Value: CVSS.Low, Color: "#F08080"},
		}
		return core.GetBadgeSVG("CVSS", values)
	}

}
