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
package services

import (
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
	"github.com/ory/client-go"
)

type assetService struct {
	assetRepository          shared.AssetRepository
	dependencyVulnRepository shared.DependencyVulnRepository
	dependencyVulnService    shared.DependencyVulnService
}

func NewAssetService(assetRepository shared.AssetRepository, dependencyVulnRepository shared.DependencyVulnRepository, dependencyVulnService shared.DependencyVulnService) *assetService {
	return &assetService{
		assetRepository:          assetRepository,
		dependencyVulnRepository: dependencyVulnRepository,
		dependencyVulnService:    dependencyVulnService,
	}
}

func (s *assetService) CreateAsset(rbac shared.AccessControl, currentUser string, asset models.Asset) (*models.Asset, error) {
	newAsset := asset
	if newAsset.Name == "" || newAsset.Slug == "" {
		return nil, echo.NewHTTPError(409, "assets with an empty name or an empty slug are not allowed").WithInternal(fmt.Errorf("assets with an empty name or an empty slug are not allowed"))
	}
	err := s.assetRepository.Create(nil, &newAsset)

	if err != nil {
		return nil, echo.NewHTTPError(500, "could not create asset").WithInternal(err)
	}

	// bootstrap the asset in the rbac system
	if err := s.BootstrapAsset(rbac, &newAsset); err != nil {
		slog.Error("error bootstrapping asset in rbac", "err", err)
		return nil, err
	}

	// make the current user the admin of the asset
	if err := rbac.GrantRoleInAsset(currentUser, shared.RoleAdmin, newAsset.GetID().String()); err != nil {
		slog.Error("error assigning current user as asset admin", "err", err)
		return nil, err
	}

	return &newAsset, nil
}

func (s *assetService) BootstrapAsset(rbac shared.AccessControl, asset *models.Asset) error {
	// make sure and project admin is an asset admin - Always
	if err := rbac.LinkProjectAndAssetRole(shared.RoleAdmin, shared.RoleAdmin, asset.ProjectID.String(), asset.GetID().String()); err != nil {
		return err
	}

	// give the admin of an asset all the permissions of a member
	if err := rbac.InheritAssetRole(shared.RoleAdmin, shared.RoleMember, asset.GetID().String()); err != nil {
		return err
	}

	if err := rbac.AllowRoleInAsset(asset.GetID().String(), shared.RoleMember, shared.ObjectAsset, []shared.Action{shared.ActionRead}); err != nil {
		return err
	}
	if err := rbac.AllowRoleInAsset(asset.GetID().String(), shared.RoleAdmin, shared.ObjectAsset, []shared.Action{shared.ActionRead, shared.ActionUpdate, shared.ActionDelete}); err != nil {
		return err
	}

	return nil
}

func (s *assetService) GetByAssetID(assetID uuid.UUID) (models.Asset, error) {
	return s.assetRepository.Read(assetID)
}

func (s *assetService) UpdateAssetRequirements(asset models.Asset, responsible string, justification string) error {
	err := s.dependencyVulnRepository.Transaction(func(tx shared.DB) error {

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

		_, err = s.dependencyVulnService.RecalculateRawRiskAssessment(tx, responsible, dependencyVulns, justification, asset)
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

func (s *assetService) GetCVSSBadgeSVG(results []models.ArtifactRiskHistory) string {

	if len(results) == 0 {
		return shared.GetBadgeSVG("CVSS", []shared.BadgeValues{
			{Key: "unknown", Value: 0, Color: "#808080"},
		})
	}
	var CVSS models.Distribution

	for _, result := range results {
		CVSS.Critical += result.CVEPurlCriticalCVSS
		CVSS.High += result.CVEPurlHighCVSS
		CVSS.Medium += result.CVEPurlMediumCVSS
		CVSS.Low += result.CVEPurlLowCVSS
	}

	if CVSS.Critical == 0 && CVSS.High == 0 && CVSS.Medium == 0 && CVSS.Low == 0 {
		return shared.GetBadgeSVG("CVSS", []shared.BadgeValues{
			{Key: "all clear", Value: 0, Color: "#008000"},
		})
	}

	values := []shared.BadgeValues{
		{Key: "C", Value: CVSS.Critical, Color: "#8B0000"},
		{Key: "H", Value: CVSS.High, Color: "#B22222"},
		{Key: "M", Value: CVSS.Medium, Color: "#CD5C5C"},
		{Key: "L", Value: CVSS.Low, Color: "#F08080"},
	}
	return shared.GetBadgeSVG("CVSS", values)

}

func FetchMembersOfAsset(ctx shared.Context) ([]dtos.UserDTO, error) {
	asset := shared.GetAsset(ctx)
	// get rbac
	rbac := shared.GetRBAC(ctx)

	members, err := rbac.GetAllMembersOfAsset(asset.ID.String())
	if err != nil {
		return nil, echo.NewHTTPError(500, "could not get members of project").WithInternal(err)
	}
	if len(members) == 0 {
		return []dtos.UserDTO{}, nil
	}

	// get the auth admin client from the context
	authAdminClient := shared.GetAuthAdminClient(ctx)
	// fetch the users from the auth service
	m, err := authAdminClient.ListUser(client.IdentityAPIListIdentitiesRequest{}.Ids(members))

	if err != nil {
		return nil, echo.NewHTTPError(500, "could not get members").WithInternal(err)
	}

	users := utils.Map(m, func(i client.Identity) dtos.UserDTO {
		name := shared.IdentityName(i.Traits)
		role, err := rbac.GetAssetRole(i.Id, asset.ID.String())
		if err != nil {
			return dtos.UserDTO{
				ID:   i.Id,
				Name: name,
			}
		}
		return dtos.UserDTO{
			ID:   i.Id,
			Name: name,
			Role: string(role),
		}
	})

	return users, nil
}
