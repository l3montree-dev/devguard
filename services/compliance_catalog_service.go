// Copyright (C) 2026 l3montree GmbH
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
	"context"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/compliance"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
)

type complianceCatalogService struct {
	frameworkControlRepository    shared.FrameworkControlRepository
	complianceComponentRepository shared.ComplianceComponentRepository
}

func NewComplianceCatalogService(frameworkControlRepository shared.FrameworkControlRepository, complianceComponentRepository shared.ComplianceComponentRepository) *complianceCatalogService {
	return &complianceCatalogService{
		frameworkControlRepository:    frameworkControlRepository,
		complianceComponentRepository: complianceComponentRepository,
	}
}

func (s *complianceCatalogService) SaveCatalog(ctx context.Context, tx shared.DB, orgID uuid.UUID, projectID *uuid.UUID, assetID *uuid.UUID, name string, data []byte) error {
	title, controls, err := compliance.ParseCatalog(data)
	if err != nil {
		return echo.NewHTTPError(400, "invalid OSCAL catalog").WithInternal(err)
	}
	if name == "" {
		name = title
	}
	if name == "" {
		return echo.NewHTTPError(400, "the catalog has no title, please provide a name")
	}

	scopeFramework := models.ScopeFramework{
		Framework: name,
		OrgID:     orgID,
		ProjectID: projectID,
		AssetID:   assetID,
		Controls:  controls,
	}
	if err := s.frameworkControlRepository.SaveScopeFramework(ctx, tx, &scopeFramework); err != nil {
		return echo.NewHTTPError(500, "could not save catalog").WithInternal(err)
	}
	return nil
}

func (s *complianceCatalogService) DeleteCatalog(ctx context.Context, tx shared.DB, orgID uuid.UUID, projectID *uuid.UUID, assetID *uuid.UUID, name string) error {
	deleted, err := s.frameworkControlRepository.DeleteScopeFramework(ctx, tx, orgID, projectID, assetID, name)
	if err != nil {
		return echo.NewHTTPError(500, "could not delete catalog").WithInternal(err)
	}
	if !deleted {
		return echo.NewHTTPError(404, "catalog is not activated in this scope")
	}
	return nil
}

func (s *complianceCatalogService) ListCatalogs(ctx context.Context, tx shared.DB, orgID uuid.UUID, projectID *uuid.UUID, assetID *uuid.UUID) ([]dtos.ScopeFramework, error) {
	scopeFrameworks, err := s.frameworkControlRepository.GetEffectiveScopeFrameworks(ctx, tx, orgID, projectID, assetID)
	if err != nil {
		return nil, echo.NewHTTPError(500, "could not list catalogs").WithInternal(err)
	}

	catalogs := make([]dtos.ScopeFramework, 0, len(scopeFrameworks))
	for _, sf := range scopeFrameworks {
		catalogs = append(catalogs, dtos.ScopeFramework{
			Framework: sf.Framework,
			ProjectID: sf.ProjectID,
			AssetID:   sf.AssetID,
		})
	}
	return catalogs, nil
}

func (s *complianceCatalogService) SaveComponentDefinition(ctx context.Context, tx shared.DB, orgID uuid.UUID, projectID *uuid.UUID, assetID *uuid.UUID, name string, data []byte) error {
	title, components, err := compliance.ParseComponentDefinition(data)
	if err != nil {
		return echo.NewHTTPError(400, "invalid OSCAL component definition").WithInternal(err)
	}
	if name == "" {
		name = title
	}
	if name == "" {
		return echo.NewHTTPError(400, "the component definition has no title, please provide a name")
	}

	if err := s.complianceComponentRepository.SaveComponentDefinition(ctx, tx, orgID, projectID, assetID, name, components); err != nil {
		return echo.NewHTTPError(500, "could not save component definition").WithInternal(err)
	}
	return nil
}

func (s *complianceCatalogService) DeleteComponentDefinition(ctx context.Context, tx shared.DB, orgID uuid.UUID, projectID *uuid.UUID, assetID *uuid.UUID, name string) error {
	deleted, err := s.complianceComponentRepository.DeleteComponentDefinition(ctx, tx, orgID, projectID, assetID, name)
	if err != nil {
		return echo.NewHTTPError(500, "could not delete component definition").WithInternal(err)
	}
	if !deleted {
		return echo.NewHTTPError(404, "component definition is not uploaded in this scope")
	}
	return nil
}

func (s *complianceCatalogService) ListComponentDefinitions(ctx context.Context, tx shared.DB, orgID uuid.UUID, projectID *uuid.UUID, assetID *uuid.UUID) ([]dtos.ScopeComponentDefinition, error) {
	components, err := s.complianceComponentRepository.ListAll(ctx, tx, orgID, projectID, assetID, nil)
	if err != nil {
		return nil, echo.NewHTTPError(500, "could not list component definitions").WithInternal(err)
	}

	definitions := make([]dtos.ScopeComponentDefinition, 0)
	seen := make(map[string]bool)
	for _, c := range components {
		if c.ComponentDefinition == nil || seen[*c.ComponentDefinition] {
			continue
		}
		seen[*c.ComponentDefinition] = true
		definitions = append(definitions, dtos.ScopeComponentDefinition{
			ComponentDefinition: *c.ComponentDefinition,
			ProjectID:           c.ProjectID,
			AssetID:             c.AssetID,
		})
	}
	return definitions, nil
}
