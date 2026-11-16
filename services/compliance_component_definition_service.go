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
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
)

type complianceComponentDefinitionService struct {
	complianceComponentRepository shared.ComplianceComponentRepository
}

func NewComplianceComponentDefinitionService(complianceComponentRepository shared.ComplianceComponentRepository) *complianceComponentDefinitionService {
	return &complianceComponentDefinitionService{
		complianceComponentRepository: complianceComponentRepository,
	}
}

func (s *complianceComponentDefinitionService) SaveComponentDefinition(ctx context.Context, tx shared.DB, orgID uuid.UUID, projectID *uuid.UUID, assetID *uuid.UUID, name string, data []byte) error {
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

func (s *complianceComponentDefinitionService) DeleteComponentDefinition(ctx context.Context, tx shared.DB, orgID uuid.UUID, projectID *uuid.UUID, assetID *uuid.UUID, name string) error {
	deleted, err := s.complianceComponentRepository.DeleteComponentDefinition(ctx, tx, orgID, projectID, assetID, name)
	if err != nil {
		return echo.NewHTTPError(500, "could not delete component definition").WithInternal(err)
	}
	if !deleted {
		return echo.NewHTTPError(404, "component definition is not uploaded in this scope")
	}
	return nil
}
