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
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
)

type dependencyProxySecretService struct {
	dependencyProxySecretRepository shared.DependencyProxySecretRepository
}

func NewDependencyProxyService(dependencyProxySecretRepository shared.DependencyProxySecretRepository) *dependencyProxySecretService {
	return &dependencyProxySecretService{
		dependencyProxySecretRepository: dependencyProxySecretRepository,
	}
}

func (s *dependencyProxySecretService) GetOrCreateByOrgID(ctx context.Context, orgID uuid.UUID) (models.DependencyProxySecret, error) {
	return s.dependencyProxySecretRepository.GetOrCreateByOrgID(ctx, nil, orgID)
}

func (s *dependencyProxySecretService) GetOrCreateByProjectID(ctx context.Context, projectID uuid.UUID) (models.DependencyProxySecret, error) {
	return s.dependencyProxySecretRepository.GetOrCreateByProjectID(ctx, nil, projectID)
}

func (s *dependencyProxySecretService) GetOrCreateByAssetID(ctx context.Context, assetID uuid.UUID) (models.DependencyProxySecret, error) {
	return s.dependencyProxySecretRepository.GetOrCreateByAssetID(ctx, nil, assetID)
}

func (s *dependencyProxySecretService) UpdateSecret(ctx context.Context, proxy models.DependencyProxySecret) (models.DependencyProxySecret, error) {

	return s.dependencyProxySecretRepository.UpdateSecret(ctx, nil, proxy)
}

func (s *dependencyProxySecretService) GetModelBySecret(ctx context.Context, secret uuid.UUID) (string, uuid.UUID, error) {
	proxy, err := s.dependencyProxySecretRepository.GetBySecret(ctx, nil, secret)
	if err != nil {
		return "", uuid.Nil, err
	}

	var uuid uuid.UUID
	var scope string
	if proxy.AssetID != nil {
		scope = "asset"
		uuid = *proxy.AssetID
	} else if proxy.ProjectID != nil {
		scope = "project"
		uuid = *proxy.ProjectID

	} else if proxy.OrgID != nil {
		scope = "organization"
		uuid = *proxy.OrgID
	}

	return scope, uuid, nil
}
