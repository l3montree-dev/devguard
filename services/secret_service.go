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
	"fmt"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
)

type secretService struct {
	secretRepository  shared.SecretRepository
	projectRepository shared.ProjectRepository
}

func NewSecretService(secretRepository shared.SecretRepository, projectRepository shared.ProjectRepository) *secretService {
	return &secretService{
		secretRepository:  secretRepository,
		projectRepository: projectRepository,
	}
}

func (s *secretService) Resolve(ctx context.Context, orgID uuid.UUID, projectID, assetID *uuid.UUID, name string) (string, error) {
	var value string

	chain, err := s.ProjectChain(ctx, projectID)
	if err != nil {
		return "", err
	}

	projectSecretPosition := len(chain)

	secrets, err := s.secretRepository.FindVisible(ctx, nil, orgID, projectID, assetID)
	if err != nil {
		return "", fmt.Errorf("could not find secrets: %w", err)
	}

	for _, secret := range secrets {
		if secret.Name != name {
			continue
		}
		if secret.AssetID != nil {
			return secret.Value, nil
		}
		if secret.ProjectID != nil {
			for i := range chain {
				if chain[i].ID == *secret.ProjectID && i < projectSecretPosition {
					value = secret.Value
					projectSecretPosition = i
				}
			}
		}
		if secret.OrgID != nil && value == "" {
			value = secret.Value
		}
	}
	if value == "" {
		return "", fmt.Errorf("secret %s not found", name)
	}
	return value, nil
}

func (s *secretService) ProjectChain(ctx context.Context, projectID *uuid.UUID) ([]models.Project, error) {
	if projectID == nil {
		return nil, nil
	}

	project, err := s.projectRepository.Read(ctx, nil, *projectID)
	if err != nil {
		return nil, err
	}

	chain := []models.Project{project}
	for project.ParentID != nil {
		project, err = s.projectRepository.Read(ctx, nil, *project.ParentID)
		if err != nil {
			return nil, err
		}
		chain = append(chain, project)
	}
	return chain, nil
}
