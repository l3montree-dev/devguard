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
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
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

var _ shared.SecretService = &secretService{}

func (s *secretService) GetSecrets(ctx context.Context, orgID uuid.UUID, projectID, assetID *uuid.UUID, orgName string, assetName *string) ([]dtos.SecretDTO, error) {
	secrets, err := s.secretRepository.All(ctx, nil, orgID, projectID, assetID)
	if err != nil {
		return nil, err
	}

	var chain []models.Project
	if projectID != nil {
		chain, err = s.projectRepository.GetAncestors(ctx, nil, *projectID)
		if err != nil {
			return nil, err
		}
	}

	ownLevel := len(chain) + 1
	if assetID != nil {
		ownLevel = 0
	} else if projectID != nil {
		ownLevel = 1
	}

	level := func(secret models.Secret) (int, string) {
		if secret.AssetID != nil {
			// assetName has to exist in. this case
			return 0, *assetName
		}
		for i, project := range chain {
			if secret.ProjectID != nil && *secret.ProjectID == project.ID {
				return i + 1, project.Name
			}
		}
		// org name does always exist
		return len(chain) + 1, orgName
	}

	lowestLevel := map[string]int{}
	for _, secret := range secrets {
		l, _ := level(secret)
		if current, ok := lowestLevel[secret.Name]; !ok || l < current {
			lowestLevel[secret.Name] = l
		}
	}

	result := make([]dtos.SecretDTO, 0, len(secrets))
	for _, secret := range secrets {
		l, ownerName := level(secret)
		var inheritedFrom *string = nil
		if l != ownLevel {
			inheritedFrom = &ownerName
		}
		result = append(result, transformer.SecretToDTO(secret, inheritedFrom, l > lowestLevel[secret.Name]))
	}

	return result, nil
}

func (s *secretService) ReplaceSecretsInString(ctx context.Context, orgID uuid.UUID, projectID, assetID *uuid.UUID, orgName string, assetName *string, payload string) (string, error) {
	secrets, err := s.GetSecrets(ctx, orgID, projectID, assetID, orgName, assetName)

	if err != nil {
		return "", err
	}
	// build up the replacer based on the dtos
	replacer := make([]string, 0)
	// sort the secrets by name length to avoid replacing $TEST_2 and $TEST with <value of $TEST>_2
	slices.SortFunc(secrets, func(a, b dtos.SecretDTO) int {
		return len(b.Name) - len(a.Name)
	})

	for _, secret := range secrets {
		if !secret.Overridden {
			replacer = append(replacer, []string{"$" + secret.Name, secret.Value}...)
		}
	}

	return strings.NewReplacer(replacer...).Replace(payload), nil
}
