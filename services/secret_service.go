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
	"github.com/l3montree-dev/devguard/shared"
)

type secretService struct {
	secretRepository shared.SecretRepository
}

func NewSecretService(secretRepository shared.SecretRepository) *secretService {
	return &secretService{
		secretRepository: secretRepository,
	}
}

func (s *secretService) Resolve(ctx context.Context, orgID uuid.UUID, projectID, assetID *uuid.UUID, name string) (string, error) {
	var value string

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
			value = secret.Value
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
