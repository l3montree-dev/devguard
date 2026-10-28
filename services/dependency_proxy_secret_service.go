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

	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
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

	var modelID uuid.UUID
	var scope string
	if proxy.AssetID != nil {
		scope = "asset"
		modelID = *proxy.AssetID
	} else if proxy.ProjectID != nil {
		scope = "project"
		modelID = *proxy.ProjectID

	} else if proxy.OrgID != nil {
		scope = "organization"
		modelID = *proxy.OrgID
	}

	if modelID == uuid.Nil {
		return "", uuid.Nil, fmt.Errorf("no model found for secret: %s", secret)
	}

	return scope, modelID, nil
}

func generateDebSigningKey() (privateKey, publicKey string, err error) {
	key, err := crypto.PGPWithProfile(profile.RFC4880()).KeyGeneration().AddUserId("DevGuard Dependency Proxy", "noreply@devguard.org").New().GenerateKey()
	if err != nil {
		return "", "", err
	}

	privKey, err := key.Armor()
	if err != nil {
		return "", "", err
	}

	pubKey, err := key.GetArmoredPublicKey()
	if err != nil {
		return "", "", err
	}

	return privKey, pubKey, nil
}

func (s *dependencyProxySecretService) GetOrCreateDebSigningKey(ctx context.Context, secret uuid.UUID) (privateKey, publicKey string, err error) {
	privKey, pubKey, found, err := s.dependencyProxySecretRepository.GetDebSigningKey(ctx, nil, secret)
	if err != nil {
		return "", "", err
	}
	if found {
		return privKey, pubKey, nil
	}

	privKey, pubKey, err = generateDebSigningKey()
	if err != nil {
		return "", "", err
	}

	if err = s.dependencyProxySecretRepository.SetDebSigningKeyIfMissing(ctx, nil, secret, privKey, pubKey); err != nil {
		return "", "", err
	}

	privKey, pubKey, found, err = s.dependencyProxySecretRepository.GetDebSigningKey(ctx, nil, secret)
	if err != nil {
		return "", "", err
	}
	if found {
		return privKey, pubKey, nil
	}
	return "", "", fmt.Errorf("signing key missing after creation")
}
