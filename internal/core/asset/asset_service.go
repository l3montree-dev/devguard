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
	"net/http"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type assetRepository interface {
	Save(tx core.DB, asset *models.AssetNew) error
	Transaction(txFunc func(core.DB) error) error

	GetByAssetID(assetID uuid.UUID) (models.AssetNew, error)
}

type service struct {
	assetRepository assetRepository
	httpClient      *http.Client
}

func NewService(assetRepository assetRepository) *service {
	return &service{
		assetRepository: assetRepository,
		httpClient:      &http.Client{},
	}
}

func (s *service) GetByAssetID(assetID uuid.UUID) (models.AssetNew, error) {
	return s.assetRepository.GetByAssetID(assetID)
}
