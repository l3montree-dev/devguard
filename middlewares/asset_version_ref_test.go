// Copyright (C) 2025 l3montree GmbH
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

package middlewares

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"gorm.io/gorm"
)

func TestReadAssetVersionBySlugOrName(t *testing.T) {
	assetID := uuid.New()

	t.Run("resolves a slug", func(t *testing.T) {
		repository := mocks.NewAssetVersionRepository(t)
		repository.On("ReadBySlug", mock.Anything, mock.Anything, assetID, "v1-2-3").Return(models.AssetVersion{Name: "v1.2.3"}, nil)

		assetVersion, err := readAssetVersionBySlugOrName(context.Background(), repository, assetID, "v1-2-3")
		assert.NoError(t, err)
		assert.Equal(t, "v1.2.3", assetVersion.Name)
	})

	t.Run("falls back to the name", func(t *testing.T) {
		repository := mocks.NewAssetVersionRepository(t)
		repository.On("ReadBySlug", mock.Anything, mock.Anything, assetID, "v1.2.3").Return(models.AssetVersion{}, gorm.ErrRecordNotFound)
		repository.On("ReadByName", mock.Anything, mock.Anything, "v1.2.3", assetID).Return(models.AssetVersion{Name: "v1.2.3"}, nil)

		assetVersion, err := readAssetVersionBySlugOrName(context.Background(), repository, assetID, "v1.2.3")
		assert.NoError(t, err)
		assert.Equal(t, "v1.2.3", assetVersion.Name)
	})

	t.Run("decodes the name like a path segment", func(t *testing.T) {
		repository := mocks.NewAssetVersionRepository(t)
		repository.On("ReadBySlug", mock.Anything, mock.Anything, assetID, mock.Anything).Return(models.AssetVersion{}, gorm.ErrRecordNotFound)
		repository.On("ReadByName", mock.Anything, mock.Anything, "feature/foo", assetID).Return(models.AssetVersion{Name: "feature/foo"}, nil)
		repository.On("ReadByName", mock.Anything, mock.Anything, "1.0.0+build", assetID).Return(models.AssetVersion{Name: "1.0.0+build"}, nil)

		assetVersion, err := readAssetVersionBySlugOrName(context.Background(), repository, assetID, "feature%2Ffoo")
		assert.NoError(t, err)
		assert.Equal(t, "feature/foo", assetVersion.Name)

		assetVersion, err = readAssetVersionBySlugOrName(context.Background(), repository, assetID, "1.0.0+build")
		assert.NoError(t, err)
		assert.Equal(t, "1.0.0+build", assetVersion.Name)
	})

	t.Run("not found by slug or name", func(t *testing.T) {
		repository := mocks.NewAssetVersionRepository(t)
		repository.On("ReadBySlug", mock.Anything, mock.Anything, assetID, "v9.9.9").Return(models.AssetVersion{}, gorm.ErrRecordNotFound)
		repository.On("ReadByName", mock.Anything, mock.Anything, "v9.9.9", assetID).Return(models.AssetVersion{}, gorm.ErrRecordNotFound)

		_, err := readAssetVersionBySlugOrName(context.Background(), repository, assetID, "v9.9.9")
		assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
	})
}
