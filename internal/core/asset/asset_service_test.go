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
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/stretchr/testify/mock"
	"gorm.io/gorm"
)

func TestUpdateSBOM(t *testing.T) {
	asset := models.Asset{
		Model: models.Model{
			ID: uuid.New(),
		},
	}

	// expect those components to get created
	components := []models.Component{
		{
			PurlOrCpe: asset.ID.String() + "/package-lock.json",
		},
		{
			PurlOrCpe: "a@1.0.0",
		},
		{
			PurlOrCpe: "b@1.0.1",
		},
	}
	expectedNewState := []models.ComponentDependency{
		{
			ComponentPurlOrCpe:  nil,
			DependencyPurlOrCpe: asset.ID.String() + "/package-lock.json",
			AssetSemverStart:    "1.0.0",
			AssetSemverEnd:      nil,
			ScanType:            "sca",
		},
		{
			ComponentPurlOrCpe:  utils.Ptr(asset.ID.String() + "/package-lock.json"),
			DependencyPurlOrCpe: "a@1.0.0",
			AssetSemverStart:    "1.0.0",
			AssetSemverEnd:      nil,
			ScanType:            "sca",
		},
		{
			ComponentPurlOrCpe:  utils.Ptr("a@1.0.0"),
			DependencyPurlOrCpe: "b@1.0.1",
			AssetSemverStart:    "1.0.0",
			AssetSemverEnd:      nil,
			ScanType:            "sca",
		},
	}

	bom := cdx.BOM{
		Components: &[]cdx.Component{
			{
				BOMRef:  "package-lock.json",
				Type:    "application",
				Name:    "package-lock.json",
				Version: "1.0.0",
			},
			{
				BOMRef:     "a@1.0.0",
				Type:       "library",
				Name:       "a",
				Version:    "1.0.0",
				PackageURL: "a@1.0.0",
				Scope:      cdx.ScopeRequired,
			},
			{
				BOMRef:     "b@1.0.1",
				Type:       "library",
				Name:       "b",
				Version:    "1.0.1",
				PackageURL: "b@1.0.1",
				Scope:      cdx.ScopeOptional,
			},
		},
		Dependencies: &[]cdx.Dependency{
			{
				Ref: "package-lock.json",
				Dependencies: &[]string{
					"a@1.0.0",
				},
			},
			{
				Ref: "a@1.0.0",
				Dependencies: &[]string{
					"b@1.0.1",
				},
			},
		},
	}

	t.Run("update sbom with empty old state", func(t *testing.T) {
		componentRepository := &mocks.AssetComponentRepository{}
		componentRepository.
			On("LoadAssetComponents", mock.Anything, asset, "sca", "1.0.0").Return([]models.ComponentDependency{}, nil)

		componentRepository.On("SaveBatch", (*gorm.DB)(nil), components).Return(nil)

		componentRepository.On("HandleStateDiff", (*gorm.DB)(nil), asset.GetID(), "1.0.0", []models.ComponentDependency{}, expectedNewState).Return(nil)

		assetService := service{
			componentRepository: componentRepository,
		}

		if err := assetService.UpdateSBOM(asset, "sca", "1.0.0", &bom); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("update sbom with existing old state", func(t *testing.T) {
		oldState := []models.ComponentDependency{
			{
				ComponentPurlOrCpe:  nil,
				DependencyPurlOrCpe: "a@1.0.0",
				AssetSemverStart:    "1.0.0",
				AssetSemverEnd:      nil,
				Dependency:          components[0],
			},
		}

		componentRepository := &mocks.AssetComponentRepository{}
		componentRepository.
			On("LoadAssetComponents", mock.Anything, asset, "sca", "1.0.0").Return(oldState, nil)

		componentRepository.On("SaveBatch", (*gorm.DB)(nil), components).Return(nil)

		componentRepository.On("HandleStateDiff", (*gorm.DB)(nil), asset.GetID(), "1.0.0", oldState, expectedNewState).Return(nil)

		assetService := service{
			componentRepository: componentRepository,
		}

		if err := assetService.UpdateSBOM(asset, "sca", "1.0.0", &bom); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

}
