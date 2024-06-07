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
	"log/slog"
	"net/url"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/database"
	"github.com/l3montree-dev/flawfix/internal/database/models"
	"github.com/l3montree-dev/flawfix/internal/utils"
)

type flawRepository interface {
	Transaction(txFunc func(core.DB) error) error
	ListByScanner(assetID uuid.UUID, scannerID string) ([]models.Flaw, error)
}

type componentRepository interface {
	SaveBatch(tx core.DB, components []models.Component) error
	UpdateSemverEnd(tx database.DB, assetID uuid.UUID, componentPurlOrCpes []string, version string) error
	CreateAssetComponents(tx database.DB, components []models.AssetComponent) error
	LoadAssetComponents(tx core.DB, asset models.Asset) ([]models.AssetComponent, error)
}

type assetRepository interface {
	Save(tx core.DB, asset *models.Asset) error
}

type flawService interface {
	UserFixedFlaws(tx core.DB, userID string, flaws []models.Flaw) error
	UserDetectedFlaws(tx core.DB, userID string, flaws []models.Flaw) error
}

type service struct {
	flawRepository      flawRepository
	componentRepository componentRepository
	flawService         flawService
	assetRepository     assetRepository
}

func NewService(assetRepository assetRepository, componentRepository componentRepository, flawRepository flawRepository, flawService flawService) *service {
	return &service{
		assetRepository:     assetRepository,
		componentRepository: componentRepository,
		flawRepository:      flawRepository,
		flawService:         flawService,
	}
}

func (s *service) HandleScanResult(userID string, scannerID string, asset models.Asset, flaws []models.Flaw) (int, int, error) {
	// get all existing flaws from the database - this is the old state
	existingFlaws, err := s.flawRepository.ListByScanner(asset.GetID(), scannerID)
	if err != nil {
		slog.Error("could not get existing flaws", "err", err)
		return 0, 0, err
	}

	comparison := utils.CompareSlices(existingFlaws, flaws, func(flaw models.Flaw) string {
		return flaw.CalculateHash()
	})

	fixedFlaws := comparison.OnlyInA
	newFlaws := comparison.OnlyInB

	// get a transaction
	if err := s.flawRepository.Transaction(func(tx core.DB) error {
		if err := s.flawService.UserDetectedFlaws(tx, userID, newFlaws); err != nil {
			// this will cancel the transaction
			return err
		}

		return s.flawService.UserFixedFlaws(tx, userID, fixedFlaws)
	}); err != nil {
		slog.Error("could not save flaws", "err", err)
		return 0, 0, err
	}
	return len(newFlaws), len(fixedFlaws), nil
}

// we have an asset, which already has some components defined.
// components will be the components, we have RIGHT NOW.
// they might be new or previously existing.
// this function will update the components of the asset.
//
// it might even happen, that we have a new release.
// if so, we need to fix the semverStart of the already existing asset components.
func (s *service) updateAssetComponents(asset models.Asset, components []models.AssetComponent, currentVersion string) error {
	// 1. Remove all "latest" components in the asset. The components parameter is the "current truth". It might happen,
	// that a user introduces a new component and removes it, before making the release
	// if this case happens, we just need to delete it again
	return s.flawRepository.Transaction(func(tx core.DB) error {
		comparison := utils.CompareSlices(asset.GetCurrentAssetComponents(), components, func(c models.AssetComponent) string {
			return c.ComponentPurlOrCpe
		})
		removedComponents := comparison.OnlyInA
		newComponents := comparison.OnlyInB

		if err := s.componentRepository.UpdateSemverEnd(tx, asset.GetID(), utils.Map(removedComponents, func(c models.AssetComponent) string {
			return c.ComponentPurlOrCpe
		}), currentVersion); err != nil {
			return err
		}

		// create the new components
		if err := s.componentRepository.CreateAssetComponents(tx, utils.Map(newComponents, func(a models.AssetComponent) models.AssetComponent {
			// make sure, that the semver start version is set correctly
			a.SemverStart = currentVersion
			a.SemverEnd = nil
			return a
		})); err != nil {
			return err
		}
		return nil
	})
}

func (s *service) UpdateSBOM(asset models.Asset, currentVersion string, sbom *cdx.BOM) {
	// load the asset components
	assetComponents, err := s.componentRepository.LoadAssetComponents(nil, asset)
	if err != nil {
		slog.Error("could not load asset components", "err", err)
		return
	}

	asset.Components = assetComponents

	// we need to check if the SBOM is new or if it already exists.
	// if it already exists, we need to update the existing SBOM
	// update the sbom for the asset in the database.
	components := make([]models.Component, 0)
	// create all components
	for _, component := range *sbom.Dependencies {
		// check if this is the asset itself.
		if component.Ref == sbom.Metadata.Component.BOMRef {
			continue
		}

		dependencies := make([]models.Component, 0)
		for _, dep := range *component.Dependencies {
			p, err := url.PathUnescape(dep)
			if err != nil {
				slog.Error("could not decode purl", "err", err)
				continue
			}
			dependencies = append(dependencies, models.Component{
				PurlOrCpe: p,
			})
		}
		// check if the component is already in the database
		// if not, create it
		// if it is, update it
		p, err := url.PathUnescape(component.Ref)
		if err != nil {
			slog.Error("could not decode purl", "err", err)
			continue
		}
		components = append(components, models.Component{
			PurlOrCpe: p,
			DependsOn: dependencies,
		})
	}
	// save all components in the database
	if err := s.componentRepository.SaveBatch(nil, components); err != nil {
		slog.Error("could not save components", "err", err)
	} else {
		slog.Info("saved components", "asset", asset.GetID().String(), "count", len(components))
	}

	// get the direct dependencies of the asset
	// ref: https://github.com/CycloneDX/cdxgen/issues/650
	directDependencies := make([]models.AssetComponent, 0)
	for _, component := range *sbom.Components {
		if component.Scope == cdx.ScopeRequired {
			p, err := url.PathUnescape(purlOrCpe(component))
			if err != nil {
				slog.Error("could not decode purl", "err", err)
				continue
			}
			directDependencies = append(directDependencies, models.AssetComponent{
				ComponentPurlOrCpe: p,
				AssetID:            asset.ID,
			})
		}
	}
	if err := s.updateAssetComponents(asset, directDependencies, currentVersion); err != nil {
		slog.Error("could not save direct dependencies", "err", err)
	} else {
		slog.Info("saved direct dependencies", "asset", asset.GetID().String(), "count", len(directDependencies))
	}
}
