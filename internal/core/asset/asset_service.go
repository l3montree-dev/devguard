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

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/database/models"
	"github.com/l3montree-dev/flawfix/internal/utils"
)

type flawRepository interface {
	Transaction(txFunc func(core.DB) error) error
	ListByScanner(assetID uuid.UUID, scannerID string) ([]models.Flaw, error)
}

type componentRepository interface {
	SaveBatch(tx core.DB, components []models.Component) error
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

func (s *service) HandleScanResult(userID string, scannerID string, asset models.Asset, flaws []models.Flaw) {
	// get all existing flaws from the database - this is the old state
	existingFlaws, err := s.flawRepository.ListByScanner(asset.GetID(), scannerID)
	if err != nil {
		slog.Error("could not get existing flaws", "err", err)
		return
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
	}
}

func (s *service) UpdateSBOM(asset models.Asset, sbom *cdx.BOM) {
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
			p, err := urlDecode(dep)
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
		p, err := urlDecode(component.Ref)
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
	directDependencies := make([]models.Component, 0)
	for _, component := range *sbom.Components {
		if component.Scope == cdx.ScopeRequired {
			p, err := urlDecode(purlOrCpe(component))
			if err != nil {
				slog.Error("could not decode purl", "err", err)
				continue
			}
			directDependencies = append(directDependencies, models.Component{
				PurlOrCpe: p,
			})
		}
	}
	asset.Components = directDependencies
	// save the direct dependencies of the asset
	if err := s.assetRepository.Save(nil, &asset); err != nil {
		slog.Error("could not save direct dependencies", "err", err)
	} else {
		slog.Info("saved direct dependencies", "asset", asset.GetID().String(), "count", len(directDependencies))
	}
}
