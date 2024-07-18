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
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/pkg/errors"
)

type flawRepository interface {
	Transaction(txFunc func(core.DB) error) error
	ListByScanner(assetID uuid.UUID, scannerID string) ([]models.Flaw, error)

	GetAllFlawsByAssetID(tx core.DB, assetID uuid.UUID) ([]models.Flaw, error)
	SaveBatch(db core.DB, flaws []models.Flaw) error

	GetFlawsByPurlOrCpe(tx core.DB, purlOrCpe []string) ([]models.Flaw, error)
}

type componentRepository interface {
	SaveBatch(tx core.DB, components []models.Component) error
	LoadAssetComponents(tx core.DB, asset models.Asset, scanType, version string) ([]models.ComponentDependency, error)
	FindByPurl(tx core.DB, purl string) (models.Component, error)
	HandleStateDiff(tx database.DB, assetID uuid.UUID, version string, oldState []models.ComponentDependency, newState []models.ComponentDependency) error
}

type assetRepository interface {
	Save(tx core.DB, asset *models.Asset) error
}

type flawService interface {
	UserFixedFlaws(tx core.DB, userID string, flaws []models.Flaw) error
	UserDetectedFlaws(tx core.DB, userID string, flaws []models.Flaw, asset models.Asset) error
	UpdateFlawState(tx core.DB, userID string, flaw *models.Flaw, statusType string, justification *string) error

	RecalculateRawRiskAssessment(tx core.DB, userID string, flaws []models.Flaw, justification string, asset models.Asset) error
}

type service struct {
	flawRepository      flawRepository
	componentRepository componentRepository
	flawService         flawService
	assetRepository     assetRepository
	httpClient          *http.Client
}

func NewService(assetRepository assetRepository, componentRepository componentRepository, flawRepository flawRepository, flawService flawService) *service {
	return &service{
		assetRepository:     assetRepository,
		componentRepository: componentRepository,
		flawRepository:      flawRepository,
		flawService:         flawService,
		httpClient:          &http.Client{},
	}
}

func (s *service) HandleScanResult(userID string, scannerID string, asset models.Asset, flaws []models.Flaw) (int, int, []models.Flaw, error) {
	// get all existing flaws from the database - this is the old state
	existingFlaws, err := s.flawRepository.ListByScanner(asset.GetID(), scannerID)
	if err != nil {
		slog.Error("could not get existing flaws", "err", err)
		return 0, 0, []models.Flaw{}, err
	}
	// remove all fixed flaws from the existing flaws
	existingFlaws = utils.Filter(existingFlaws, func(flaw models.Flaw) bool {
		return flaw.State != models.FlawStateFixed
	})

	comparison := utils.CompareSlices(existingFlaws, flaws, func(flaw models.Flaw) string {
		return flaw.CalculateHash()
	})

	fixedFlaws := comparison.OnlyInA
	newFlaws := comparison.OnlyInB

	// get a transaction
	if err := s.flawRepository.Transaction(func(tx core.DB) error {
		if err := s.flawService.UserDetectedFlaws(tx, userID, newFlaws, asset); err != nil {
			// this will cancel the transaction
			return err
		}
		return s.flawService.UserFixedFlaws(tx, userID, utils.Filter(
			fixedFlaws,
			func(flaw models.Flaw) bool {
				return flaw.State == models.FlawStateOpen
			},
		))
	}); err != nil {
		slog.Error("could not save flaws", "err", err)
		return 0, 0, []models.Flaw{}, err
	}
	// the amount we actually fixed, is the amount that was open before
	fixedFlaws = utils.Filter(fixedFlaws, func(flaw models.Flaw) bool {
		return flaw.State == models.FlawStateOpen
	})
	return len(newFlaws), len(fixedFlaws), append(newFlaws, comparison.InBoth...), nil
}

type DepsDevResponse struct {
	Nodes []struct {
		VersionKey struct {
			System  string `json:"system"`
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"versionKey"`
		Bundled  bool          `json:"bundled"`
		Relation string        `json:"relation"`
		Errors   []interface{} `json:"errors"`
	} `json:"nodes"`
	Edges []struct {
		FromNode    int    `json:"fromNode"`
		ToNode      int    `json:"toNode"`
		Requirement string `json:"requirement"`
	} `json:"edges"`
	Error string `json:"error"`
}

func (s *service) UpdateSBOM(asset models.Asset, scanType string, currentVersion string, sbom *cdx.BOM) error {
	// load the asset components
	assetComponents, err := s.componentRepository.LoadAssetComponents(nil, asset, scanType, currentVersion)
	if err != nil {
		return errors.Wrap(err, "could not load asset components")
	}

	// we need to check if the SBOM is new or if it already exists.
	// if it already exists, we need to update the existing SBOM
	// update the sbom for the asset in the database.
	components := make([]models.Component, 0)
	dependencies := make([]models.ComponentDependency, 0)
	// create all components
	for _, component := range *sbom.Components {
		// check if this is the asset itself.
		if component.BOMRef == sbom.Metadata.Component.BOMRef {
			continue
		}

		// the sbom of a container image does not contain the scope. In a container image, we do not have
		// anything like a deep nested dependency tree. Everything is a direct dependency.
		if component.Scope == cdx.ScopeRequired || component.Scope == "" {
			// create the direct dependency edge.
			dependencies = append(dependencies,
				models.ComponentDependency{
					ComponentPurlOrCpe: nil, // direct dependency - therefore set it to nil
					Dependency: models.Component{
						PurlOrCpe: component.BOMRef,
					},
					ScanType:            scanType,
					DependencyPurlOrCpe: component.BOMRef,
					AssetSemverStart:    currentVersion,
				},
			)
		}

		// find all dependencies from this component

		for _, c := range *sbom.Dependencies {
			if c.Ref != component.BOMRef {
				continue
			}

			for _, dep := range *c.Dependencies {
				p, err := url.PathUnescape(dep)

				if err != nil {
					slog.Error("could not decode purl", "err", err)
					continue
				}
				dependencies = append(dependencies,
					models.ComponentDependency{
						Component: models.Component{
							PurlOrCpe: component.BOMRef,
						},
						ComponentPurlOrCpe: utils.Ptr(component.BOMRef),
						Dependency: models.Component{
							PurlOrCpe: p,
						},
						ScanType:            scanType,
						DependencyPurlOrCpe: p,
						AssetSemverStart:    currentVersion,
					},
				)
			}
		}

		p, err := url.PathUnescape(component.BOMRef)
		if err != nil {
			slog.Error("could not decode purl", "err", err)
			continue
		}

		components = append(components,
			models.Component{
				PurlOrCpe: p,
			},
		)
	}

	// make sure, that the components exist
	if err := s.componentRepository.SaveBatch(nil, components); err != nil {
		return err
	}

	return s.componentRepository.HandleStateDiff(nil, asset.ID, currentVersion, assetComponents, dependencies)
}

func (s *service) UpdateAssetRequirements(asset models.Asset, responsible string, justification string) error {
	err := s.flawRepository.Transaction(func(tx core.DB) error {

		err := s.assetRepository.Save(tx, &asset)
		if err != nil {
			slog.Info("Error saving asset: %v", err)
			return fmt.Errorf("could not save asset: %v", err)
		}
		// get the flaws
		flaws, err := s.flawRepository.GetAllFlawsByAssetID(tx, asset.GetID())
		if err != nil {
			slog.Info("error getting flaws", "err", err)
			return fmt.Errorf("could not get flaws: %v", err)
		}

		err = s.flawService.RecalculateRawRiskAssessment(tx, responsible, flaws, justification, asset)
		if err != nil {
			slog.Info("error updating raw risk assessment", "err", err)
			return fmt.Errorf("could not update raw risk assessment: %v", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("could not update asset: %v", err)
	}

	return nil
}
