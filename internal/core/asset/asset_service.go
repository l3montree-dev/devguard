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
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

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

	GetRecentFlawsForAsset(assetID uuid.UUID, time time.Time) ([]models.FlawRisk, error)
	GetAssetFlawsStatistics(asset_ID string) ([]models.AssetRiskSummary, error)
	GetAssetRisksDistribution(asset_ID string) ([]models.AssetRiskDistribution, error)
	GetAssetCriticalDependenciesGroupedByScanType(asset_ID string) ([]models.AssetCriticalDependencies, error)
}

type componentRepository interface {
	SaveBatch(tx core.DB, components []models.Component) error
	LoadAssetComponents(tx core.DB, asset models.Asset, scanType, version string) ([]models.ComponentDependency, error)
	FindByPurl(tx core.DB, purl string) (models.Component, error)
	HandleStateDiff(tx database.DB, assetID uuid.UUID, version string, oldState []models.ComponentDependency, newState []models.ComponentDependency) error
	GetAssetDependenciesGroupedByScanType(asset_ID string) ([]models.AssetAllDependencies, error)
}

type assetRepository interface {
	Save(tx core.DB, asset *models.Asset) error
	Transaction(txFunc func(core.DB) error) error
}

type flawService interface {
	UserFixedFlaws(tx core.DB, userID string, flaws []models.Flaw) error
	UserDetectedFlaws(tx core.DB, userID string, flaws []models.Flaw, asset models.Asset) error
	UpdateFlawState(tx core.DB, userID string, flaw *models.Flaw, statusType string, justification *string) error

	RecalculateRawRiskAssessment(tx core.DB, userID string, flaws []models.Flaw, justification string, asset models.Asset) error
}
type service struct {
	flawRepository            flawRepository
	componentRepository       componentRepository
	flawService               flawService
	assetRepository           assetRepository
	httpClient                *http.Client
	assetRecentRiskRepository assetRecentRiskRepository
}

type assetRecentRiskRepository interface {
	GetAssetRecentRisksByAssetId(assetId uuid.UUID) ([]models.AssetRecentRisks, error)
	UpdateAssetRecentRisks(assetRisks *models.AssetRecentRisks) error
}

func NewService(assetRepository assetRepository, assetRecentRiskRepository assetRecentRiskRepository, componentRepository componentRepository, flawRepository flawRepository, flawService flawService) *service {
	return &service{
		assetRepository:           assetRepository,
		assetRecentRiskRepository: assetRecentRiskRepository,
		componentRepository:       componentRepository,
		flawRepository:            flawRepository,
		flawService:               flawService,
		httpClient:                &http.Client{},
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

func recursiveBuildBomRefMap(component cdx.Component) map[string]cdx.Component {
	res := make(map[string]cdx.Component)
	if component.Components == nil {
		return res
	}

	for _, c := range *component.Components {
		res[c.BOMRef] = c
		for k, v := range recursiveBuildBomRefMap(c) {
			res[k] = v
		}
	}
	return res
}

func buildBomRefMap(bom *cdx.BOM) map[string]cdx.Component {
	res := make(map[string]cdx.Component)
	if bom.Components == nil {
		return res
	}

	for _, c := range *bom.Components {
		res[c.BOMRef] = c
		for k, v := range recursiveBuildBomRefMap(c) {
			res[k] = v
		}
	}
	return res
}

func purlOrCpe(component cdx.Component) (string, error) {
	if component.PackageURL != "" {
		return url.PathUnescape(component.PackageURL)
	}
	if component.CPE != "" {
		return component.CPE, nil
	}
	return component.Name, nil
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
	components := make(map[string]models.Component)
	dependencies := make([]models.ComponentDependency, 0)

	// build a map of all components
	bomRefMap := buildBomRefMap(sbom)

	// create all direct dependencies
	root := sbom.Metadata.Component.BOMRef
	for _, c := range *sbom.Dependencies {
		if c.Ref != root {
			continue // no direct dependency
		}
		// we found it.
		for _, directDependency := range *c.Dependencies {
			component := bomRefMap[directDependency]
			// the sbom of a container image does not contain the scope. In a container image, we do not have
			// anything like a deep nested dependency tree. Everything is a direct dependency.
			componentPackageUrl, err := purlOrCpe(component)
			if err != nil {
				slog.Error("could not decode purl", "err", err)
				continue
			}

			// create the direct dependency edge.
			dependencies = append(dependencies,
				models.ComponentDependency{
					ComponentPurlOrCpe:  nil, // direct dependency - therefore set it to nil
					ScanType:            scanType,
					DependencyPurlOrCpe: componentPackageUrl,
					AssetSemverStart:    currentVersion,
				},
			)
			components[componentPackageUrl] = models.Component{
				PurlOrCpe: componentPackageUrl,
				AssetID:   asset.GetID(),
				ScanType:  scanType,
			}
		}
	}

	// find all dependencies from this component

	for _, c := range *sbom.Dependencies {
		comp := bomRefMap[c.Ref]
		compPackageUrl, err := purlOrCpe(comp)
		if err != nil {
			slog.Warn("could not decode purl", "err", err)
			continue
		}

		for _, d := range *c.Dependencies {
			dep := bomRefMap[d]
			depPurlOrName, err := purlOrCpe(dep)
			if err != nil {
				slog.Error("could not decode purl", "err", err)
				continue
			}
			dependencies = append(dependencies,
				models.ComponentDependency{
					ComponentPurlOrCpe:  utils.Ptr(compPackageUrl),
					ScanType:            scanType,
					DependencyPurlOrCpe: depPurlOrName,
					AssetSemverStart:    currentVersion,
				},
			)
			components[depPurlOrName] = models.Component{
				PurlOrCpe: depPurlOrName,
				AssetID:   asset.GetID(),
				ScanType:  scanType,
			}
			components[compPackageUrl] = models.Component{
				PurlOrCpe: compPackageUrl,
				AssetID:   asset.GetID(),
				ScanType:  scanType,
			}
		}
	}

	componentsSlice := make([]models.Component, 0, len(components))
	for _, c := range components {
		componentsSlice = append(componentsSlice, c)
	}

	// make sure, that the components exist
	if err := s.componentRepository.SaveBatch(nil, componentsSlice); err != nil {
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

func (s *service) GetAssetCombinedDependencies(asset_ID string) ([]models.AssetCombinedDependencies, error) {

	allDependencies, err := s.getAssetDependenciesGroupedByScanType(asset_ID)
	if err != nil {
		return nil, err
	}

	criticalDependencies, err := s.getAssetCriticalDependenciesGroupedByScanType(asset_ID)
	if err != nil {
		return nil, err
	}

	criticalCountMap := make(map[string]int64)
	for _, criticalDep := range criticalDependencies {
		criticalCountMap[criticalDep.ScannerID] = criticalDep.Count
	}

	combinedDependencies := make([]models.AssetCombinedDependencies, len(allDependencies))
	for i, allDep := range allDependencies {
		combinedDependencies[i] = models.AssetCombinedDependencies{
			ScanType:          allDep.ScanType,
			CountDependencies: allDep.Count,
			CountCritical:     criticalCountMap[allDep.ScanType],
		}
	}

	return combinedDependencies, nil
}

func (s *service) getAssetCriticalDependenciesGroupedByScanType(asset_ID string) ([]models.AssetCriticalDependencies, error) {
	assets, err := s.flawRepository.GetAssetCriticalDependenciesGroupedByScanType(asset_ID)
	if err != nil {
		return nil, err
	}

	for i := range assets {
		assets[i].ScannerID = scanTypeFromScannerID(assets[i].ScannerID)
	}
	return assets, nil

}

func (s *service) getAssetDependenciesGroupedByScanType(asset_ID string) ([]models.AssetAllDependencies, error) {
	return s.componentRepository.GetAssetDependenciesGroupedByScanType(asset_ID)
}

func (s *service) GetAssetFlawsStatistics(asset_ID string) ([]models.AssetRiskSummary, error) {

	risks, err := s.flawRepository.GetAssetFlawsStatistics(asset_ID)
	if err != nil {
		return nil, err
	}
	for i := range risks {
		risks[i].ScannerID = scanTypeFromScannerID(risks[i].ScannerID)

	}
	return risks, nil
}

func scanTypeFromScannerID(scannerID string) string {
	parts := strings.Split(scannerID, "/")
	return parts[len(parts)-1]
}

func (s *service) UpdateAssetRecentRisks(assetID uuid.UUID, begin time.Time, end time.Time) error {
	tmpID := 1

	for time := begin; time.Before(end); time = time.AddDate(0, 0, 1) {
		assetRisk, err := s.flawRepository.GetRecentFlawsForAsset(assetID, time)
		if err != nil {
			return err
		}

		riskSum := 0.0
		riskAvg := 0.0
		riskMax := 0.0
		riskMin := 99.0
		dayOfRisk := "9999-99-99 00:00:00.000000 +0200 CEST"

		for i := range assetRisk {
			arbitraryJsonData := make(map[string]interface{})
			err := json.Unmarshal([]byte(assetRisk[i].ArbitraryJsonData), &arbitraryJsonData)
			if err != nil {
				slog.Error("could not parse additional data", "err", err, "flawId", assetRisk[i].FlawID)
			}
			risk := arbitraryJsonData["risk"].(float64)
			riskSum += risk
			if risk > riskMax {
				riskMax = risk
			}
			if risk <= riskMin {
				riskMin = risk
			}

		}

		if riskMin == 99.0 {
			riskMin = 0.0
		}
		if len(assetRisk) != 0 {
			riskAvg = riskSum / float64(len(assetRisk))
			dayOfRisk = assetRisk[0].CreatedAt.String()

		}

		result := models.AssetRecentRisks{
			AssetID:      assetID,
			ID:           tmpID,
			DayOfRisk:    dayOfRisk,
			DayOfScan:    time.Format("2006-01-02"),
			AssetSumRisk: riskSum,
			AssetAvgRisk: riskAvg,
			AssetMaxRisk: riskMax,
			AssetMinRisk: riskMin,
		}

		tmpID++

		err = s.assetRecentRiskRepository.UpdateAssetRecentRisks(&result)
		if err != nil {
			return err
		}

	}
	return nil

}

func (s *service) GetAssetRecentRisksByAssetId(assetID uuid.UUID) ([]models.AssetRecentRisks, error) {
	return s.assetRecentRiskRepository.GetAssetRecentRisksByAssetId(assetID)
}

func (s *service) GetAssetFlawsDistribution(asset_ID string) ([]models.AssetRiskDistribution, error) {
	assets, err := s.flawRepository.GetAssetRisksDistribution(asset_ID)
	if err != nil {
		return nil, err
	}

	for i := range assets {
		assets[i].ScannerID = scanTypeFromScannerID(assets[i].ScannerID)
	}

	return assets, nil

}

func (s *service) GetAssetFlaws(assetID uuid.UUID) ([]models.AssetFlaws, error) {
	assetFlaws := make([]models.AssetFlaws, 0)

	flaws, err := s.flawRepository.GetAllFlawsByAssetID(nil, assetID)
	if err != nil {
		return nil, err
	}
	for _, flaw := range flaws {
		assetFlaws = append(assetFlaws, models.AssetFlaws{
			FlawID:            flaw.ID,
			RawRiskAssessment: flaw.RawRiskAssessment,
		})
	}
	return assetFlaws, nil
}
