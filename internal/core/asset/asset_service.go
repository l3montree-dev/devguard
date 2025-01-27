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
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/normalize"
	"github.com/l3montree-dev/devguard/internal/core/risk"
	"github.com/l3montree-dev/devguard/internal/database"
	"github.com/l3montree-dev/devguard/internal/database/models"

	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/package-url/packageurl-go"
	"github.com/pkg/errors"
)

type flawRepository interface {
	Transaction(txFunc func(core.DB) error) error
	ListByScanner(assetID uuid.UUID, scannerID string) ([]models.Flaw, error)

	GetAllFlawsByAssetID(tx core.DB, assetID uuid.UUID) ([]models.Flaw, error)
	SaveBatch(db core.DB, flaws []models.Flaw) error

	GetFlawsByPurl(tx core.DB, purl []string) ([]models.Flaw, error)
}

type componentRepository interface {
	SaveBatch(tx core.DB, components []models.Component) error
	LoadComponents(tx core.DB, asset models.Asset, scanner, version string) ([]models.ComponentDependency, error)
	FindByPurl(tx core.DB, purl string) (models.Component, error)
	HandleStateDiff(tx database.DB, assetID uuid.UUID, version string, oldState []models.ComponentDependency, newState []models.ComponentDependency) error
}

type assetRepository interface {
	Save(tx core.DB, asset *models.Asset) error
	Transaction(txFunc func(core.DB) error) error
}

type flawService interface {
	UserFixedFlaws(tx core.DB, userID string, flaws []models.Flaw, doRiskManagement bool) error
	UserDetectedFlaws(tx core.DB, userID string, flaws []models.Flaw, asset models.Asset, doRiskManagement bool) error
	UpdateFlawState(tx core.DB, userID string, flaw *models.Flaw, statusType string, justification string) (models.FlawEvent, error)

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

func (s *service) HandleScanResult(asset models.Asset, vulns []models.VulnInPackage, scanner string, version string, scannerID string, userID string, doRiskManagement bool) (amountOpened int, amountClose int, newState []models.Flaw, err error) {

	// create flaws out of those vulnerabilities
	flaws := []models.Flaw{}

	// load all asset components again and build a dependency tree
	assetComponents, err := s.componentRepository.LoadComponents(nil, asset, scanner, version)
	if err != nil {
		return 0, 0, []models.Flaw{}, errors.Wrap(err, "could not load asset components")
	}
	// build a dependency tree
	tree := BuildDependencyTree(assetComponents)
	// calculate the depth of each component
	depthMap := make(map[string]int)

	// our dependency tree has a "fake" root node.
	//  the first - 0 - element is just the name of the application
	// therefore we start at -1 to get the correct depth. The fake node will be 0, the first real node will be 1
	CalculateDepth(tree.Root, -1, depthMap)

	// now we have the depth.
	for _, vuln := range vulns {
		v := vuln

		flaw := models.Flaw{
			AssetID:               asset.ID,
			CVEID:                 utils.Ptr(v.CVEID),
			ScannerID:             scannerID,
			ComponentPurl:         utils.Ptr(v.Purl),
			ComponentFixedVersion: v.FixedVersion,
			ComponentDepth:        utils.Ptr(depthMap[v.Purl]),
			CVE:                   &v.CVE,
		}

		flaws = append(flaws, flaw)
	}

	flaws = utils.UniqBy(flaws, func(f models.Flaw) string {
		return f.CalculateHash()
	})

	// let the asset service handle the new scan result - we do not need
	// any return value from that process - even if it fails, we should return the current flaws
	amountOpened, amountClosed, amountExisting, err := s.handleScanResult(userID, scannerID, asset, flaws, doRiskManagement)
	if err != nil {
		return 0, 0, []models.Flaw{}, err
	}

	switch scanner {
	case "sast":
		asset.LastSastScan = utils.Ptr(time.Now())
	case "dast":
		asset.LastDastScan = utils.Ptr(time.Now())
	case "sca":
		asset.LastScaScan = utils.Ptr(time.Now())
	case "container-scanning":
		asset.LastContainerScan = utils.Ptr(time.Now())
	case "secret-scanning":
		asset.LastSecretScan = utils.Ptr(time.Now())
	case "iac":
		asset.LastIacScan = utils.Ptr(time.Now())
	}

	if doRiskManagement {
		err = s.assetRepository.Save(nil, &asset)
		if err != nil {
			// swallow but log
			slog.Error("could not save asset", "err", err)
		}
	}
	return amountOpened, amountClosed, amountExisting, nil
}

func (s *service) handleScanResult(userID string, scannerID string, asset models.Asset, flaws []models.Flaw, doRiskManagement bool) (int, int, []models.Flaw, error) {
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

	if doRiskManagement {
		// get a transaction
		if err := s.flawRepository.Transaction(func(tx core.DB) error {
			if err := s.flawService.UserDetectedFlaws(tx, userID, newFlaws, asset, true); err != nil {
				// this will cancel the transaction
				return err
			}
			return s.flawService.UserFixedFlaws(tx, userID, utils.Filter(
				fixedFlaws,
				func(flaw models.Flaw) bool {
					return flaw.State == models.FlawStateOpen
				},
			), true)
		}); err != nil {
			slog.Error("could not save flaws", "err", err)
			return 0, 0, []models.Flaw{}, err
		}
	} else {
		if err := s.flawService.UserDetectedFlaws(nil, userID, newFlaws, asset, false); err != nil {
			slog.Error("could not save flaws", "err", err)
			return 0, 0, []models.Flaw{}, err
		}

		if err := s.flawService.UserFixedFlaws(nil, userID, utils.Filter(
			fixedFlaws,
			func(flaw models.Flaw) bool {
				return flaw.State == models.FlawStateOpen
			},
		), false); err != nil {
			slog.Error("could not save flaws", "err", err)
			return 0, 0, []models.Flaw{}, err
		}
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

func buildBomRefMap(bom normalize.SBOM) map[string]cdx.Component {
	res := make(map[string]cdx.Component)
	if bom.GetComponents() == nil {
		return res
	}

	for _, c := range *bom.GetComponents() {
		res[c.BOMRef] = c
		for k, v := range recursiveBuildBomRefMap(c) {
			res[k] = v
		}
	}
	return res
}

func (s *service) UpdateSBOM(asset models.Asset, scannerID string, currentVersion string, sbom normalize.SBOM) error {
	// load the asset components
	assetComponents, err := s.componentRepository.LoadComponents(nil, asset, scannerID, currentVersion)
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
	root := sbom.GetMetadata().Component.BOMRef
	for _, c := range *sbom.GetDependencies() {
		if c.Ref != root {
			continue // no direct dependency
		}
		// we found it.
		for _, directDependency := range *c.Dependencies {
			component := bomRefMap[directDependency]
			// the sbom of a container image does not contain the scope. In a container image, we do not have
			// anything like a deep nested dependency tree. Everything is a direct dependency.
			componentPackageUrl := normalize.Purl(component)

			// create the direct dependency edge.
			dependencies = append(dependencies,
				models.ComponentDependency{
					ComponentPurl:    nil, // direct dependency - therefore set it to nil
					ScannerID:        scannerID,
					DependencyPurl:   componentPackageUrl,
					AssetSemverStart: currentVersion,
				},
			)
			components[componentPackageUrl] = models.Component{
				Purl:          componentPackageUrl,
				ComponentType: models.ComponentType(component.Type),
				Version:       component.Version,
			}
		}
	}

	// find all dependencies from this component
	for _, c := range *sbom.GetDependencies() {
		comp := bomRefMap[c.Ref]
		compPackageUrl := normalize.Purl(comp)

		for _, d := range *c.Dependencies {
			dep := bomRefMap[d]
			depPurlOrName := normalize.Purl(dep)

			dependencies = append(dependencies,
				models.ComponentDependency{
					ComponentPurl:    utils.EmptyThenNil(compPackageUrl),
					ScannerID:        scannerID,
					DependencyPurl:   depPurlOrName,
					AssetSemverStart: currentVersion,
				},
			)
			components[depPurlOrName] = models.Component{
				Purl:          depPurlOrName,
				ComponentType: models.ComponentType(dep.Type),
				Version:       dep.Version,
			}
			components[compPackageUrl] = models.Component{
				Purl:          compPackageUrl,
				ComponentType: models.ComponentType(comp.Type),
				Version:       comp.Version,
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
			slog.Info("error saving asset", "err", err)
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

func (s *service) BuildSBOM(asset models.Asset, version string, organizationName string, components []models.ComponentDependency) *cdx.BOM {
	if version == models.NoVersion {
		version = "latest"
	}

	bom := cdx.BOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: cyclonedx.SpecVersion1_5,
		Version:     1,
		Metadata: &cdx.Metadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Component: &cdx.Component{
				BOMRef:    asset.Slug,
				Type:      cdx.ComponentTypeApplication,
				Name:      asset.Name,
				Version:   version,
				Author:    organizationName,
				Publisher: "github.com/l3montree-dev/devguard",
			},
		},
	}

	bomComponents := make([]cdx.Component, 0)
	alreadyIncluded := make(map[string]bool)
	for _, cLoop := range components {
		c := cLoop

		var p packageurl.PackageURL
		var err error
		if c.ComponentPurl != nil {
			p, err = packageurl.FromString(*c.ComponentPurl)
			if err == nil {
				if _, ok := alreadyIncluded[*c.ComponentPurl]; !ok {
					alreadyIncluded[*c.ComponentPurl] = true
					bomComponents = append(bomComponents, cdx.Component{
						BOMRef:     *c.ComponentPurl,
						Type:       cdx.ComponentType(c.Component.ComponentType),
						PackageURL: *c.ComponentPurl,
						Version:    c.Component.Version,
						Name:       fmt.Sprintf("%s/%s", p.Namespace, p.Name),
					})
				}
			}
		}

		if c.DependencyPurl != "" {
			p, err = packageurl.FromString(c.DependencyPurl)
			if err == nil {
				alreadyIncluded[c.DependencyPurl] = true
				bomComponents = append(bomComponents, cdx.Component{
					BOMRef:     c.DependencyPurl,
					Type:       cdx.ComponentType(c.Dependency.ComponentType),
					PackageURL: c.DependencyPurl,
					Name:       fmt.Sprintf("%s/%s", p.Namespace, p.Name),
					Version:    c.Dependency.Version,
				})
			}
		}
	}

	// build up the dependency map
	dependencyMap := make(map[string][]string)
	for _, c := range components {
		if c.ComponentPurl == nil {
			if _, ok := dependencyMap[asset.Slug]; !ok {
				dependencyMap[asset.Slug] = []string{c.DependencyPurl}
				continue
			}
			dependencyMap[asset.Slug] = append(dependencyMap[asset.Slug], c.DependencyPurl)
			continue
		}
		if _, ok := dependencyMap[*c.ComponentPurl]; !ok {
			dependencyMap[*c.ComponentPurl] = make([]string, 0)
		}
		dependencyMap[*c.ComponentPurl] = append(dependencyMap[*c.ComponentPurl], c.DependencyPurl)
	}

	// build up the dependencies
	bomDependencies := make([]cdx.Dependency, len(dependencyMap))
	i := 0
	for k, v := range dependencyMap {
		vtmp := v
		bomDependencies[i] = cdx.Dependency{
			Ref:          k,
			Dependencies: &vtmp,
		}
		i++
	}
	bom.Dependencies = &bomDependencies
	bom.Components = &bomComponents
	return &bom
}

func (s *service) BuildVeX(asset models.Asset, version string, organizationName string, components []models.ComponentDependency, flaws []models.Flaw) *cdx.BOM {
	if version == models.NoVersion {
		version = "latest"
	}

	bom := cdx.BOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: cyclonedx.SpecVersion1_5,
		Version:     1,
		Metadata: &cdx.Metadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Component: &cdx.Component{
				BOMRef:    asset.Slug,
				Type:      cdx.ComponentTypeApplication,
				Name:      asset.Name,
				Version:   version,
				Author:    organizationName,
				Publisher: "github.com/l3montree-dev/devguard",
			},
		},
	}
	vulnerabilities := make([]cdx.Vulnerability, 0)
	for _, flaw := range flaws {
		// check if cve
		cve := flaw.CVE
		if cve != nil {
			vuln := cdx.Vulnerability{
				ID: cve.CVE,
				Source: &cdx.Source{
					Name: "NVD",
					URL:  fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", *flaw.CVEID),
				},
				Affects: &[]cdx.Affects{{
					Ref: *flaw.ComponentPurl,
				}},
				Analysis: &cdx.VulnerabilityAnalysis{
					State: flawStateToImpactAnalysisState(flaw.State),
				},
			}

			response := flawStateToResponseStatus(flaw.State)
			if response != "" {
				vuln.Analysis.Response = &[]cdx.ImpactAnalysisResponse{response}
			}

			justification := getJustification(flaw)
			if justification != nil {
				vuln.Analysis.Detail = *justification
			}

			cvss := math.Round(float64(cve.CVSS)*100) / 100

			risk := risk.RawRisk(*cve, core.GetEnvironmentalFromAsset(asset), *flaw.ComponentDepth)

			vuln.Ratings = &[]cdx.VulnerabilityRating{
				{
					Vector:   cve.Vector,
					Method:   vectorToCVSSScoringMethod(cve.Vector),
					Score:    &cvss,
					Severity: scoreToSeverity(cvss),
				},
				{
					Vector:        risk.Vector,
					Method:        "DevGuard",
					Score:         &risk.Risk,
					Severity:      scoreToSeverity(risk.Risk),
					Justification: risk.String(),
				},
			}

			vulnerabilities = append(vulnerabilities, vuln)
		}
	}
	bom.Vulnerabilities = &vulnerabilities

	return &bom
}

func scoreToSeverity(score float64) cdx.Severity {
	if score >= 9.0 {
		return cdx.SeverityCritical
	} else if score >= 7.0 {
		return cdx.SeverityHigh
	} else if score >= 4.0 {
		return cdx.SeverityMedium
	}
	return cdx.SeverityLow
}

func vectorToCVSSScoringMethod(vector string) cdx.ScoringMethod {
	if strings.Contains(vector, "CVSS:3.0") {
		return cdx.ScoringMethodCVSSv3
	} else if strings.Contains(vector, "CVSS:2.0") {
		return cdx.ScoringMethodCVSSv2
	} else if strings.Contains(vector, "CVSS:3.1") {
		return cdx.ScoringMethodCVSSv31
	}
	return cdx.ScoringMethodCVSSv4
}

func flawStateToImpactAnalysisState(state models.FlawState) cdx.ImpactAnalysisState {
	switch state {
	case models.FlawStateOpen:
		return cdx.IASInTriage
	case models.FlawStateFixed:
		return cdx.IASResolved
	case models.FlawStateAccepted:
		return cdx.IASExploitable
	case models.FlawStateFalsePositive:
		return cdx.IASFalsePositive
	case models.FlawStateMarkedForTransfer:
		return cdx.IASInTriage
	default:
		return cdx.IASInTriage
	}
}

func getJustification(flaw models.Flaw) *string {
	// check if we have any event
	if len(flaw.Events) > 0 {
		// look for the last event which has a justification
		for i := len(flaw.Events) - 1; i >= 0; i-- {
			if flaw.Events[i].Justification != nil {
				return flaw.Events[i].Justification
			}
		}
	}
	return nil
}

func flawStateToResponseStatus(state models.FlawState) cdx.ImpactAnalysisResponse {
	switch state {
	case models.FlawStateOpen:
		return ""
	case models.FlawStateFixed:
		return cdx.IARUpdate
	case models.FlawStateAccepted:
		return cdx.IARWillNotFix
	case models.FlawStateFalsePositive:
		return cdx.IARWillNotFix
	case models.FlawStateMarkedForTransfer:
		return ""
	default:
		return ""
	}
}
