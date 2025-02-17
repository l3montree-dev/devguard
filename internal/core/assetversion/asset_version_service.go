package assetversion

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
	"github.com/l3montree-dev/devguard/internal/database/models"

	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/package-url/packageurl-go"
	"github.com/pkg/errors"
)

type assetVersionRepository interface {
	GetDB(core.DB) core.DB
	Save(tx core.DB, assetVersion *models.AssetVersion) error
	GetAllAssetsVersionFromDBByAssetID(tx core.DB, assetID uuid.UUID) ([]models.AssetVersion, error)
}

type assetRepository interface {
	GetByAssetID(assetID uuid.UUID) (models.Asset, error)
}

type service struct {
	flawRepository         flawRepository
	componentRepository    componentRepository
	flawService            flawService
	assetVersionRepository assetVersionRepository
	assetRepository        assetRepository
	httpClient             *http.Client
}

func NewService(assetVersionRepository assetVersionRepository, componentRepository componentRepository, flawRepository flawRepository, flawService flawService, assetRepository assetRepository) *service {
	return &service{
		assetVersionRepository: assetVersionRepository,
		componentRepository:    componentRepository,
		flawRepository:         flawRepository,
		flawService:            flawService,
		assetRepository:        assetRepository,
		httpClient:             &http.Client{},
	}
}

func (s *service) GetAssetVersionsByAssetID(assetID uuid.UUID) ([]models.AssetVersion, error) {
	return s.assetVersionRepository.GetAllAssetsVersionFromDBByAssetID(nil, assetID)
}

func (s *service) HandleScanResult(asset models.Asset, assetVersion models.AssetVersion, vulns []models.VulnInPackage, scanner string, version string, scannerID string, userID string, doRiskManagement bool) (amountOpened int, amountClose int, newState []models.Flaw, err error) {

	// create flaws out of those vulnerabilities
	flaws := []models.Flaw{}

	// load all asset components again and build a dependency tree
	assetComponents, err := s.componentRepository.LoadComponents(nil, assetVersion.Name, assetVersion.AssetID, scanner, version)
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
			AssetVersionName:      assetVersion.Name,
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
	amountOpened, amountClosed, amountExisting, err := s.handleScanResult(userID, scannerID, assetVersion, flaws, doRiskManagement, asset)
	if err != nil {
		return 0, 0, []models.Flaw{}, err
	}

	switch scanner {
	case "sast":
		assetVersion.LastSastScan = utils.Ptr(time.Now())
	case "dast":
		assetVersion.LastDastScan = utils.Ptr(time.Now())
	case "sca":
		assetVersion.LastScaScan = utils.Ptr(time.Now())
	case "container-scanning":
		assetVersion.LastContainerScan = utils.Ptr(time.Now())
	case "secret-scanning":
		assetVersion.LastSecretScan = utils.Ptr(time.Now())
	case "iac":
		assetVersion.LastIacScan = utils.Ptr(time.Now())
	}

	if doRiskManagement {
		err = s.assetVersionRepository.Save(nil, &assetVersion)
		if err != nil {
			// swallow but log
			slog.Error("could not save asset", "err", err)
		}
	}
	return amountOpened, amountClosed, amountExisting, nil
}

func (s *service) handleScanResult(userID string, scannerID string, assetVersion models.AssetVersion, flaws []models.Flaw, doRiskManagement bool, asset models.Asset) (int, int, []models.Flaw, error) {
	// get all existing flaws from the database - this is the old state
	existingFlaws, err := s.flawRepository.ListByScanner(assetVersion.Name, assetVersion.AssetID, scannerID)
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

	fmt.Println("flaws", flaws)
	fmt.Println("fixedFlaws", fixedFlaws)
	fmt.Println("newFlaws", newFlaws)

	if doRiskManagement {
		// get a transaction
		if err := s.flawRepository.Transaction(func(tx core.DB) error {
			if err := s.flawService.UserDetectedFlaws(tx, userID, newFlaws, assetVersion, asset, true); err != nil {

				// this will cancel the transaction
				return err
			}
			return s.flawService.UserFixedFlaws(tx, userID, utils.Filter(
				fixedFlaws,
				func(flaw models.Flaw) bool {
					return flaw.State == models.FlawStateOpen
				},
			), assetVersion, asset, true)
		}); err != nil {
			slog.Error("could not save flaws", "err", err)
			return 0, 0, []models.Flaw{}, err
		}
	} else {
		if err := s.flawService.UserDetectedFlaws(nil, userID, newFlaws, assetVersion, asset, false); err != nil {
			slog.Error("could not save flaws", "err", err)
			return 0, 0, []models.Flaw{}, err
		}

		if err := s.flawService.UserFixedFlaws(nil, userID, utils.Filter(
			fixedFlaws,
			func(flaw models.Flaw) bool {
				return flaw.State == models.FlawStateOpen
			},
		), assetVersion, asset, false); err != nil {
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

func (s *service) UpdateSBOM(assetVersion models.AssetVersion, scannerID string, currentVersion string, sbom normalize.SBOM) error {
	// load the asset components
	assetComponents, err := s.componentRepository.LoadComponents(nil, assetVersion.Name, assetVersion.AssetID, scannerID, currentVersion)
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

	return s.componentRepository.HandleStateDiff(nil, assetVersion.Name, assetVersion.AssetID, currentVersion, assetComponents, dependencies)
}

func (s *service) BuildSBOM(assetVersion models.AssetVersion, version string, organizationName string, components []models.ComponentDependency) *cdx.BOM {

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
				BOMRef:    assetVersion.Slug,
				Type:      cdx.ComponentTypeApplication,
				Name:      assetVersion.Name,
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
			if _, ok := dependencyMap[assetVersion.Slug]; !ok {
				dependencyMap[assetVersion.Slug] = []string{c.DependencyPurl}
				continue
			}
			dependencyMap[assetVersion.Slug] = append(dependencyMap[assetVersion.Slug], c.DependencyPurl)
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

func (s *service) BuildVeX(asset models.Asset, assetVersion models.AssetVersion, version string, organizationName string, components []models.ComponentDependency, flaws []models.Flaw) *cdx.BOM {
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
				BOMRef:    assetVersion.Slug,
				Type:      cdx.ComponentTypeApplication,
				Name:      assetVersion.Name,
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
