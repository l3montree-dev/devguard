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

type service struct {
	dependencyVulnRepository core.DependencyVulnRepository
	firstPartyVulnRepository core.FirstPartyVulnRepository
	componentRepository      core.ComponentRepository
	dependencyVulnService    core.DependencyVulnService
	firstPartyVulnService    core.FirstPartyVulnService
	assetVersionRepository   core.AssetVersionRepository
	assetRepository          core.AssetRepository
	componentService         core.ComponentService
	httpClient               *http.Client
}

func NewService(assetVersionRepository core.AssetVersionRepository, componentRepository core.ComponentRepository, dependencyVulnRepository core.DependencyVulnRepository, firstPartyVulnRepository core.FirstPartyVulnRepository, dependencyVulnService core.DependencyVulnService, firstPartyVulnService core.FirstPartyVulnService, assetRepository core.AssetRepository, componentService core.ComponentService) *service {
	return &service{
		assetVersionRepository:   assetVersionRepository,
		componentRepository:      componentRepository,
		dependencyVulnRepository: dependencyVulnRepository,
		firstPartyVulnRepository: firstPartyVulnRepository,
		dependencyVulnService:    dependencyVulnService,
		firstPartyVulnService:    firstPartyVulnService,
		componentService:         componentService,
		assetRepository:          assetRepository,
		httpClient:               &http.Client{},
	}
}

func (s *service) GetAssetVersionsByAssetID(assetID uuid.UUID) ([]models.AssetVersion, error) {
	return s.assetVersionRepository.GetAllAssetsVersionFromDBByAssetID(nil, assetID)
}

func (s *service) HandleFirstPartyVulnResult(asset models.Asset, assetVersion *models.AssetVersion, sarifScan models.SarifResult, scannerID string, userID string, doRiskManagement bool) (int, int, []models.FirstPartyVulnerability, error) {

	firstPartyVulnerabilities := []models.FirstPartyVulnerability{}

	for _, run := range sarifScan.Runs {
		for _, result := range run.Results {

			snippet := result.Locations[0].PhysicalLocation.Region.Snippet.Text
			if scannerID == "github.com/l3montree-dev/devguard/cmd/devguard-scanner/secret-scanning" {
				snippetMax := 20
				if snippetMax < len(snippet)/2 {
					snippetMax = len(snippet) / 2
				}
				snippet = snippet[:snippetMax] + "***"
			}

			firstPartyVulnerability := models.FirstPartyVulnerability{
				Vulnerability: models.Vulnerability{
					AssetVersionName: assetVersion.Name,
					AssetID:          asset.ID,
					Message:          &result.Message.Text,
					ScannerID:        scannerID,
				},
				RuleID:      result.RuleId,
				Uri:         result.Locations[0].PhysicalLocation.ArtifactLocation.Uri,
				StartLine:   result.Locations[0].PhysicalLocation.Region.StartLine,
				StartColumn: result.Locations[0].PhysicalLocation.Region.StartColumn,
				EndLine:     result.Locations[0].PhysicalLocation.Region.EndLine,
				EndColumn:   result.Locations[0].PhysicalLocation.Region.EndColumn,
				Snippet:     snippet,
				Commit:      result.PartialFingerprints.CommitSha,
				Email:       result.PartialFingerprints.Email,
				Author:      result.PartialFingerprints.Author,
				Date:        result.PartialFingerprints.Date,
			}

			firstPartyVulnerabilities = append(firstPartyVulnerabilities, firstPartyVulnerability)
		}
	}

	firstPartyVulnerabilities = utils.UniqBy(firstPartyVulnerabilities, func(f models.FirstPartyVulnerability) string {
		return f.CalculateHash()
	})

	amountOpened, amountClosed, amountExisting, err := s.handleFirstPartyVulnResult(userID, scannerID, assetVersion, firstPartyVulnerabilities, doRiskManagement, asset)
	if err != nil {
		return 0, 0, []models.FirstPartyVulnerability{}, err
	}

	devguardScanner := "github.com/l3montree-dev/devguard/cmd/devguard-scanner" + "/"
	switch scannerID {
	case devguardScanner + "sast":
		assetVersion.LastSastScan = utils.Ptr(time.Now())
	case devguardScanner + "dast":
		assetVersion.LastDastScan = utils.Ptr(time.Now())
	case devguardScanner + "secret-scanning":
		assetVersion.LastSecretScan = utils.Ptr(time.Now())
	case devguardScanner + "iac":
		assetVersion.LastIacScan = utils.Ptr(time.Now())
	}

	return amountOpened, amountClosed, amountExisting, nil
}

func (s *service) handleFirstPartyVulnResult(userID string, scannerID string, assetVersion *models.AssetVersion, vulns []models.FirstPartyVulnerability, doRiskManagement bool, asset models.Asset) (int, int, []models.FirstPartyVulnerability, error) {
	// get all existing vulns from the database - this is the old state
	existingVulns, err := s.firstPartyVulnRepository.ListByScanner(assetVersion.Name, assetVersion.AssetID, scannerID)
	if err != nil {
		slog.Error("could not get existing vulns", "err", err)
		return 0, 0, []models.FirstPartyVulnerability{}, err
	}

	// remove all fixed vulns from the existing vulns
	existingVulns = utils.Filter(existingVulns, func(vuln models.FirstPartyVulnerability) bool {
		return vuln.State != models.VulnStateFixed
	})

	comparison := utils.CompareSlices(existingVulns, vulns, func(vuln models.FirstPartyVulnerability) string {
		return vuln.CalculateHash()
	})

	fixedVulns := comparison.OnlyInA
	newVulns := comparison.OnlyInB

	// get a transaction
	if err := s.firstPartyVulnRepository.Transaction(func(tx core.DB) error {
		if err := s.firstPartyVulnService.UserDetectedFirstPartyVulns(tx, userID, newVulns, true); err != nil {
			// this will cancel the transaction
			return err
		}
		return s.firstPartyVulnService.UserFixedFirstPartyVulns(tx, userID, fixedVulns, true)
	}); err != nil {
		slog.Error("could not save vulns", "err", err)
		return 0, 0, []models.FirstPartyVulnerability{}, err
	}

	// the amount we actually fixed, is the amount that was open before
	fixedVulns = utils.Filter(fixedVulns, func(vuln models.FirstPartyVulnerability) bool {
		return vuln.State == models.VulnStateOpen
	})

	return len(newVulns), len(fixedVulns), append(newVulns, comparison.InBoth...), nil
}

func (s *service) HandleScanResult(asset models.Asset, assetVersion *models.AssetVersion, vulns []models.VulnInPackage, scanner string, scannerID string, userID string, doRiskManagement bool) (amountOpened int, amountClose int, newState []models.DependencyVuln, err error) {

	// create dependencyVulns out of those vulnerabilities
	dependencyVulns := []models.DependencyVuln{}

	// load all asset components again and build a dependency tree
	assetComponents, err := s.componentRepository.LoadComponents(nil, assetVersion.Name, assetVersion.AssetID, scanner)
	if err != nil {
		return 0, 0, []models.DependencyVuln{}, errors.Wrap(err, "could not load asset components")
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

		dependencyVuln := models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				AssetVersionName: assetVersion.Name,
				AssetID:          asset.ID,
				ScannerID:        scannerID,
			},
			CVEID:                 utils.Ptr(v.CVEID),
			ComponentPurl:         utils.Ptr(v.Purl),
			ComponentFixedVersion: v.FixedVersion,
			ComponentDepth:        utils.Ptr(depthMap[v.Purl]),
			CVE:                   &v.CVE,
		}

		dependencyVulns = append(dependencyVulns, dependencyVuln)
	}

	dependencyVulns = utils.UniqBy(dependencyVulns, func(f models.DependencyVuln) string {
		return f.CalculateHash()
	})

	// let the asset service handle the new scan result - we do not need
	// any return value from that process - even if it fails, we should return the current dependencyVulns
	amountOpened, amountClosed, amountExisting, err := s.handleScanResult(userID, scannerID, assetVersion, dependencyVulns, doRiskManagement, asset)
	if err != nil {
		return 0, 0, []models.DependencyVuln{}, err
	}

	devguardScanner := "github.com/l3montree-dev/devguard/cmd/devguard-scanner" + "/"

	switch scanner {

	case devguardScanner + "sca":
		assetVersion.LastScaScan = utils.Ptr(time.Now())
	case devguardScanner + "container-scanning":
		assetVersion.LastContainerScan = utils.Ptr(time.Now())
	}

	return amountOpened, amountClosed, amountExisting, nil
}

func (s *service) handleScanResult(userID string, scannerID string, assetVersion *models.AssetVersion, dependencyVulns []models.DependencyVuln, doRiskManagement bool, asset models.Asset) (int, int, []models.DependencyVuln, error) {
	// get all existing dependencyVulns from the database - this is the old state
	existingDependencyVulns, err := s.dependencyVulnRepository.ListByScanner(assetVersion.Name, assetVersion.AssetID, scannerID)
	if err != nil {
		slog.Error("could not get existing dependencyVulns", "err", err)
		return 0, 0, []models.DependencyVuln{}, err
	}
	// remove all fixed dependencyVulns from the existing dependencyVulns
	existingDependencyVulns = utils.Filter(existingDependencyVulns, func(dependencyVuln models.DependencyVuln) bool {
		return dependencyVuln.State != models.VulnStateFixed
	})

	comparison := utils.CompareSlices(existingDependencyVulns, dependencyVulns, func(dependencyVuln models.DependencyVuln) string {
		return dependencyVuln.CalculateHash()
	})

	fixedDependencyVulns := comparison.OnlyInA
	newDependencyVulns := comparison.OnlyInB

	// get a transaction
	if err := s.dependencyVulnRepository.Transaction(func(tx core.DB) error {
		if err := s.dependencyVulnService.UserDetectedDependencyVulns(tx, userID, newDependencyVulns, *assetVersion, asset, true); err != nil {

			// this will cancel the transaction
			return err
		}
		return s.dependencyVulnService.UserFixedDependencyVulns(tx, userID, fixedDependencyVulns, *assetVersion, asset, true)
	}); err != nil {
		slog.Error("could not save dependencyVulns", "err", err)
		return 0, 0, []models.DependencyVuln{}, err
	}

	// the amount we actually fixed, is the amount that was open before
	fixedDependencyVulns = utils.Filter(fixedDependencyVulns, func(dependencyVuln models.DependencyVuln) bool {
		return dependencyVuln.State == models.VulnStateOpen
	})
	return len(newDependencyVulns), len(fixedDependencyVulns), append(newDependencyVulns, comparison.InBoth...), nil
}

func recursiveBuildBomRefMap(component cdx.Component) map[string]cdx.Component {
	res := make(map[string]cdx.Component)
	if component.Components == nil {
		return res
	}

	for _, component := range *component.Components {
		res[component.BOMRef] = component
		for k, v := range recursiveBuildBomRefMap(component) {
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

	for _, component := range *bom.GetComponents() {
		res[component.BOMRef] = component
		for k, v := range recursiveBuildBomRefMap(component) {
			res[k] = v
		}
	}
	return res
}

func (s *service) UpdateSBOM(assetVersion models.AssetVersion, scannerID string, sbom normalize.SBOM) error {
	// load the asset components
	assetComponents, err := s.componentRepository.LoadComponents(nil, assetVersion.Name, assetVersion.AssetID, scannerID)
	if err != nil {
		return errors.Wrap(err, "could not load asset components")
	}

	existingComponentPurls := make(map[string]bool)
	for _, c := range assetComponents {
		existingComponentPurls[c.Component.Purl] = true
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
					ComponentPurl:  nil, // direct dependency - therefore set it to nil
					ScannerID:      scannerID,
					DependencyPurl: componentPackageUrl,
				},
			)
			if _, ok := existingComponentPurls[componentPackageUrl]; !ok {
				components[componentPackageUrl] = models.Component{
					Purl:          componentPackageUrl,
					ComponentType: models.ComponentType(component.Type),
					Version:       component.Version,
				}
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
					ComponentPurl:  utils.EmptyThenNil(compPackageUrl),
					ScannerID:      scannerID,
					DependencyPurl: depPurlOrName,
				},
			)

			if _, ok := existingComponentPurls[depPurlOrName]; !ok {
				components[depPurlOrName] = models.Component{
					Purl:          depPurlOrName,
					ComponentType: models.ComponentType(dep.Type),
					Version:       dep.Version,
				}
			}

			if _, ok := existingComponentPurls[compPackageUrl]; !ok {
				components[compPackageUrl] = models.Component{
					Purl:          compPackageUrl,
					ComponentType: models.ComponentType(comp.Type),
					Version:       comp.Version,
				}
			}
		}
	}

	componentsSlice := make([]models.Component, 0, len(components))
	for _, c := range components {
		componentsSlice = append(componentsSlice, c)
	}

	// make sure, that the components exist
	if err := s.componentRepository.CreateBatch(nil, componentsSlice); err != nil {
		return err
	}

	if err = s.componentRepository.HandleStateDiff(nil, assetVersion.Name, assetVersion.AssetID, assetComponents, dependencies); err != nil {
		return err
	}

	// update the license information in the background
	go func() {
		slog.Info("updating license information in background", "asset", assetVersion.Name, "assetID", assetVersion.AssetID)

		_, err := s.componentService.GetAndSaveLicenseInformation(assetVersion.Name, assetVersion.AssetID, scannerID)
		if err != nil {
			slog.Error("could not update license information", "asset", assetVersion.Name, "assetID", assetVersion.AssetID, "err", err)
		} else {
			slog.Info("license information updated", "asset", assetVersion.Name, "assetID", assetVersion.AssetID)
		}
	}()

	return nil
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

func (s *service) BuildVeX(asset models.Asset, assetVersion models.AssetVersion, version string, organizationName string, components []models.ComponentDependency, dependencyVulns []models.DependencyVuln) *cdx.BOM {
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
	for _, dependencyVuln := range dependencyVulns {
		// check if cve
		cve := dependencyVuln.CVE
		if cve != nil {
			vuln := cdx.Vulnerability{
				ID: cve.CVE,
				Source: &cdx.Source{
					Name: "NVD",
					URL:  fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", *dependencyVuln.CVEID),
				},
				Affects: &[]cdx.Affects{{
					Ref: *dependencyVuln.ComponentPurl,
				}},
				Analysis: &cdx.VulnerabilityAnalysis{
					State: dependencyVulnStateToImpactAnalysisState(dependencyVuln.State),
				},
			}

			response := dependencyVulnStateToResponseStatus(dependencyVuln.State)
			if response != "" {
				vuln.Analysis.Response = &[]cdx.ImpactAnalysisResponse{response}
			}

			justification := getJustification(dependencyVuln)
			if justification != nil {
				vuln.Analysis.Detail = *justification
			}

			cvss := math.Round(float64(cve.CVSS)*100) / 100

			risk := risk.RawRisk(*cve, core.GetEnvironmentalFromAsset(asset), *dependencyVuln.ComponentDepth)

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

func dependencyVulnStateToImpactAnalysisState(state models.VulnState) cdx.ImpactAnalysisState {
	switch state {
	case models.VulnStateOpen:
		return cdx.IASInTriage
	case models.VulnStateFixed:
		return cdx.IASResolved
	case models.VulnStateAccepted:
		return cdx.IASExploitable
	case models.VulnStateFalsePositive:
		return cdx.IASFalsePositive
	case models.VulnStateMarkedForTransfer:
		return cdx.IASInTriage
	default:
		return cdx.IASInTriage
	}
}

func getJustification(dependencyVuln models.DependencyVuln) *string {
	// check if we have any event
	if len(dependencyVuln.Events) > 0 {
		// look for the last event which has a justification
		for i := len(dependencyVuln.Events) - 1; i >= 0; i-- {
			if dependencyVuln.Events[i].Justification != nil {
				return dependencyVuln.Events[i].Justification
			}
		}
	}
	return nil
}

func dependencyVulnStateToResponseStatus(state models.VulnState) cdx.ImpactAnalysisResponse {
	switch state {
	case models.VulnStateOpen:
		return ""
	case models.VulnStateFixed:
		return cdx.IARUpdate
	case models.VulnStateAccepted:
		return cdx.IARWillNotFix
	case models.VulnStateFalsePositive:
		return cdx.IARWillNotFix
	case models.VulnStateMarkedForTransfer:
		return ""
	default:
		return ""
	}
}
