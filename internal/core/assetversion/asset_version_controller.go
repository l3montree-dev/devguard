package assetversion

import (
	"net/url"
	"slices"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/dependency_vuln"
	"github.com/l3montree-dev/devguard/internal/core/normalize"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/labstack/echo/v4"
	"golang.org/x/exp/slog"
)

type assetVersionController struct {
	assetVersionRepository   core.AssetVersionRepository
	assetVersionService      core.AssetVersionService
	dependencyVulnRepository core.DependencyVulnRepository
	componentRepository      core.ComponentRepository
	dependencyVulnService    core.DependencyVulnService
	supplyChainRepository    core.SupplyChainRepository
}

func NewAssetVersionController(
	assetVersionRepository core.AssetVersionRepository,
	assetVersionService core.AssetVersionService,
	dependencyVulnRepository core.DependencyVulnRepository,
	componentRepository core.ComponentRepository,
	dependencyVulnService core.DependencyVulnService,
	supplyChainRepository core.SupplyChainRepository,
) *assetVersionController {
	return &assetVersionController{
		assetVersionRepository:   assetVersionRepository,
		assetVersionService:      assetVersionService,
		dependencyVulnRepository: dependencyVulnRepository,
		componentRepository:      componentRepository,
		dependencyVulnService:    dependencyVulnService,
		supplyChainRepository:    supplyChainRepository,
	}
}

func (a *assetVersionController) Read(c core.Context) error {
	assetVersion := core.GetAssetVersion(c)
	return c.JSON(200, assetVersion)
}

// Function to delete provided asset version
func (a *assetVersionController) Delete(c core.Context) error {
	assetVersion := core.GetAssetVersion(c)                    //Get the asset provided in the context / URL
	err := a.assetVersionRepository.Delete(nil, &assetVersion) //Call delete on the returned assetVersion
	if err != nil {
		slog.Error("error when trying to call delete function in assetVersionRepository", "err", err)
		return err
	}
	return c.JSON(200, "deleted asset version successfully")
}

func (a *assetVersionController) GetAssetVersionsByAssetID(c core.Context) error {
	asset := core.GetAsset(c)

	assetVersions, err := a.assetVersionService.GetAssetVersionsByAssetID(asset.ID)
	if err != nil {
		return err
	}
	return c.JSON(200, assetVersions)
}

func (a *assetVersionController) Versions(c core.Context) error {
	assetVersion := core.GetAssetVersion(c)
	versions, err := a.componentRepository.GetVersions(nil, assetVersion)
	if err != nil {
		return err
	}

	// order the version in descending order
	normalize.SemverSort(versions)

	// now only reverse it
	slices.Reverse(versions)

	return c.JSON(200, versions)
}

func (a *assetVersionController) AffectedComponents(c core.Context) error {

	scanner := c.QueryParam("scanner")
	if scanner == "" {
		return echo.NewHTTPError(400, "scanner query param is required")
	}

	assetVersion := core.GetAssetVersion(c)
	_, dependencyVulns, err := a.getComponentsAndDependencyVulns(assetVersion, scanner)
	if err != nil {
		return err
	}

	return c.JSON(200, utils.Map(dependencyVulns, func(m models.DependencyVuln) dependency_vuln.DependencyVulnDTO {
		return dependency_vuln.DependencyVulnToDto(m)
	}))
}

func (a *assetVersionController) getComponentsAndDependencyVulns(assetVersion models.AssetVersion, scanner string) ([]models.ComponentDependency, []models.DependencyVuln, error) {
	components, err := a.componentRepository.LoadComponents(nil, assetVersion.Name, assetVersion.AssetID, scanner)
	if err != nil {
		return nil, nil, err
	}

	purls := utils.Map(components, func(c models.ComponentDependency) string {
		return c.DependencyPurl
	})

	dependencyVulns, err := a.dependencyVulnRepository.GetDependencyVulnsByPurl(nil, purls)
	if err != nil {
		return nil, nil, err
	}
	return components, dependencyVulns, nil
}

func (a *assetVersionController) DependencyGraph(c core.Context) error {
	app := core.GetAssetVersion(c)

	scanner := c.QueryParam("scanner")
	if scanner == "" {
		return echo.NewHTTPError(400, "scanner query param is required")
	}

	components, err := a.componentRepository.LoadComponents(nil, app.Name, app.AssetID, scanner)
	if err != nil {
		return err
	}

	tree := BuildDependencyTree(components)
	if tree.Root.Children == nil {
		tree.Root.Children = make([]*treeNode, 0)
	}

	return c.JSON(200, tree)
}

func (a *assetVersionController) SBOMJSON(c core.Context) error {
	sbom, err := a.buildSBOM(c)
	if err != nil {
		return err
	}
	return cdx.NewBOMEncoder(c.Response().Writer, cdx.BOMFileFormatJSON).Encode(sbom)
}

func (a *assetVersionController) SBOMXML(c core.Context) error {
	sbom, err := a.buildSBOM(c)
	if err != nil {
		return err
	}

	return cdx.NewBOMEncoder(c.Response().Writer, cdx.BOMFileFormatXML).Encode(sbom)
}

func (a *assetVersionController) VEXXML(c core.Context) error {
	sbom, err := a.buildVeX(c)
	if err != nil {
		return err
	}

	return cdx.NewBOMEncoder(c.Response().Writer, cdx.BOMFileFormatXML).Encode(sbom)
}

func (a *assetVersionController) VEXJSON(c core.Context) error {
	sbom, err := a.buildVeX(c)
	if err != nil {
		return err
	}

	return cdx.NewBOMEncoder(c.Response().Writer, cdx.BOMFileFormatJSON).Encode(sbom)
}

func (a *assetVersionController) buildSBOM(c core.Context) (*cdx.BOM, error) {

	assetVersion := core.GetAssetVersion(c)
	org := core.GetOrganization(c)
	// check for version query param
	version := c.QueryParam("version")
	if version == "" {
		version = models.NoVersion
	} else {
		var err error
		version, err = normalize.SemverFix(version)
		if err != nil {
			return nil, err
		}
	}

	scanner := c.QueryParam("scanner")
	if scanner == "" {
		return nil, echo.NewHTTPError(400, "scanner query param is required")
	}

	components, err := a.componentRepository.LoadComponents(nil, assetVersion.Name, assetVersion.AssetID, scanner)
	if err != nil {
		return nil, err
	}
	return a.assetVersionService.BuildSBOM(assetVersion, version, org.Name, components), nil
}

func (a *assetVersionController) buildVeX(c core.Context) (*cdx.BOM, error) {
	asset := core.GetAsset(c)
	assetVersion := core.GetAssetVersion(c)
	org := core.GetOrganization(c)
	// check for version query param
	version := c.QueryParam("version")
	if version == "" {
		version = models.NoVersion
	} else {
		var err error
		version, err = normalize.SemverFix(version)
		if err != nil {
			return nil, err
		}
	}

	scanner := c.QueryParam("scanner")
	if scanner == "" {
		return nil, echo.NewHTTPError(400, "scanner query param is required")
	}

	// url decode the scanner
	scanner, err := url.QueryUnescape(scanner)
	if err != nil {
		return nil, err
	}

	// get all associated dependencyVulns
	components, dependencyVulns, err := a.getComponentsAndDependencyVulns(assetVersion, scanner)
	if err != nil {
		return nil, err
	}

	return a.assetVersionService.BuildVeX(asset, assetVersion, version, org.Name, components, dependencyVulns), nil
}

func (a *assetVersionController) Metrics(c core.Context) error {
	assetVersion := core.GetAssetVersion(c)
	scannerIds := []string{}
	// get the latest events of this asset per scan type
	err := a.assetVersionRepository.GetDB(nil).Table("dependency_vulns").Select("DISTINCT scanner_id").Where("asset_version_name  = ? AND asset_id = ?", assetVersion.Name, assetVersion.AssetID).Pluck("scanner_id", &scannerIds).Error

	if err != nil {
		return err
	}

	var enabledSca bool = false
	var enabledContainerScanning bool = false
	var enabledImageSigning bool = assetVersion.SigningPubKey != nil

	for _, scannerId := range scannerIds {
		if scannerId == "github.com/l3montree-dev/devguard/cmd/devguard-scanner/sca" {
			enabledSca = true
		}
		if scannerId == "github.com/l3montree-dev/devguard/cmd/devguard-scanner/container-scanning" {
			enabledContainerScanning = true
		}
	}

	// check if in-toto is enabled
	verifiedSupplyChainsPercentage, err := a.supplyChainRepository.PercentageOfVerifiedSupplyChains(assetVersion.Name, assetVersion.AssetID)
	if err != nil {
		return err
	}

	return c.JSON(200, assetMetrics{
		EnabledContainerScanning:       enabledContainerScanning,
		EnabledSCA:                     enabledSca,
		EnabledImageSigning:            enabledImageSigning,
		VerifiedSupplyChainsPercentage: verifiedSupplyChainsPercentage,
	})
}
