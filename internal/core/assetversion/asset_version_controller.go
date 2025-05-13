package assetversion

import (
	"net/url"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/normalize"
	"github.com/l3montree-dev/devguard/internal/core/vuln"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/labstack/echo/v4"
	"github.com/openvex/go-vex/pkg/vex"
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

func (a *assetVersionController) Read(ctx core.Context) error {
	assetVersion := core.GetAssetVersion(ctx)
	return ctx.JSON(200, assetVersion)
}

// Function to delete provided asset version
func (a *assetVersionController) Delete(ctx core.Context) error {
	assetVersion := core.GetAssetVersion(ctx)                  //Get the asset provided in the context / URL
	err := a.assetVersionRepository.Delete(nil, &assetVersion) //Call delete on the returned assetVersion
	if err != nil {
		slog.Error("error when trying to call delete function in assetVersionRepository", "err", err)
		return err
	}
	return ctx.JSON(200, "deleted asset version successfully")
}

func (a *assetVersionController) GetAssetVersionsByAssetID(ctx core.Context) error {
	asset := core.GetAsset(ctx)

	assetVersions, err := a.assetVersionService.GetAssetVersionsByAssetID(asset.ID)
	if err != nil {
		return err
	}
	return ctx.JSON(200, assetVersions)
}

func (a *assetVersionController) AffectedComponents(ctx core.Context) error {
	scannerID := ctx.QueryParam("scanner")
	if scannerID == "" {
		return echo.NewHTTPError(400, "scanner query param is required")
	}

	assetVersion := core.GetAssetVersion(ctx)
	_, dependencyVulns, err := a.getComponentsAndDependencyVulns(assetVersion, scannerID)
	if err != nil {
		return err
	}

	return ctx.JSON(200, utils.Map(dependencyVulns, func(m models.DependencyVuln) vuln.DependencyVulnDTO {
		return vuln.DependencyVulnToDto(m)
	}))
}

func (a *assetVersionController) getComponentsAndDependencyVulns(assetVersion models.AssetVersion, scannerID string) ([]models.ComponentDependency, []models.DependencyVuln, error) {
	components, err := a.componentRepository.LoadComponents(nil, assetVersion.Name, assetVersion.AssetID, scannerID)
	if err != nil {
		return nil, nil, err
	}

	purls := utils.Map(components, func(ctx models.ComponentDependency) string {
		return ctx.DependencyPurl
	})

	dependencyVulns, err := a.dependencyVulnRepository.GetDependencyVulnsByPurl(nil, purls)
	if err != nil {
		return nil, nil, err
	}
	return components, dependencyVulns, nil
}

func (a *assetVersionController) DependencyGraph(ctx core.Context) error {
	app := core.GetAssetVersion(ctx)

	scannerID := ctx.QueryParam("scanner")
	if scannerID == "" {
		return echo.NewHTTPError(400, "scanner query param is required")
	}

	components, err := a.componentRepository.LoadComponents(nil, app.Name, app.AssetID, scannerID)
	if err != nil {
		return err
	}

	tree := BuildDependencyTree(components)
	if tree.Root.Children == nil {
		tree.Root.Children = make([]*treeNode, 0)
	}

	return ctx.JSON(200, tree)
}

// function to return a graph of all dependencies which lead to the requested pURL
func (a *assetVersionController) GetDependencyPathFromPURL(ctx core.Context) error {
	assetVersion := core.GetAssetVersion(ctx)

	scannerID := ctx.QueryParam("scanner")
	pURL := ctx.QueryParam("purl")

	if scannerID == "" {
		return echo.NewHTTPError(400, "scanner query param is required")
	}

	components, err := a.componentRepository.LoadPathToComponent(nil, assetVersion.Name, assetVersion.AssetID, pURL, scannerID)
	if err != nil {
		return err
	}

	tree := BuildDependencyTree(components)
	if tree.Root.Children == nil {
		tree.Root.Children = make([]*treeNode, 0)
	}

	return ctx.JSON(200, tree)
}

func (a *assetVersionController) SBOMJSON(ctx core.Context) error {
	sbom, err := a.buildSBOM(ctx)
	if err != nil {
		return err
	}
	return cdx.NewBOMEncoder(ctx.Response().Writer, cdx.BOMFileFormatJSON).Encode(sbom)
}

func (a *assetVersionController) SBOMXML(ctx core.Context) error {
	sbom, err := a.buildSBOM(ctx)
	if err != nil {
		return err
	}

	return cdx.NewBOMEncoder(ctx.Response().Writer, cdx.BOMFileFormatXML).Encode(sbom)
}

func (a *assetVersionController) VEXXML(ctx core.Context) error {
	sbom, err := a.buildVeX(ctx)
	if err != nil {
		return err
	}

	return cdx.NewBOMEncoder(ctx.Response().Writer, cdx.BOMFileFormatXML).Encode(sbom)
}

func (a *assetVersionController) VEXJSON(ctx core.Context) error {
	sbom, err := a.buildVeX(ctx)
	if err != nil {
		return err
	}

	return cdx.NewBOMEncoder(ctx.Response().Writer, cdx.BOMFileFormatJSON).Encode(sbom)
}

func (a *assetVersionController) OpenVEXJSON(ctx core.Context) error {
	vex, err := a.buildOpenVeX(ctx)
	if err != nil {
		return err
	}

	return vex.ToJSON(ctx.Response().Writer)
}

func (a *assetVersionController) buildSBOM(ctx core.Context) (*cdx.BOM, error) {

	assetVersion := core.GetAssetVersion(ctx)
	org := core.GetOrganization(ctx)
	// check for version query param
	version := ctx.QueryParam("version")
	if version == "" {
		version = models.NoVersion
	} else {
		var err error
		version, err = normalize.SemverFix(version)
		if err != nil {
			return nil, err
		}
	}

	scannerID := ctx.QueryParam("scanner")
	if scannerID == "" {
		return nil, echo.NewHTTPError(400, "scanner query param is required")
	}

	components, err := a.componentRepository.LoadComponentsWithProject(nil, assetVersion.Name, assetVersion.AssetID, scannerID, core.PageInfo{
		PageSize: 1000,
		Page:     1,
	}, "", nil, nil)
	if err != nil {
		return nil, err
	}

	return a.assetVersionService.BuildSBOM(assetVersion, version, org.Name, components.Data), nil
}

func (a *assetVersionController) buildOpenVeX(ctx core.Context) (vex.VEX, error) {
	asset := core.GetAsset(ctx)
	assetVersion := core.GetAssetVersion(ctx)
	org := core.GetOrganization(ctx)
	// check for version query param
	version := ctx.QueryParam("version")
	if version == "" {
		version = models.NoVersion
	} else {
		var err error
		version, err = normalize.SemverFix(version)
		if err != nil {
			return vex.VEX{}, err
		}
	}

	scannerID := ctx.QueryParam("scanner")

	// url decode the scanner
	scannerID, err := url.QueryUnescape(scannerID)
	if err != nil {
		return vex.VEX{}, err
	}

	// get all associated dependencyVulns
	_, dependencyVulns, err := a.getComponentsAndDependencyVulns(assetVersion, scannerID)
	if err != nil {
		return vex.VEX{}, err
	}

	return a.assetVersionService.BuildOpenVeX(asset, assetVersion, version, org.Slug, dependencyVulns), nil
}

func (a *assetVersionController) buildVeX(ctx core.Context) (*cdx.BOM, error) {
	asset := core.GetAsset(ctx)
	assetVersion := core.GetAssetVersion(ctx)
	org := core.GetOrganization(ctx)
	// check for version query param
	version := ctx.QueryParam("version")
	if version == "" {
		version = models.NoVersion
	} else {
		var err error
		version, err = normalize.SemverFix(version)
		if err != nil {
			return nil, err
		}
	}

	scannerID := ctx.QueryParam("scanner")

	// url decode the scanner
	scannerID, err := url.QueryUnescape(scannerID)
	if err != nil {
		return nil, err
	}

	// get all associated dependencyVulns
	components, dependencyVulns, err := a.getComponentsAndDependencyVulns(assetVersion, scannerID)
	if err != nil {
		return nil, err
	}

	return a.assetVersionService.BuildVeX(asset, assetVersion, version, org.Name, components, dependencyVulns), nil
}

func (a *assetVersionController) Metrics(ctx core.Context) error {
	assetVersion := core.GetAssetVersion(ctx)
	scannerIds := []string{}
	// get the latest events of this asset per scan type
	err := a.assetVersionRepository.GetDB(nil).Table("dependency_vulns").Select("DISTINCT scanner_ids").Where("asset_version_name  = ? AND asset_id = ?", assetVersion.Name, assetVersion.AssetID).Pluck("scanner_ids", &scannerIds).Error

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

	return ctx.JSON(200, assetMetrics{
		EnabledContainerScanning:       enabledContainerScanning,
		EnabledSCA:                     enabledSca,
		EnabledImageSigning:            enabledImageSigning,
		VerifiedSupplyChainsPercentage: verifiedSupplyChainsPercentage,
	})
}
