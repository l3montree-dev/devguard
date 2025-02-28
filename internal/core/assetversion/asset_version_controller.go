package assetversion

import (
	"net/url"
	"slices"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/flaw"
	"github.com/l3montree-dev/devguard/internal/core/normalize"
	"github.com/l3montree-dev/devguard/internal/database"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/labstack/echo/v4"
	"golang.org/x/exp/slog"
)

type assetVersionComponentsLoader interface {
	GetVersions(tx core.DB, assetVersion models.AssetVersion) ([]string, error)
	LoadComponents(tx core.DB, assetVersionName string, assetID uuid.UUID, scanner, version string) ([]models.ComponentDependency, error)
}
type assetVersionService interface {
	BuildSBOM(assetVersion models.AssetVersion, version, orgName string, components []models.ComponentDependency) *cdx.BOM
	BuildVeX(asset models.Asset, assetVersion models.AssetVersion, version, orgName string, components []models.ComponentDependency, flaws []models.Flaw) *cdx.BOM
	GetAssetVersionsByAssetID(assetID uuid.UUID) ([]models.AssetVersion, error)
}

type flawRepository interface {
	Transaction(txFunc func(core.DB) error) error
	ListByScanner(assetVersionName string, assetID uuid.UUID, scannerID string) ([]models.Flaw, error)

	SaveBatch(db core.DB, flaws []models.Flaw) error

	GetFlawsByPurl(tx core.DB, purl []string) ([]models.Flaw, error)
}

type componentRepository interface {
	SaveBatch(tx core.DB, components []models.Component) error
	LoadComponents(tx database.DB, assetVersionName string, assetID uuid.UUID, scannerID, version string) ([]models.ComponentDependency, error)
	FindByPurl(tx core.DB, purl string) (models.Component, error)
	HandleStateDiff(tx database.DB, assetVersionName string, assetID uuid.UUID, version string, oldState []models.ComponentDependency, newState []models.ComponentDependency) error
}

type supplyChainRepository interface {
	PercentageOfVerifiedSupplyChains(assetVersionName string, assetID uuid.UUID) (float64, error)
}

type flawService interface {
	UserFixedFlaws(tx core.DB, userID string, flaws []models.Flaw, assetVersion models.AssetVersion, asset models.Asset, doRiskManagement bool) error
	UserDetectedFlaws(tx core.DB, userID string, flaws []models.Flaw, assetVersion models.AssetVersion, asset models.Asset, doRiskManagement bool) error
	UpdateFlawState(tx core.DB, assetID uuid.UUID, userID string, flaw *models.Flaw, statusType string, justification string, assetVersionName string) (models.FlawEvent, error)
}

type assetVersionController struct {
	assetVersionRepository       assetVersionRepository
	assetVersionService          assetVersionService
	flawRepository               flawRepository
	componentRepository          componentRepository
	flawService                  flawService
	supplyChainRepository        supplyChainRepository
	assetVersionComponentsLoader assetVersionComponentsLoader
}

func NewAssetVersionController(
	assetVersionRepository assetVersionRepository,
	assetVersionService assetVersionService,
	flawRepository flawRepository,
	componentRepository componentRepository,
	flawService flawService,
	supplyChainRepository supplyChainRepository,
	assetVersionComponentsLoader assetVersionComponentsLoader,
) *assetVersionController {
	return &assetVersionController{
		assetVersionRepository:       assetVersionRepository,
		assetVersionService:          assetVersionService,
		flawRepository:               flawRepository,
		componentRepository:          componentRepository,
		flawService:                  flawService,
		supplyChainRepository:        supplyChainRepository,
		assetVersionComponentsLoader: assetVersionComponentsLoader,
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
	versions, err := a.assetVersionComponentsLoader.GetVersions(nil, assetVersion)
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
	// get the version query param
	version := c.QueryParam("version")
	if version == "" {
		version = models.NoVersion
	} else {
		var err error
		version, err = normalize.SemverFix(version)
		if err != nil {
			return err
		}
	}

	scanner := c.QueryParam("scanner")
	if scanner == "" {
		return echo.NewHTTPError(400, "scanner query param is required")
	}

	assetVersion := core.GetAssetVersion(c)
	_, flaws, err := a.getComponentsAndFlaws(assetVersion, scanner, version)
	if err != nil {
		return err
	}

	return c.JSON(200, utils.Map(flaws, func(m models.Flaw) flaw.FlawDTO {
		return flaw.FlawToDto(m)
	}))
}

func (a *assetVersionController) getComponentsAndFlaws(assetVersion models.AssetVersion, scanner, version string) ([]models.ComponentDependency, []models.Flaw, error) {
	components, err := a.assetVersionComponentsLoader.LoadComponents(nil, assetVersion.Name, assetVersion.AssetID, scanner, version)
	if err != nil {
		return nil, nil, err
	}

	purls := utils.Map(components, func(c models.ComponentDependency) string {
		return c.DependencyPurl
	})

	flaws, err := a.flawRepository.GetFlawsByPurl(nil, purls)
	if err != nil {
		return nil, nil, err
	}
	return components, flaws, nil
}

func (a *assetVersionController) DependencyGraph(c core.Context) error {
	app := core.GetAssetVersion(c)
	// check for version query param
	version := c.QueryParam("version")
	if version == "" {
		version = models.NoVersion
	} else {
		var err error
		version, err = normalize.SemverFix(version)
		if err != nil {
			return err
		}
	}

	scanner := c.QueryParam("scanner")
	if scanner == "" {
		return echo.NewHTTPError(400, "scanner query param is required")
	}

	components, err := a.assetVersionComponentsLoader.LoadComponents(nil, app.Name, app.AssetID, scanner, version)
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
	org := core.GetTenant(c)
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

	components, err := a.assetVersionComponentsLoader.LoadComponents(nil, assetVersion.Name, assetVersion.AssetID, scanner, version)
	if err != nil {
		return nil, err
	}
	return a.assetVersionService.BuildSBOM(assetVersion, version, org.Name, components), nil
}

func (a *assetVersionController) buildVeX(c core.Context) (*cdx.BOM, error) {
	asset := core.GetAsset(c)
	assetVersion := core.GetAssetVersion(c)
	org := core.GetTenant(c)
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

	// get all associated flaws
	components, flaws, err := a.getComponentsAndFlaws(assetVersion, scanner, version)
	if err != nil {
		return nil, err
	}

	return a.assetVersionService.BuildVeX(asset, assetVersion, version, org.Name, components, flaws), nil
}

func (a *assetVersionController) Metrics(c core.Context) error {
	assetVersion := core.GetAssetVersion(c)
	scannerIds := []string{}
	// get the latest events of this asset per scan type
	err := a.assetVersionRepository.GetDB(nil).Table("flaws").Select("DISTINCT scanner_id").Where("asset_version_name  = ? AND asset_id = ?", assetVersion.Name, assetVersion.AssetID).Pluck("scanner_id", &scannerIds).Error

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
