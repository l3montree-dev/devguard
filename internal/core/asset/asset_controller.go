package asset

import (
	"encoding/json"
	"fmt"
	"slices"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/flaw"

	"github.com/l3montree-dev/devguard/internal/core/normalize"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"

	"github.com/l3montree-dev/devguard/internal/utils"

	"github.com/labstack/echo/v4"
)

// we use this in multiple files in the asset package itself
type repository interface {
	repositories.Repository[uuid.UUID, models.Asset, core.DB]
	FindByName(name string) (models.Asset, error)
	FindOrCreate(tx core.DB, name string) (models.Asset, error)
	GetByProjectID(projectID uuid.UUID) ([]models.Asset, error)
	ReadBySlug(projectID uuid.UUID, slug string) (models.Asset, error)
	GetAssetIDBySlug(projectID uuid.UUID, slug string) (uuid.UUID, error)
	Update(tx core.DB, asset *models.Asset) error
}

type assetComponentsLoader interface {
	GetVersions(tx core.DB, asset models.Asset) ([]string, error)
	LoadComponents(tx core.DB, asset models.Asset, scanType, version string) ([]models.ComponentDependency, error)
}

type assetService interface {
	UpdateAssetRequirements(asset models.Asset, responsible string, justification string) error
	BuildSBOM(asset models.Asset, version, orgName string, components []models.ComponentDependency) *cdx.BOM
	BuildVeX(asset models.Asset, version, orgName string, components []models.ComponentDependency, flaws []models.Flaw) *cdx.BOM
}

type httpController struct {
	assetRepository       repository
	assetComponentsLoader assetComponentsLoader

	flawRepository flawRepository
	assetService   assetService
}

func NewHttpController(repository repository, assetComponentsLoader assetComponentsLoader, flawRepository flawRepository, assetService assetService) *httpController {
	return &httpController{
		assetRepository:       repository,
		assetComponentsLoader: assetComponentsLoader,

		flawRepository: flawRepository,
		assetService:   assetService,
	}
}

func (a *httpController) List(c core.Context) error {

	project := core.GetProject(c)

	apps, err := a.assetRepository.GetByProjectID(project.GetID())
	if err != nil {
		return err
	}

	return c.JSON(200, apps)
}

func (a *httpController) Versions(c core.Context) error {
	asset := core.GetAsset(c)
	versions, err := a.assetComponentsLoader.GetVersions(nil, asset)
	if err != nil {
		return err
	}

	// order the version in descending order
	normalize.SemverSort(versions)

	// now only reverse it
	slices.Reverse(versions)

	return c.JSON(200, versions)
}

func (a *httpController) AffectedComponents(c core.Context) error {
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

	scanType := c.QueryParam("scanType")
	if scanType == "" {
		return echo.NewHTTPError(400, "scanType query param is required")
	}

	asset := core.GetAsset(c)
	_, flaws, err := a.getComponentsAndFlaws(asset, scanType, version)
	if err != nil {
		return err
	}

	return c.JSON(200, utils.Map(flaws, func(m models.Flaw) flaw.FlawDTO {
		return flaw.FlawToDto(m)
	}))
}

func (a *httpController) getComponentsAndFlaws(asset models.Asset, scanType, version string) ([]models.ComponentDependency, []models.Flaw, error) {
	components, err := a.assetComponentsLoader.LoadComponents(nil, asset, scanType, version)
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

func (a *httpController) Metrics(c core.Context) error {
	asset := core.GetAsset(c)
	scannerIds := []string{}
	// get the latest events of this asset per scan type
	err := a.assetRepository.GetDB(nil).Table("flaws").Select("DISTINCT scanner_id").Where("asset_id  = ?", asset.ID).Pluck("scanner_id", &scannerIds).Error

	if err != nil {
		return err
	}

	return c.JSON(200, assetMetrics{
		EnabledScanners: scannerIds,
	})
}

func (a *httpController) Create(c core.Context) error {
	var req createRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "unable to process request").WithInternal(err)
	}

	if err := core.V.Struct(req); err != nil {
		return echo.NewHTTPError(400, err.Error())
	}

	project := core.GetProject(c)

	app := req.toModel(project.GetID())

	err := a.assetRepository.Create(nil, &app)

	if err != nil {
		return echo.NewHTTPError(500, "could not create asset").WithInternal(err)
	}

	return c.JSON(200, app)
}

func (a *httpController) Read(c core.Context) error {
	app := core.GetAsset(c)
	return c.JSON(200, app)
}

func (a *httpController) DependencyGraph(c core.Context) error {
	app := core.GetAsset(c)
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

	scanType := c.QueryParam("scanType")
	if scanType == "" {
		return echo.NewHTTPError(400, "scanType query param is required")
	}

	components, err := a.assetComponentsLoader.LoadComponents(nil, app, scanType, version)
	if err != nil {
		return err
	}

	tree := BuildDependencyTree(components)
	if tree.Root.Children == nil {
		tree.Root.Children = make([]*treeNode, 0)
	}

	return c.JSON(200, tree)
}

func (a *httpController) SBOMJSON(c core.Context) error {
	sbom, err := a.buildSBOM(c)
	if err != nil {
		return err
	}
	return cdx.NewBOMEncoder(c.Response().Writer, cdx.BOMFileFormatJSON).Encode(sbom)
}

func (a *httpController) SBOMXML(c core.Context) error {
	sbom, err := a.buildSBOM(c)
	if err != nil {
		return err
	}

	return cdx.NewBOMEncoder(c.Response().Writer, cdx.BOMFileFormatXML).Encode(sbom)
}

func (a *httpController) VEXXML(c core.Context) error {
	sbom, err := a.buildVeX(c)
	if err != nil {
		return err
	}

	return cdx.NewBOMEncoder(c.Response().Writer, cdx.BOMFileFormatXML).Encode(sbom)
}

func (a *httpController) VEXJSON(c core.Context) error {
	sbom, err := a.buildVeX(c)
	if err != nil {
		return err
	}

	return cdx.NewBOMEncoder(c.Response().Writer, cdx.BOMFileFormatJSON).Encode(sbom)
}

func (a *httpController) buildSBOM(c core.Context) (*cdx.BOM, error) {
	asset := core.GetAsset(c)
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

	scanType := c.QueryParam("scanType")
	if scanType == "" {
		return nil, echo.NewHTTPError(400, "scanType query param is required")
	}

	components, err := a.assetComponentsLoader.LoadComponents(nil, asset, scanType, version)
	if err != nil {
		return nil, err
	}
	return a.assetService.BuildSBOM(asset, version, org.Name, components), nil
}

func (a *httpController) buildVeX(c core.Context) (*cdx.BOM, error) {
	asset := core.GetAsset(c)
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

	scanType := c.QueryParam("scanType")
	if scanType == "" {
		return nil, echo.NewHTTPError(400, "scanType query param is required")
	}

	// get all associated flaws
	components, flaws, err := a.getComponentsAndFlaws(asset, scanType, version)
	if err != nil {
		return nil, err
	}

	return a.assetService.BuildVeX(asset, version, org.Name, components, flaws), nil
}

func (c *httpController) Update(ctx core.Context) error {
	asset := core.GetAsset(ctx)

	req := ctx.Request().Body
	defer req.Close()

	var patchRequest patchRequest
	err := json.NewDecoder(req).Decode(&patchRequest)
	if err != nil {
		return fmt.Errorf("Error decoding request: %v", err)
	}

	var justification string = ""
	if patchRequest.ConfidentialityRequirement != nil && *patchRequest.ConfidentialityRequirement != asset.ConfidentialityRequirement {
		justification += "Confidentiality Requirement updated: " + string(asset.ConfidentialityRequirement) + " -> " + string(*patchRequest.ConfidentialityRequirement)
		asset.ConfidentialityRequirement = *patchRequest.ConfidentialityRequirement
	}

	if patchRequest.IntegrityRequirement != nil && *patchRequest.IntegrityRequirement != asset.IntegrityRequirement {
		justification += ", Integrity Requirement updated: " + string(asset.IntegrityRequirement) + " -> " + string(*patchRequest.IntegrityRequirement)
		asset.IntegrityRequirement = *patchRequest.IntegrityRequirement
	}

	if patchRequest.AvailabilityRequirement != nil && *patchRequest.AvailabilityRequirement != asset.AvailabilityRequirement {
		justification += ", Availability Requirement updated: " + string(asset.AvailabilityRequirement) + " -> " + string(*patchRequest.AvailabilityRequirement)
		asset.AvailabilityRequirement = *patchRequest.AvailabilityRequirement
	}

	if justification != "" {
		err = c.assetService.UpdateAssetRequirements(asset, core.GetSession(ctx).GetUserID(), justification)
		if err != nil {
			return fmt.Errorf("Error updating requirements: %v", err)
		}
	}
	updated := patchRequest.applyToModel(&asset)

	if updated {
		err = c.assetRepository.Update(nil, &asset)
		if err != nil {
			return fmt.Errorf("Error updating asset: %v", err)
		}
	}

	return ctx.JSON(200, asset)
}
