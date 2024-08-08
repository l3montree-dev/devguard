package asset

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/flaw"

	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"

	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/package-url/packageurl-go"

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

type vulnService interface {
	GetVulnsForAll(purls []string) ([]models.VulnInPackage, error)
}

type assetComponentsLoader interface {
	GetVersions(tx core.DB, asset models.Asset) ([]string, error)
	LoadAssetComponents(tx core.DB, asset models.Asset, scanType, version string) ([]models.ComponentDependency, error)
}

type assetService interface {
	UpdateAssetRequirements(asset models.Asset, responsible string, justification string) error
}

type httpController struct {
	assetRepository       repository
	assetComponentsLoader assetComponentsLoader
	vulnService           vulnService
	flawRepository        flawRepository
	assetService          assetService
}

func NewHttpController(repository repository, assetComponentsLoader assetComponentsLoader, vulnService vulnService, flawRepository flawRepository, assetService assetService) *httpController {
	return &httpController{
		assetRepository:       repository,
		assetComponentsLoader: assetComponentsLoader,
		vulnService:           vulnService,
		flawRepository:        flawRepository,
		assetService:          assetService,
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

	return c.JSON(200, versions)
}

func (a *httpController) AffectedPackages(c core.Context) error {
	// get the version query param
	version := c.QueryParam("version")
	if version == "" {
		version = models.LatestVersion
	} else {
		var err error
		version, err = utils.SemverFix(version)
		if err != nil {
			return err
		}
	}

	scanType := c.QueryParam("scanType")
	if scanType == "" {
		return echo.NewHTTPError(400, "scanType query param is required")
	}

	components, err := a.assetComponentsLoader.LoadAssetComponents(nil, core.GetAsset(c), scanType, version)
	if err != nil {
		return err
	}

	purls := utils.Map(components, func(c models.ComponentDependency) string {
		return c.DependencyPurlOrCpe
	})

	flaws, err := a.flawRepository.GetFlawsByPurlOrCpe(nil, purls)
	if err != nil {
		return err
	}

	return c.JSON(200, utils.Map(flaws, func(m models.Flaw) flaw.FlawDTO {
		return flaw.FlawToDto(m)
	}))
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
		version = models.LatestVersion
	} else {
		var err error
		version, err = utils.SemverFix(version)
		if err != nil {
			return err
		}
	}

	scanType := c.QueryParam("scanType")
	if scanType == "" {
		return echo.NewHTTPError(400, "scanType query param is required")
	}

	components, err := a.assetComponentsLoader.LoadAssetComponents(nil, app, scanType, version)
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

func (a *httpController) buildSBOM(c core.Context) (*cdx.BOM, error) {
	asset := core.GetAsset(c)
	org := core.GetTenant(c)
	// check for version query param
	version := c.QueryParam("version")
	if version == "" {
		version = models.LatestVersion
	} else {
		var err error
		version, err = utils.SemverFix(version)
		if err != nil {
			return nil, err
		}
	}

	scanType := c.QueryParam("scanType")
	if scanType == "" {
		return nil, echo.NewHTTPError(400, "scanType query param is required")
	}

	components, err := a.assetComponentsLoader.LoadAssetComponents(nil, asset, scanType, version)
	if err != nil {
		return nil, err
	}
	return buildSBOM(asset, version, org.Name, components), nil
}

func buildSBOM(asset models.Asset, version string, organizationName string, components []models.ComponentDependency) *cdx.BOM {
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

		scope := cdx.ScopeOptional
		var p packageurl.PackageURL
		var err error
		if c.ComponentPurlOrCpe == nil {
			scope = cdx.ScopeRequired
			p, err = packageurl.FromString(c.DependencyPurlOrCpe)
			if err != nil {
				continue
			}
		} else {
			p, err = packageurl.FromString(*c.ComponentPurlOrCpe)
			if err != nil {
				continue
			}
		}

		if _, ok := alreadyIncluded[c.DependencyPurlOrCpe]; !ok {
			alreadyIncluded[c.DependencyPurlOrCpe] = true
			bomComponents = append(bomComponents, cdx.Component{
				BOMRef:     c.DependencyPurlOrCpe,
				Type:       cdx.ComponentTypeLibrary,
				PackageURL: c.DependencyPurlOrCpe,
				Scope:      scope,
				Name:       fmt.Sprintf("%s/%s", p.Namespace, p.Name),
			})
		}

		if c.ComponentPurlOrCpe != nil {
			if _, ok := alreadyIncluded[*c.ComponentPurlOrCpe]; !ok {
				alreadyIncluded[*c.ComponentPurlOrCpe] = true
				bomComponents = append(bomComponents, cdx.Component{
					BOMRef:     *c.ComponentPurlOrCpe,
					Type:       cdx.ComponentTypeLibrary,
					PackageURL: *c.ComponentPurlOrCpe,
					Scope:      scope,
					Name:       fmt.Sprintf("%s/%s", p.Namespace, p.Name),
				})
			}
		}
	}

	// build up the dependency map
	dependencyMap := make(map[string][]string)
	for _, c := range components {
		if c.ComponentPurlOrCpe == nil {
			if _, ok := dependencyMap[asset.Slug]; !ok {
				dependencyMap[asset.Slug] = []string{c.DependencyPurlOrCpe}
				continue
			}
			dependencyMap[asset.Slug] = append(dependencyMap[asset.Slug], c.DependencyPurlOrCpe)
			continue
		}
		if _, ok := dependencyMap[*c.ComponentPurlOrCpe]; !ok {
			dependencyMap[*c.ComponentPurlOrCpe] = make([]string, 0)
		}
		dependencyMap[*c.ComponentPurlOrCpe] = append(dependencyMap[*c.ComponentPurlOrCpe], c.DependencyPurlOrCpe)
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
