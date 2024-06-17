package asset

import (
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/core/risk"
	"github.com/l3montree-dev/flawfix/internal/database"
	"github.com/l3montree-dev/flawfix/internal/database/models"
	"github.com/l3montree-dev/flawfix/internal/database/repositories"
	"github.com/l3montree-dev/flawfix/internal/utils"
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
	LoadAssetComponents(tx core.DB, asset models.Asset, version string) ([]models.ComponentDependency, error)
}

type cveRepository interface {
	FindCVE(tx database.DB, cveId string) (any, error)
}

type assetService interface {
	UpdateEvents(asset models.Asset, responsibility string, justification string) error
}

type httpController struct {
	assetRepository       repository
	assetComponentsLoader assetComponentsLoader
	vulnService           vulnService
	flawRepository        flawRepository
	cveRepository         cveRepository
	assetService          assetService
}

func NewHttpController(repository repository, assetComponentsLoader assetComponentsLoader, vulnService vulnService, flawRepository flawRepository, cveRepository cveRepository, assetService assetService) *httpController {
	return &httpController{
		assetRepository:       repository,
		assetComponentsLoader: assetComponentsLoader,
		vulnService:           vulnService,
		flawRepository:        flawRepository,
		cveRepository:         cveRepository,
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

	components, err := a.assetComponentsLoader.LoadAssetComponents(nil, core.GetAsset(c), version)
	if err != nil {
		return err
	}

	purls := utils.Map(components, func(c models.ComponentDependency) string {
		if c.ComponentPurlOrCpe == nil {
			return c.DependencyPurlOrCpe
		}
		return *c.ComponentPurlOrCpe
	})

	vulns, err := a.vulnService.GetVulnsForAll(purls)
	if err != nil {
		return err
	}

	return c.JSON(200, vulns)
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

	components, err := a.assetComponentsLoader.LoadAssetComponents(nil, app, version)
	if err != nil {
		return err
	}

	tree, _ := buildDependencyTree(components)

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
	components, err := a.assetComponentsLoader.LoadAssetComponents(nil, asset, version)
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
				Publisher: "github.com/l3montree-dev/flawfix",
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

func (c *httpController) UpdateRrequirements(ctx core.Context) error {
	asset := core.GetAsset(ctx)

	req := ctx.Request().Body
	defer req.Close()

	var assetNew models.Asset
	err := json.NewDecoder(req).Decode(&assetNew)
	if err != nil {
		return err
	}

	if assetNew.ConfidentialityRequirement != asset.ConfidentialityRequirement || assetNew.IntegrityRequirement != asset.IntegrityRequirement || assetNew.AvailabilityRequirement != asset.AvailabilityRequirement {

		justification := "Requirements Level updated: " + "AvailabilityRequirement: " + asset.AvailabilityRequirement + " -> " + assetNew.AvailabilityRequirement + ", ConfidentialityRequirement: " + asset.ConfidentialityRequirement + " -> " + assetNew.ConfidentialityRequirement + ", IntegrityRequirement: " + asset.IntegrityRequirement + " -> " + assetNew.IntegrityRequirement
		justificationStr := string(justification)

		asset.ConfidentialityRequirement = assetNew.ConfidentialityRequirement
		asset.IntegrityRequirement = assetNew.IntegrityRequirement
		asset.AvailabilityRequirement = assetNew.AvailabilityRequirement

		//save the asset inside the database
		err = c.assetRepository.Update(nil, &asset)
		if err != nil {
			return err
		}

		env := core.Environmental{
			ConfidentialityRequirements: string(assetNew.ConfidentialityRequirement),
			IntegrityRequirements:       string(assetNew.IntegrityRequirement),
			AvailabilityRequirements:    string(assetNew.AvailabilityRequirement),
		}

		// get the flaws
		flaws, err := c.flawRepository.GetAllFlawsByAssetID(nil, asset.GetID())
		if err != nil {
			slog.Info("Error getting flaws: %v", err)
			return err
		}
		if flaws == nil {
			slog.Info("No flaws found")
			return nil
		}
		for i, flaw := range flaws {
			cviID := flaw.CVEID
			cve, err := c.cveRepository.FindCVE(nil, cviID)
			if err != nil {
				slog.Info("Error getting CVE: %v", err)
				continue
			}

			cve2 := cve.(models.CVE)
			flaws[i].RawRiskAssessment = risk.RowRisk(cve2, env)

			// Log the updated flaw
			log.Printf("Updated flaw with ID: %s -  Risk is: %f", flaw.ID, *flaws[i].RawRiskAssessment)

		}

		// save the flaws inside the database

		err = c.flawRepository.SaveBatch(nil, flaws)
		if err != nil {
			log.Printf("Error saving flaws: %v", err)
			return err
		}

		userID := core.GetSession(ctx).GetUserID()
		//update event for all flaws
		err = c.assetService.UpdateEvents(asset, userID, justificationStr)
		if err != nil {
			return err
		}

	}

	return nil
}
