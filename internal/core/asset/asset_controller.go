package asset

import (
	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/core"
	"github.com/l3montree-dev/flawfix/internal/database/models"
	"github.com/l3montree-dev/flawfix/internal/database/repositories"
	"github.com/l3montree-dev/flawfix/internal/obj"
	"github.com/l3montree-dev/flawfix/internal/utils"

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
	GetTransitiveDependencies(assetID uuid.UUID) []obj.Dependency
	GetAllComponentsByAssetID(assetID uuid.UUID) []obj.ComponentDepth
}

type vulnService interface {
	GetVulnsForAll(purls []string) ([]models.VulnInPackage, error)
}

type httpController struct {
	assetRepository repository
	vulnService     vulnService
}

func NewHttpController(repository repository, vulnService vulnService) *httpController {
	return &httpController{
		assetRepository: repository,
		vulnService:     vulnService,
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

func (a *httpController) AffectedPackages(c core.Context) error {
	components := a.assetRepository.GetAllComponentsByAssetID(core.GetAsset(c).GetID())
	purls := utils.Map(components, func(c obj.ComponentDepth) string {
		return c.PurlOrCpe
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
	dependencies := a.assetRepository.GetTransitiveDependencies(app.GetID())

	tree := buildDependencyTree(dependencies)

	return c.JSON(200, tree)
}
