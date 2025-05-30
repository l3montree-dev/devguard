package asset_lookup

import (
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/labstack/echo/v4"
)

type httpController struct {
	assetRepository   core.AssetRepository
	projectRepository core.ProjectRepository
	orgRepository     core.OrganizationRepository
}

func NewHttpController(assetRepository core.AssetRepository, projectRepository core.ProjectRepository, orgRepository core.OrganizationRepository) *httpController {
	return &httpController{
		assetRepository:   assetRepository,
		projectRepository: projectRepository,
		orgRepository:     orgRepository,
	}
}

func (a *httpController) HandleLookup(ctx core.Context) error {
	integration := ctx.QueryParam("integration")
	if integration == "" {
		return echo.NewHTTPError(400, "missing integration")
	}

	provider := ctx.QueryParam("provider")
	if provider == "" {
		return echo.NewHTTPError(400, "missing provider")
	}
	providerUrl := "xyz" // todo...
	if provider == "opencode" {
		providerUrl = "https://gitlab.opencode.de"
	}

	repositoryId := ctx.QueryParam("repositoryId")
	if repositoryId == "" {
		return echo.NewHTTPError(400, "missing repositoryId")
	}

	if integration == "gitlab" {
		asset, err := a.assetRepository.FindAssetByGitLabIntegrationAndId(repositoryId, providerUrl)
		if err != nil {
			return echo.NewHTTPError(500, "error while loading repos").WithInternal(err)
		}

		project, err := a.projectRepository.Read(asset.ProjectID)
		if err != nil {
			return echo.NewHTTPError(500, "error while fetching project details").WithInternal(err)
		}

		organization, err := a.orgRepository.Read(project.OrganizationID)
		if err != nil {
			return echo.NewHTTPError(500, "error while fetching organization details").WithInternal(err)
		}

		response := struct {
			Org     string `json:"org"`
			Project string `json:"project"`
			Asset   string `json:"asset"`
		}{
			Org:     organization.Slug,
			Project: project.Slug,
			Asset:   asset.Slug,
		}

		return ctx.JSON(200, response)
	}
	return echo.NewHTTPError(400, "error unsupported integration")
}
