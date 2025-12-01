package controllers

import (
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/licenses"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
)

type ComponentController struct {
	componentRepository    shared.ComponentRepository
	assetVersionRepository shared.AssetVersionRepository
	licenseRiskRepository  shared.LicenseRiskRepository
	projectRepository      shared.ProjectRepository
}

func NewComponentController(componentRepository shared.ComponentRepository, assetVersionRepository shared.AssetVersionRepository, licenseOverwriteRepository shared.LicenseRiskRepository, projectRepository shared.ProjectRepository) *ComponentController {
	return &ComponentController{
		componentRepository:    componentRepository,
		assetVersionRepository: assetVersionRepository,
		licenseRiskRepository:  licenseOverwriteRepository,
		projectRepository:      projectRepository,
	}
}

type licenseResponse struct {
	License licenses.License `json:"license"`
	Count   int              `json:"count"`
}

func (ComponentController ComponentController) LicenseDistribution(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)
	assetVersion, err := shared.MaybeGetAssetVersion(ctx)

	// check if there is an artifact name as query param
	artifactName := ctx.QueryParam("artifact")

	if err != nil {
		// we need to get the default asset version
		assetVersion, err = ComponentController.assetVersionRepository.GetDefaultAssetVersion(asset.ID)
		if err != nil {
			return ctx.JSON(404, nil)
		}
	}

	fetchedLicenses, err := ComponentController.componentRepository.GetLicenseDistribution(nil,
		assetVersion.Name,
		assetVersion.AssetID,
		utils.EmptyThenNil(artifactName),
	)

	var res = make([]licenseResponse, 0, len(fetchedLicenses))
	for id, count := range fetchedLicenses {
		// get the license from the license repository
		l, ok := licenses.LicenseMap[strings.ToLower(id)]
		if !ok {
			l = licenses.License{
				LicenseID: id,
				Name:      id,
			}
		}
		res = append(res, licenseResponse{
			License: l,
			Count:   count,
		})
	}

	if err != nil {
		return err
	}
	// sort the array by count descending
	slices.SortFunc(res, func(a, b licenseResponse) int {
		return b.Count - a.Count
	})

	return ctx.JSON(200, res)
}

func (ComponentController ComponentController) ListPaged(ctx shared.Context) error {
	assetVersion := shared.GetAssetVersion(ctx)

	filter := shared.GetFilterQuery(ctx)

	pageInfo := shared.GetPageInfo(ctx)

	search := ctx.QueryParam("search")
	sort := shared.GetSortQuery(ctx)

	overwrittenLicense, err := ComponentController.licenseRiskRepository.GetAllOverwrittenLicensesForAssetVersion(assetVersion.AssetID, assetVersion.Name)
	if err != nil {
		return err
	}

	// make sure to only load valid purls
	filter = append(filter, shared.FilterQuery{
		Field:      "purl",
		FieldValue: "pkg:%",
		Operator:   "like",
	})

	components, err := ComponentController.componentRepository.LoadComponentsWithProject(nil,
		overwrittenLicense,
		assetVersion.Name,
		assetVersion.AssetID,
		pageInfo,
		search,
		filter,
		sort,
	)

	if err != nil {
		return err
	}

	var componentsDTO = make([]dtos.ComponentDependencyDTO, 0, len(components.Data))

	for _, component := range components.Data {
		componentsDTO = append(componentsDTO, transformer.ComponentDependencyToDTO(component))
	}

	return ctx.JSON(200, shared.NewPaged(pageInfo, components.Total, componentsDTO))
}

func (ComponentController ComponentController) SearchComponentOccurrences(ctx shared.Context) error {
	project := shared.GetProject(ctx)

	// get all child projects as well
	projects, err := ComponentController.projectRepository.RecursivelyGetChildProjects(project.ID)
	if err != nil {
		return echo.NewHTTPError(500, "could not fetch child projects").WithInternal(err)
	}

	projectIDs := []uuid.UUID{
		project.ID,
	}
	for _, p := range projects {
		projectIDs = append(projectIDs, p.ID)
	}

	pagedResp, err := ComponentController.componentRepository.SearchComponentOccurrencesByProject(
		nil,
		projectIDs,
		shared.GetPageInfo(ctx),
		ctx.QueryParam("search"),
	)
	if err != nil {
		return echo.NewHTTPError(500, "could not search components").WithInternal(err)
	}

	return ctx.JSON(200, pagedResp.Map(func(occurrence models.ComponentOccurrence) any {
		return transformer.ComponentOccurrenceToDTO(occurrence)
	}))
}
