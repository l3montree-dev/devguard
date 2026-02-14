package controllers

import (
	"net/url"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/licenses"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/labstack/echo/v4"
)

type ComponentController struct {
	componentRepository    shared.ComponentRepository
	assetVersionRepository shared.AssetVersionRepository
	licenseRiskRepository  shared.LicenseRiskRepository
	projectRepository      shared.ProjectRepository
	assetVersionService    shared.AssetVersionService
}

func NewComponentController(componentRepository shared.ComponentRepository, assetVersionRepository shared.AssetVersionRepository, licenseOverwriteRepository shared.LicenseRiskRepository, projectRepository shared.ProjectRepository, assetVersionService shared.AssetVersionService) *ComponentController {
	return &ComponentController{
		componentRepository:    componentRepository,
		assetVersionRepository: assetVersionRepository,
		licenseRiskRepository:  licenseOverwriteRepository,
		projectRepository:      projectRepository,
		assetVersionService:    assetVersionService,
	}
}

type licenseResponse struct {
	License licenses.License `json:"license"`
	Count   int              `json:"count"`
}

func (componentController ComponentController) LicenseDistribution(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)
	assetVersion, err := shared.MaybeGetAssetVersion(ctx)

	// check if there is an artifact name as query param
	artifactName := ctx.QueryParam("artifact")

	if err != nil {
		// we need to get the default asset version
		assetVersion, err = componentController.assetVersionRepository.GetDefaultAssetVersion(asset.ID)
		if err != nil {
			return ctx.JSON(404, nil)
		}
	}

	// Load the full SBOM
	sbom, err := componentController.assetVersionService.LoadFullSBOMGraph(assetVersion)
	if err != nil {
		return echo.NewHTTPError(500, "could not load sbom").WithInternal(err)
	}

	// If artifact name is specified, extract just that artifact's subtree
	if artifactName != "" {
		err := sbom.ScopeToArtifact(artifactName)
		if err != nil {
			return ctx.JSON(200, []licenseResponse{})
		}
	}

	// Get license distribution from the SBOM
	fetchedLicenses := sbom.LicenseDistribution()

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

	// sort the array by count descending
	slices.SortFunc(res, func(a, b licenseResponse) int {
		return b.Count - a.Count
	})

	return ctx.JSON(200, res)
}

func (componentController ComponentController) ListPaged(ctx shared.Context) error {
	assetVersion := shared.GetAssetVersion(ctx)

	filter := shared.GetFilterQuery(ctx)

	pageInfo := shared.GetPageInfo(ctx)

	search := ctx.QueryParam("search")
	sort := shared.GetSortQuery(ctx)

	artifactName := ctx.QueryParam("artifactName")
	// unescape artifact name
	artifactName, _ = url.PathUnescape(artifactName)

	overwrittenLicense, err := componentController.licenseRiskRepository.GetAllOverwrittenLicensesForAssetVersion(assetVersion.AssetID, assetVersion.Name)
	if err != nil {
		return err
	}

	// make sure to only load valid purls
	filter = append(filter, shared.FilterQuery{
		Field:      "component_dependencies.dependency_id",
		FieldValue: "pkg:%",
		Operator:   "like",
	})

	// If artifact is specified, we need to filter using the SBOM graph
	if artifactName != "" {
		// Load the full SBOM to determine which components belong to this artifact
		sbom, err := componentController.assetVersionService.LoadFullSBOMGraph(assetVersion)
		if err != nil {
			return echo.NewHTTPError(500, "could not load sbom").WithInternal(err)
		}

		err = sbom.ScopeToArtifact(artifactName)
		if err != nil {
			return ctx.JSON(200, shared.NewPaged(pageInfo, 0, []dtos.ComponentDependencyDTO{}))
		}

		origin := ctx.QueryParam("origin")
		if origin != "" {
			origin, _ = url.PathUnescape(origin)
			err = sbom.ScopeToInfoSource(origin, normalize.InfoSourceSBOM)
			if err != nil {
				return echo.NewHTTPError(500, "could not scope sbom to origin").WithInternal(err)
			}
		}

		// Get all component IDs in this artifact
		componentIDs := make([]string, 0)
		for node := range sbom.Components() {
			if node.Component != nil && node.Component.PackageURL != "" {
				componentIDs = append(componentIDs, node.Component.PackageURL)
			}
		}

		if len(componentIDs) == 0 {
			return ctx.JSON(200, shared.NewPaged(pageInfo, 0, []dtos.ComponentDependencyDTO{}))
		}

		// Add filter for these component IDs
		filter = append(filter, shared.FilterQuery{
			Field:      "component_dependencies.dependency_id",
			FieldValue: componentIDs,
			Operator:   "in",
		})
	}

	components, err := componentController.componentRepository.LoadComponentsWithProject(nil,
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

func (componentController ComponentController) SearchComponentOccurrences(ctx shared.Context) error {
	project := shared.GetProject(ctx)

	// get all child projects as well
	projects, err := componentController.projectRepository.RecursivelyGetChildProjects(project.ID)
	if err != nil {
		return echo.NewHTTPError(500, "could not fetch child projects").WithInternal(err)
	}

	projectIDs := []uuid.UUID{
		project.ID,
	}
	for _, p := range projects {
		projectIDs = append(projectIDs, p.ID)
	}

	pagedResp, err := componentController.componentRepository.SearchComponentOccurrencesByProject(
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
