package component

import (
	"slices"
	"strings"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/labstack/echo/v4"
)

type httpController struct {
	componentRepository    core.ComponentRepository
	assetVersionRepository core.AssetVersionRepository
	licenseRiskRepository  core.LicenseRiskRepository
}

func NewHTTPController(componentRepository core.ComponentRepository, assetVersionRepository core.AssetVersionRepository, licenseOverwriteRepository core.LicenseRiskRepository) *httpController {
	return &httpController{
		componentRepository:    componentRepository,
		assetVersionRepository: assetVersionRepository,
		licenseRiskRepository:  licenseOverwriteRepository,
	}
}

type licenseResponse struct {
	License license `json:"license"`
	Count   int     `json:"count"`
}

func (httpController httpController) LicenseDistribution(ctx core.Context) error {
	asset := core.GetAsset(ctx)
	assetVersion, err := core.MaybeGetAssetVersion(ctx)

	// check if there is an artifact name as query param
	artifactName := ctx.QueryParam("artifact")

	if err != nil {
		// we need to get the default asset version
		assetVersion, err = httpController.assetVersionRepository.GetDefaultAssetVersion(asset.ID)
		if err != nil {
			return ctx.JSON(404, nil)
		}
	}

	licenses, err := httpController.componentRepository.GetLicenseDistribution(nil,
		assetVersion.Name,
		assetVersion.AssetID,
		utils.EmptyThenNil(artifactName),
	)

	var res = make([]licenseResponse, 0, len(licenses))
	for id, count := range licenses {
		// get the license from the license repository
		l, ok := LicenseMap[strings.ToLower(id)]
		if !ok {
			l = license{
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

func (httpController httpController) ListPaged(ctx core.Context) error {
	assetVersion := core.GetAssetVersion(ctx)

	filter := core.GetFilterQuery(ctx)

	pageInfo := core.GetPageInfo(ctx)

	search := ctx.QueryParam("search")
	sort := core.GetSortQuery(ctx)

	overwrittenLicense, err := httpController.licenseRiskRepository.GetAllOverwrittenLicensesForAssetVersion(assetVersion.AssetID, assetVersion.Name)
	if err != nil {
		return err
	}

	// make sure to only load valid purls
	filter = append(filter, core.FilterQuery{
		Field:      "purl",
		FieldValue: "pkg:",
		Operator:   "like",
	})

	components, err := httpController.componentRepository.LoadComponentsWithProject(nil,
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

	var componentsDTO = make([]componentDTO, 0, len(components.Data))

	for _, component := range components.Data {
		componentsDTO = append(componentsDTO, toDTO(component))
	}

	return ctx.JSON(200, core.NewPaged(pageInfo, components.Total, componentsDTO))
}

func (controller httpController) SearchComponentOccurrences(ctx core.Context) error {
	org := core.GetOrg(ctx)

	pagedResp, err := controller.componentRepository.SearchComponentOccurrencesByOrg(
		nil,
		org.GetID(),
		core.GetPageInfo(ctx),
		ctx.QueryParam("search"),
	)
	if err != nil {
		return echo.NewHTTPError(500, "could not search components").WithInternal(err)
	}

	return ctx.JSON(200, pagedResp.Map(func(occurrence models.ComponentOccurrence) any {
		return componentOccurrenceToDTO(occurrence)
	}))
}

type componentOccurrenceDTO struct {
	ComponentDependencyID string  `json:"componentDependencyId"`
	DependencyPurl        *string `json:"dependencyPurl"`
	OrganizationID        string  `json:"organizationId"`
	OrganizationName      string  `json:"organizationName"`
	ProjectID             string  `json:"projectId"`
	ProjectName           string  `json:"projectName"`
	ProjectSlug           string  `json:"projectSlug"`
	AssetID               string  `json:"assetId"`
	AssetName             string  `json:"assetName"`
	AssetSlug             string  `json:"assetSlug"`
	AssetVersionName      string  `json:"assetVersionName"`
	ComponentPurl         *string `json:"componentPurl"`
	ComponentVersion      *string `json:"componentVersion"`
	ArtifactName          *string `json:"artifactName"`
	ArtifactAssetVersion  *string `json:"artifactAssetVersion"`
}

func componentOccurrenceToDTO(m models.ComponentOccurrence) componentOccurrenceDTO {
	return componentOccurrenceDTO{
		ComponentDependencyID: m.ComponentDependencyID.String(),
		DependencyPurl:        m.DependencyPurl,
		OrganizationID:        m.OrganizationID.String(),
		OrganizationName:      m.OrganizationName,
		ProjectID:             m.ProjectID.String(),
		ProjectName:           m.ProjectName,
		ProjectSlug:           m.ProjectSlug,
		AssetID:               m.AssetID.String(),
		AssetName:             m.AssetName,
		AssetSlug:             m.AssetSlug,
		AssetVersionName:      m.AssetVersionName,
		ComponentPurl:         m.ComponentPurl,
		ComponentVersion:      m.ComponentVersion,
		ArtifactName:          m.ArtifactName,
		ArtifactAssetVersion:  m.ArtifactAssetVersion,
	}
}
