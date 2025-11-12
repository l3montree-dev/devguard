package controllers

import (
	"slices"
	"strings"

	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/l3montree-dev/devguard/shared"
)

type componentController struct {
	componentRepository    shared.ComponentRepository
	assetVersionRepository shared.AssetVersionRepository
	licenseRiskRepository  shared.LicenseRiskRepository
}

func NewComponentController(componentRepository shared.ComponentRepository, assetVersionRepository shared.AssetVersionRepository, licenseOverwriteRepository shared.LicenseRiskRepository) *componentController {
	return &componentController{
		componentRepository:    componentRepository,
		assetVersionRepository: assetVersionRepository,
		licenseRiskRepository:  licenseOverwriteRepository,
	}
}

type licenseResponse struct {
	License license `json:"license"`
	Count   int     `json:"count"`
}

func (componentController componentController) LicenseDistribution(ctx shared.Context) error {
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

	licenses, err := componentController.componentRepository.GetLicenseDistribution(nil,
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

func (componentController componentController) ListPaged(ctx shared.Context) error {
	assetVersion := shared.GetAssetVersion(ctx)

	filter := shared.GetFilterQuery(ctx)

	pageInfo := shared.GetPageInfo(ctx)

	search := ctx.QueryParam("search")
	sort := shared.GetSortQuery(ctx)

	overwrittenLicense, err := componentController.licenseRiskRepository.GetAllOverwrittenLicensesForAssetVersion(assetVersion.AssetID, assetVersion.Name)
	if err != nil {
		return err
	}

	// make sure to only load valid purls
	filter = append(filter, shared.FilterQuery{
		Field:      "purl",
		FieldValue: "pkg:%",
		Operator:   "like",
	})

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

	var componentsDTO = make([]componentDTO, 0, len(components.Data))

	for _, component := range components.Data {
		componentsDTO = append(componentsDTO, toDTO(component))
	}

	return ctx.JSON(200, shared.NewPaged(pageInfo, components.Total, componentsDTO))
}
