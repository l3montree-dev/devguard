package component

import (
	"strings"

	"github.com/l3montree-dev/devguard/internal/core"
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
	if err != nil {
		// we need to get the default asset version
		assetVersion, err = httpController.assetVersionRepository.GetDefaultAssetVersion(asset.ID)
		if err != nil {
			return ctx.JSON(404, nil)
		}
	}

	artifactName, err := core.GetUrlDecodedParam(ctx, "artifact")
	if err != nil {
		return err
	}

	licenses, err := httpController.componentRepository.GetLicenseDistribution(nil,
		assetVersion.Name,
		assetVersion.AssetID,
		artifactName,
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
