package component

import (
	"github.com/l3montree-dev/devguard/internal/core"
)

type httpController struct {
	componentRepository        core.ComponentRepository
	assetVersionRepository     core.AssetVersionRepository
	licenseOverwriteRepository core.LicenseOverwriteRepository
}

func NewHTTPController(componentRepository core.ComponentRepository, assetVersionRepository core.AssetVersionRepository, licenseOverwriteRepository core.LicenseOverwriteRepository) *httpController {
	return &httpController{
		componentRepository:        componentRepository,
		assetVersionRepository:     assetVersionRepository,
		licenseOverwriteRepository: licenseOverwriteRepository,
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

	scannerId := ctx.QueryParam("scannerId")

	licenses, err := httpController.componentRepository.GetLicenseDistribution(nil,
		assetVersion.Name,
		assetVersion.AssetID,
		scannerId,
	)

	var res = make([]licenseResponse, 0, len(licenses))
	for id, count := range licenses {
		// get the license from the license repository
		l, ok := licenseMap[id]
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
	scannerId := ctx.QueryParam("scannerId")

	pageInfo := core.GetPageInfo(ctx)
	filter := core.GetFilterQuery(ctx)
	search := ctx.QueryParam("search")
	sort := core.GetSortQuery(ctx)

	orgID := core.GetOrganization(ctx).ID

	overwrittenLicense, err := httpController.licenseOverwriteRepository.GetAllOverwritesForOrganization(orgID)
	if err != nil {
		return err
	}

	components, err := httpController.componentRepository.LoadComponentsWithProject(nil,
		overwrittenLicense,
		assetVersion.Name,
		assetVersion.AssetID,
		scannerId,
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
