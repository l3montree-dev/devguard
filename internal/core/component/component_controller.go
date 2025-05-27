package component

import (
	"github.com/l3montree-dev/devguard/internal/core"
)

type httpController struct {
	componentRepository    core.ComponentRepository
	assetVersionRepository core.AssetVersionRepository
}

func NewHTTPController(componentRepository core.ComponentRepository, assetVersionRepository core.AssetVersionRepository) *httpController {
	return &httpController{
		componentRepository:    componentRepository,
		assetVersionRepository: assetVersionRepository,
	}
}

type licenseResponse struct {
	License license `json:"license"`
	Count   int     `json:"count"`
}

func (httpController httpController) LicenseDistribution(c core.Context) error {
	asset := core.GetAsset(c)
	assetVersion, err := core.MaybeGetAssetVersion(c)
	if err != nil {
		// we need to get the default asset version
		assetVersion, err = httpController.assetVersionRepository.GetDefaultAssetVersion(asset.ID)
		if err != nil {
			return c.JSON(404, nil)
		}
	}

	scannerId := c.QueryParam("scannerId")

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

	return c.JSON(200, res)
}

func (httpController httpController) ListPaged(c core.Context) error {
	assetVersion := core.GetAssetVersion(c)
	scannerId := c.QueryParam("scannerId")

	pageInfo := core.GetPageInfo(c)
	filter := core.GetFilterQuery(c)
	search := c.QueryParam("search")
	sort := core.GetSortQuery(c)

	components, err := httpController.componentRepository.LoadComponentsWithProject(nil,
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

	return c.JSON(200, core.NewPaged(pageInfo, components.Total, componentsDTO))
}
