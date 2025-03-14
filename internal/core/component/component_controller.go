package component

import (
	"github.com/l3montree-dev/devguard/internal/core"
)

type httpController struct {
	componentRepository core.ComponentRepository
}

func NewHTTPController(componentRepository core.ComponentRepository) *httpController {
	return &httpController{
		componentRepository: componentRepository,
	}
}

func (httpController httpController) ListPaged(c core.Context) error {
	assetVersion := core.GetAssetVersion(c)
	scannerId := c.QueryParam("scannerId")
	version := c.QueryParam("version")
	pageInfo := core.GetPageInfo(c)
	filter := core.GetFilterQuery(c)
	search := c.QueryParam("search")
	sort := core.GetSortQuery(c)

	components, err := httpController.componentRepository.LoadComponentsWithProject(nil,
		assetVersion.Name,
		assetVersion.AssetID,
		scannerId,
		version,
		pageInfo,
		search,
		filter,
		sort,
	)

	if err != nil {
		return err
	}

	var componentsDTO []componentDTO = make([]componentDTO, 0, len(components.Data))

	for _, component := range components.Data {
		componentsDTO = append(componentsDTO, toDTO(component))
	}

	return c.JSON(200, core.NewPaged(pageInfo, components.Total, componentsDTO))
}
