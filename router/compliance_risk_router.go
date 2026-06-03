package router

import (
	"github.com/l3montree-dev/devguard/controllers"
	"github.com/l3montree-dev/devguard/middlewares"
	"github.com/labstack/echo/v4"
)

type ComplianceRiskRouter struct {
	*echo.Group
}

func NewComplianceRiskRouter(
	assetVersionGroup AssetVersionRouter,
	controller *controllers.ComplianceRiskController,
) ComplianceRiskRouter {
	g := assetVersionGroup.Group.Group("/compliance-risks")
	g.GET("/", controller.ListPaged)
	g.GET("/:complianceRiskID/", controller.Read)
	g.POST("/:complianceRiskID/", controller.CreateEvent, middlewares.NeededScope([]string{"manage"}), middlewares.DisallowPublicRequests)
	g.POST("/:complianceRiskID/mitigate/", controller.Mitigate, middlewares.NeededScope([]string{"manage"}), middlewares.DisallowPublicRequests)

	return ComplianceRiskRouter{Group: g}
}
