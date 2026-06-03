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
	complianceRisksRouter := assetVersionGroup.Group.Group("/compliance-risks")
	complianceRisksRouter.GET("/", controller.ListPaged)
	complianceRisksRouter.GET("/:complianceRiskID/", controller.Read)
	complianceRisksRouter.POST("/:complianceRiskID/", controller.CreateEvent, middlewares.NeededScope([]string{"manage"}), middlewares.DisallowPublicRequests)
	complianceRisksRouter.POST("/:complianceRiskID/mitigate/", controller.Mitigate, middlewares.NeededScope([]string{"manage"}), middlewares.DisallowPublicRequests)

	complianceRisksRouter.POST("/recalculate/", controller.RecalculateFromService, middlewares.NeededScope([]string{"manage"}), middlewares.DisallowPublicRequests)
	complianceRisksRouter.POST("/upload-zip/", controller.UploadZip, middlewares.NeededScope([]string{"manage"}), middlewares.DisallowPublicRequests)

	return ComplianceRiskRouter{Group: complianceRisksRouter}
}
