package controllers

import (
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
)

type LogController struct {
	logService shared.LogService
}

func NewLogController(logService shared.LogService) *LogController {
	return &LogController{logService: logService}
}

// @Summary List logs
// @Tags Logs
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param page query int false "Page number"
// @Param pageSize query int false "Page size"
// @Success 200 {object} shared.Paged[models.Log]
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/logs/ [get]
func (controller *LogController) ListPaged(ctx shared.Context) error {
	org := shared.GetOrg(ctx)
	project := shared.GetProject(ctx)
	asset := shared.GetAsset(ctx)
	var logs shared.Paged[models.Log]
	logs, err := controller.logService.ListPaged(ctx, nil, org.ID, project.ID, asset.ID)
	if err != nil {
		return echo.NewHTTPError(500, "could not get logs").WithInternal(err)
	}
	return ctx.JSON(200, logs)
}
