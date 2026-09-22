package controllers

import (
	"github.com/google/uuid"
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
// @Param projectSlug path string false "Project slug"
// @Param assetSlug path string false "Asset slug"
// @Param page query int false "Page number"
// @Param pageSize query int false "Page size"
// @Param search query string false "Search term"
// @Param sort query string false "Sort query, e.g. sort[createdAt]=desc"
// @Param filterQuery query string false "Filter query, e.g. filterQuery[logs.log_level][is]=error"
// @Success 200 {object} shared.Paged[dtos.LogDTO]
// @Router /organizations/{organization}/logs/ [get]
// @Router /organizations/{organization}/projects/{projectSlug}/logs/ [get]
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/logs/ [get]
func (controller *LogController) ListPaged(ctx shared.Context) error {
	org := shared.GetOrg(ctx)

	var projectID *uuid.UUID
	project, err := shared.MaybeGetProject(ctx)
	if err == nil {
		projectID = &project.ID
	}
	var assetID *uuid.UUID
	asset, err := shared.MaybeGetAsset(ctx)
	if err == nil {
		assetID = &asset.ID
	}
	logs, err := controller.logService.ListPaged(ctx, nil, &org.ID, projectID, assetID, shared.GetPageInfo(ctx), ctx.QueryParam("search"), shared.GetFilterQuery(ctx), shared.GetSortQuery(ctx))
	if err != nil {
		return echo.NewHTTPError(500, "could not get logs").WithInternal(err)
	}
	return ctx.JSON(200, logs)
}
