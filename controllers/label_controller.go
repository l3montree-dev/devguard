package controllers

import (
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
)

type LabelController struct {
	labelService    shared.LabelService
	labelRepository shared.LabelRepository
}

func NewLabelController(labelService shared.LabelService, labelRepository shared.LabelRepository) *LabelController {
	return &LabelController{
		labelService:    labelService,
		labelRepository: labelRepository,
	}
}

func (l *LabelController) Create(ctx shared.Context) error {
	var label models.Label

	org := shared.GetOrg(ctx)
	project := shared.GetProject(ctx)
	asset := shared.GetAsset(ctx)

	if err := ctx.Bind(&label); err != nil {
		return echo.NewHTTPError(400, "could not parse request body").WithInternal(err)
	}

	label.OrganizationID = &org.ID
	label.ProjectID = &project.ID
	label.AssetID = &asset.ID

	err := l.labelRepository.Create(ctx.Request().Context(), nil, &label)
	if err != nil {
		return echo.NewHTTPError(500, "could not create artifact").WithInternal(err)
	}

	return ctx.NoContent(200)
}

func (l *LabelController) Update(ctx shared.Context) error {
	var label models.Label

	org := shared.GetOrg(ctx)
	project := shared.GetProject(ctx)
	asset := shared.GetAsset(ctx)

	if err := ctx.Bind(&label); err != nil {
		return echo.NewHTTPError(400, "could not parse request body").WithInternal(err)
	}

	label.OrganizationID = &org.ID
	label.ProjectID = &project.ID
	label.AssetID = &asset.ID

	err := l.labelRepository.Save(ctx.Request().Context(), nil, &label)
	if err != nil {
		return echo.NewHTTPError(500, "could not create artifact").WithInternal(err)
	}

	return ctx.NoContent(200)
}

func (l *LabelController) Delete(ctx shared.Context) error {
	var label models.Label
	if err := ctx.Bind(&label); err != nil {
		return echo.NewHTTPError(400, "No labelID provided, could not parse request body")
	}
	err := l.labelRepository.Delete(ctx.Request().Context(), nil, label.ID)
	if err != nil {
		return echo.NewHTTPError(500, "Could not delete label").WithInternal(err)
	}
	return ctx.NoContent(200)
}

func (l *LabelController) ListOnOrgLevel(ctx shared.Context) error {
	org := shared.GetOrg(ctx)
	labels, err := l.labelService.ListOnOrgLevel(ctx.Request().Context(), nil, org.ID)
	if err != nil {
		return echo.NewHTTPError(500, "could not find labels for this org").WithInternal(err)
	}
	return ctx.JSON(200, labels)
}

func (l *LabelController) ListOnProjectLevel(ctx shared.Context) error {
	org := shared.GetOrg(ctx)
	project := shared.GetProject(ctx)
	labels, err := l.labelService.ListOnProjectLevel(ctx.Request().Context(), nil, org.ID, project.ID)
	if err != nil {
		return echo.NewHTTPError(500, "could not find labels for this project").WithInternal(err)
	}
	return ctx.JSON(200, labels)
}

func (l *LabelController) ListOnAssetLevel(ctx shared.Context) error {
	org := shared.GetOrg(ctx)
	project := shared.GetProject(ctx)
	asset := shared.GetAsset(ctx)
	labels, err := l.labelService.ListOnAssetLevel(ctx.Request().Context(), nil, org.ID, project.ID, asset.ID)
	if err != nil {
		return echo.NewHTTPError(500, "could not find labels for this asset").WithInternal(err)
	}
	return ctx.JSON(200, labels)
}
