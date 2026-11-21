package controllers

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
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

func scopeIDs(ctx shared.Context) (projectID, assetID *uuid.UUID) {
	if shared.HasProject(ctx) {
		project := shared.GetProject(ctx)
		projectID = &project.ID
	}
	if shared.HasAsset(ctx) {
		asset := shared.GetAsset(ctx)
		assetID = &asset.ID
	}
	return projectID, assetID
}

func setLabelScope(ctx shared.Context, label *models.Label) {
	org := shared.GetOrg(ctx)
	label.OrganizationID = &org.ID
	label.ProjectID, label.AssetID = scopeIDs(ctx)
}

func attachLabelError(err error, target string) error {
	switch {
	case shared.IsNotFound(err):
		return echo.NewHTTPError(404, "label not found").WithInternal(err)
	case errors.Is(err, shared.ErrLabelNotInScope):
		return echo.NewHTTPError(403, fmt.Sprintf("label is not available for this %s", target)).WithInternal(err)
	}
	return echo.NewHTTPError(500, fmt.Sprintf("could not attach label to %s", target)).WithInternal(err)
}

func (l *LabelController) readLabelOnLevel(ctx shared.Context) (models.Label, error) {
	labelID, err := uuid.Parse(ctx.Param("labelID"))
	if err != nil {
		return models.Label{}, echo.NewHTTPError(400, "invalid label id").WithInternal(err)
	}
	label, err := l.labelRepository.Read(ctx.Request().Context(), nil, labelID)
	if err != nil {
		if shared.IsNotFound(err) {
			return models.Label{}, echo.NewHTTPError(404, "label not found")
		}
		return models.Label{}, echo.NewHTTPError(500, "could not read label").WithInternal(err)
	}
	projectID, assetID := scopeIDs(ctx)
	if !label.IsDefinedAt(shared.GetOrg(ctx).ID, projectID, assetID) {
		return models.Label{}, echo.NewHTTPError(403, "not allowed to modify this label")
	}
	return label, nil
}

// @Summary Create label
// @Tags Label
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string false "Project slug (project and asset level)"
// @Param assetSlug path string false "Asset slug (asset level)"
// @Param body body dtos.LabelRequest true "Label data"
// @Success 200
// @Router /organizations/{organization}/labels/ [post]
// @Router /organizations/{organization}/projects/{projectSlug}/labels/ [post]
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/labels/ [post]
func (l *LabelController) Create(ctx shared.Context) error {
	var req dtos.LabelRequest
	if err := ctx.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "could not parse request body").WithInternal(err)
	}
	if err := dtos.V.Struct(req); err != nil {
		return echo.NewHTTPError(400, fmt.Sprintf("could not validate request: %s", err.Error()))
	}

	label := models.Label{Label: req.Label, BackgroundColor: req.BackgroundColor}
	setLabelScope(ctx, &label)

	err := l.labelRepository.Create(ctx.Request().Context(), nil, &label)
	if err != nil {
		return echo.NewHTTPError(500, "could not save label").WithInternal(err)
	}

	return ctx.NoContent(200)
}

// @Summary Update label
// @Tags Label
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string false "Project slug (project and asset level)"
// @Param assetSlug path string false "Asset slug (asset level)"
// @Param labelID path string true "Label ID"
// @Param body body dtos.LabelRequest true "Label data"
// @Success 200
// @Router /organizations/{organization}/labels/{labelID}/ [put]
// @Router /organizations/{organization}/projects/{projectSlug}/labels/{labelID}/ [put]
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/labels/{labelID}/ [put]
func (l *LabelController) Update(ctx shared.Context) error {
	existing, err := l.readLabelOnLevel(ctx)
	if err != nil {
		return err
	}

	var req dtos.LabelRequest
	if err := ctx.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "could not parse request body").WithInternal(err)
	}
	if err := dtos.V.Struct(req); err != nil {
		return echo.NewHTTPError(400, fmt.Sprintf("could not validate request: %s", err.Error()))
	}

	label := models.Label{
		ID:              existing.ID,
		OrganizationID:  existing.OrganizationID,
		ProjectID:       existing.ProjectID,
		AssetID:         existing.AssetID,
		CreatedAt:       existing.CreatedAt,
		Label:           req.Label,
		BackgroundColor: req.BackgroundColor,
	}

	if err := l.labelRepository.Save(ctx.Request().Context(), nil, &label); err != nil {
		return echo.NewHTTPError(500, "could not update label").WithInternal(err)
	}

	return ctx.NoContent(200)
}

// @Summary Delete label
// @Tags Label
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string false "Project slug (project and asset level)"
// @Param assetSlug path string false "Asset slug (asset level)"
// @Param labelID path string true "Label ID"
// @Success 200
// @Router /organizations/{organization}/labels/{labelID}/ [delete]
// @Router /organizations/{organization}/projects/{projectSlug}/labels/{labelID}/ [delete]
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/labels/{labelID}/ [delete]
func (l *LabelController) Delete(ctx shared.Context) error {
	label, err := l.readLabelOnLevel(ctx)
	if err != nil {
		return err
	}
	if err := l.labelRepository.Delete(ctx.Request().Context(), nil, label.ID); err != nil {
		return echo.NewHTTPError(500, "Could not delete label").WithInternal(err)
	}
	return ctx.NoContent(200)
}

// @Summary List labels on organization level
// @Tags Label
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Success 200 {array} dtos.Label
// @Router /organizations/{organization}/labels/ [get]
func (l *LabelController) ListOnOrgLevel(ctx shared.Context) error {
	org := shared.GetOrg(ctx)
	labels, err := l.labelService.ListOnOrgLevel(ctx.Request().Context(), nil, org.ID)
	if err != nil {
		return echo.NewHTTPError(500, "could not find labels for this org").WithInternal(err)
	}
	return ctx.JSON(200, labels)
}

// @Summary List labels on project level
// @Tags Label
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Success 200 {array} dtos.Label
// @Router /organizations/{organization}/projects/{projectSlug}/labels/ [get]
func (l *LabelController) ListOnProjectLevel(ctx shared.Context) error {
	org := shared.GetOrg(ctx)
	project := shared.GetProject(ctx)
	labels, err := l.labelService.ListOnProjectLevel(ctx.Request().Context(), nil, org.ID, project.ID)
	if err != nil {
		return echo.NewHTTPError(500, "could not find labels for this project").WithInternal(err)
	}
	return ctx.JSON(200, labels)
}

// @Summary List labels on asset level
// @Tags Label
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Success 200 {array} dtos.Label
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/labels/ [get]
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
