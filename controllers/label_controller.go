package controllers

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
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
	label.OrganizationID = org.ID
	label.ProjectID, label.AssetID = scopeIDs(ctx)
}

func attachLabelError(err error, target string) error {
	if shared.IsNotFound(err) {
		return echo.NewHTTPError(404, "label not found").WithInternal(err)
	}
	return echo.NewHTTPError(500, fmt.Sprintf("could not attach label to %s", target)).WithInternal(err)
}

func saveLabelError(err error, msg string) error {
	if shared.IsUniqueViolation(err) {
		return echo.NewHTTPError(409, "a label with this name and color already exists on this level").WithInternal(err)
	}
	return echo.NewHTTPError(500, fmt.Sprintf("could not save label: %s", msg)).WithInternal(err)
}

func (l *LabelController) readLabelOnLevel(ctx shared.Context) (models.Label, error) {
	organizationID := shared.GetOrg(ctx).ID
	projectID, assetID := scopeIDs(ctx)
	labelID, err := uuid.Parse(ctx.Param("labelID"))
	if err != nil {
		return models.Label{}, echo.NewHTTPError(400, "invalid label id").WithInternal(err)
	}
	label, err := l.labelRepository.FindLabelByIDThroughHierarchy(ctx.Request().Context(), nil, &labelID, &organizationID, projectID, assetID)
	if err != nil {
		if shared.IsNotFound(err) {
			return models.Label{}, echo.NewHTTPError(404, "label not found")
		}
		return models.Label{}, echo.NewHTTPError(500, "could not read label").WithInternal(err)
	}
	if !label.IsDefinedAt(organizationID, projectID, assetID) {
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

	if err := l.labelRepository.Create(ctx.Request().Context(), nil, &label); err != nil {
		return saveLabelError(err, "could not save label")
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
		return saveLabelError(err, "could not update label")
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
	labels, err := l.labelRepository.ListThroughHierarchy(ctx.Request().Context(), nil, &org.ID, nil, nil)
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
// @Success 200 {array} models.Label
// @Router /organizations/{organization}/projects/{projectSlug}/labels/ [get]
func (l *LabelController) ListOnProjectLevel(ctx shared.Context) error {
	org := shared.GetOrg(ctx)
	project := shared.GetProject(ctx)
	labels, err := l.labelRepository.ListThroughHierarchy(ctx.Request().Context(), nil, &org.ID, &project.ID, nil)
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
// @Success 200 {array} models.Label
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/labels/ [get]
func (l *LabelController) ListOnAssetLevel(ctx shared.Context) error {
	org := shared.GetOrg(ctx)
	project := shared.GetProject(ctx)
	asset := shared.GetAsset(ctx)
	labels, err := l.labelRepository.ListThroughHierarchy(ctx.Request().Context(), nil, &org.ID, &project.ID, &asset.ID)
	if err != nil {
		return echo.NewHTTPError(500, "could not find labels for this asset").WithInternal(err)
	}
	return ctx.JSON(200, labels)
}

// @Summary Attach label to artifact
// @Tags Label
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Param artifactName path string true "Artifact name"
// @Param body body dtos.AttachLabelRequest true "Label data"
// @Success 204
// @Router /organizations/{organization}/projects/{projectSlug}/labels/attach/ [post]
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/labels/attach/ [post]
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/artifacts/{artifactName}/labels/attach/ [post]
func (c *LabelController) AttachLabel(ctx shared.Context) error {
	var org models.Org
	var project models.Project
	var asset models.Asset
	var artifact models.Artifact

	var req dtos.AttachLabelRequest
	var err error
	if err = ctx.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "could not parse request body").WithInternal(err)
	}
	if err = dtos.V.Struct(req); err != nil {
		return echo.NewHTTPError(400, fmt.Sprintf("could not validate request: %s", err.Error()))
	}

	if !shared.HasOrganization(ctx) {
		return echo.NewHTTPError(400, "missing organization ID")
	}
	uniqueLabels := utils.UniqBy(req.Labels, func(label string) string {
		return label
	})
	var parsedLabels []uuid.UUID
	for _, stringLabel := range uniqueLabels {
		parsed, err := uuid.Parse(stringLabel)
		if err != nil {
			return echo.NewHTTPError(400, "could not parse label ID, ID might be invalid")
		}
		parsedLabels = append(parsedLabels, parsed)
	}

	tx := c.labelRepository.GetDB(ctx.Request().Context(), nil)
	org = shared.GetOrg(ctx)

	if !shared.HasProject(ctx) {
		return echo.NewHTTPError(400, "attaching labels requires at least a project ID")
	}
	project = shared.GetProject(ctx)

	if org.ID != project.OrganizationID {
		return echo.NewHTTPError(403, "project does not belong to organization")
	}

	if !shared.HasAsset(ctx) {
		err = c.labelService.AttachLabels(ctx.Request().Context(), tx, org.ID, &project.ID, nil, nil, parsedLabels)
		if err != nil {
			return attachLabelError(err, "project")
		}
		return ctx.NoContent(204)
	}

	asset = shared.GetAsset(ctx)
	if project.ID != asset.ProjectID {
		return echo.NewHTTPError(403, "asset does not belong to project")
	}

	if !shared.HasArtifact(ctx) {
		err = c.labelService.AttachLabels(ctx.Request().Context(), tx, org.ID, &project.ID, &asset.ID, nil, parsedLabels)
		if err != nil {
			return attachLabelError(err, "asset")
		}
		return ctx.NoContent(204)
	}

	artifact = shared.GetArtifact(ctx)
	if asset.ID != artifact.AssetID {
		return echo.NewHTTPError(403, "artifact does not belong to asset")
	}

	err = c.labelService.AttachLabels(ctx.Request().Context(), tx, org.ID, &project.ID, &asset.ID, &artifact.ID, parsedLabels)
	if err != nil {
		return attachLabelError(err, "artifact")
	}
	return ctx.NoContent(204)
}
