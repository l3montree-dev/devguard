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
	labelRepository shared.LabelRepository
}

func NewLabelController(labelRepository shared.LabelRepository) *LabelController {
	return &LabelController{
		labelRepository: labelRepository,
	}
}

func saveLabelError(err error, msg string) error {
	if shared.IsUniqueViolation(err) {
		return echo.NewHTTPError(409, "a label with this name and color already exists on this level").WithInternal(err)
	}
	return echo.NewHTTPError(500, fmt.Sprintf("could not save label: %s", msg)).WithInternal(err)
}

func (l *LabelController) readLabelOnLevel(ctx shared.Context) (models.Label, error) {
	organizationID, projectID, assetID := scopeIDs(ctx)
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
// @Success 200 {object} models.Label
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

	label := models.Label{Label: req.Label, BackgroundColor: req.BackgroundColor, Description: req.Description}
	label.OrganizationID, label.ProjectID, label.AssetID = scopeIDs(ctx)

	if err := l.labelRepository.Create(ctx.Request().Context(), nil, &label); err != nil {
		return saveLabelError(err, "could not save label")
	}

	return ctx.JSON(200, label)
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
// @Success 200 {object} models.Label
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
		Description:     req.Description,
	}

	if err := l.labelRepository.Save(ctx.Request().Context(), nil, &label); err != nil {
		return saveLabelError(err, "could not update label")
	}

	return ctx.JSON(200, label)
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
// @Success 200 {array} models.Label
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
// @Success 200 {array} models.Label
// @Router /organizations/{organization}/projects/{projectSlug}/labels/attach/ [post]
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/labels/attach/ [post]
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/artifacts/{artifactName}/labels/attach/ [post]
func (l *LabelController) AttachLabel(ctx shared.Context) error {
	var org models.Org
	var projectID *uuid.UUID
	var assetID *uuid.UUID
	var artifactID *uuid.UUID

	var req dtos.AttachLabelRequest
	var err error
	requestCtx := ctx.Request().Context()
	tx := l.labelRepository.GetDB(requestCtx, nil)

	if err = ctx.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "could not parse request body").WithInternal(err)
	}
	if err = dtos.V.Struct(req); err != nil {
		return echo.NewHTTPError(400, fmt.Sprintf("could not validate request: %s", err.Error()))
	}

	uniqueLabels := utils.UniqBy(req.Labels, func(label string) string {
		return label
	})
	if len(uniqueLabels) != len(req.Labels) {
		return echo.NewHTTPError(400, "duplicate labels detected, cannot attach the same id to the same resource twice")
	}

	if !shared.HasOrganization(ctx) {
		return echo.NewHTTPError(400, "organization ID is missing")
	}

	if !shared.HasProject(ctx) {
		return echo.NewHTTPError(400, "project ID is required at minimum")
	}

	org = shared.GetOrg(ctx)
	projectExtract := shared.GetProject(ctx)
	projectID = &projectExtract.ID

	if shared.HasAsset(ctx) {
		assetExtract := shared.GetAsset(ctx)
		assetID = &assetExtract.ID
	}

	if shared.HasArtifact(ctx) {
		artifactExtract := shared.GetArtifact(ctx)
		artifactID = &artifactExtract.ID
	}

	var parsedLabels []uuid.UUID
	for _, stringLabel := range uniqueLabels {
		parsed, err := uuid.Parse(stringLabel)
		if err != nil {
			return echo.NewHTTPError(400, "could not parse label ID, ID might be invalid")
		}
		parsedLabels = append(parsedLabels, parsed)
	}

	existingLabels, err := l.labelRepository.FindLabelsByIDsThroughHierarchy(requestCtx, tx, parsedLabels, &org.ID, projectID, assetID)
	if err != nil {
		return err
	}
	if len(existingLabels) != len(req.Labels) {
		return echo.NewHTTPError(400, "could not find all labels, labelID list might contain invalid IDs")
	}

	err = l.labelRepository.CreateLabelAttachmentBatch(requestCtx, tx, parsedLabels, projectID, assetID, artifactID)
	if err != nil {
		return echo.NewHTTPError(500, "could not attach labels to resources")
	}
	return ctx.JSON(200, existingLabels)
}
