package release

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/labstack/echo/v4"
)

type releaseController struct {
	service *service
}

func NewReleaseController(s *service) *releaseController {
	return &releaseController{service: s}
}

func (h *releaseController) List(c core.Context) error {
	project := core.GetProject(c)

	filter := core.GetFilterQuery(c)
	pageInfo := core.GetPageInfo(c)
	search := c.QueryParam("search")
	sort := core.GetSortQuery(c)

	paged, err := h.service.ListByProjectPaged(project.GetID(), pageInfo, search, filter, sort)
	if err != nil {
		return echo.NewHTTPError(500, "could not list releases").WithInternal(err)
	}

	// map releases to DTOs
	pagedDTO := paged.Map(func(r models.Release) any {
		return releaseToDTO(r)
	})

	return c.JSON(http.StatusOK, pagedDTO)
}

func (h *releaseController) Read(c core.Context) error {
	idParam := core.GetParam(c, "releaseId")
	id, err := uuid.Parse(idParam)
	if err != nil {
		return echo.NewHTTPError(400, "invalid release id")
	}

	rel, err := h.service.Read(id)
	if err != nil {
		return echo.NewHTTPError(404, "release not found").WithInternal(err)
	}

	return c.JSON(http.StatusOK, releaseToDTO(rel))
}

func (h *releaseController) Create(c core.Context) error {
	var req createRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "invalid payload").WithInternal(err)
	}

	project := core.GetProject(c)
	model := req.toModel(project.GetID())

	if err := h.service.Create(&model); err != nil {
		return echo.NewHTTPError(500, "could not create release").WithInternal(err)
	}

	return c.JSON(http.StatusCreated, releaseToDTO(model))
}

func (h *releaseController) Update(c core.Context) error {
	idParam := core.GetParam(c, "releaseId")
	id, err := uuid.Parse(idParam)
	if err != nil {
		return echo.NewHTTPError(400, "invalid release id")
	}

	var req patchRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "invalid payload").WithInternal(err)
	}

	rel, err := h.service.Read(id)
	if err != nil {
		return echo.NewHTTPError(404, "release not found").WithInternal(err)
	}

	req.applyToModel(&rel)

	if err := h.service.Update(&rel); err != nil {
		return echo.NewHTTPError(500, "could not update release").WithInternal(err)
	}

	return c.JSON(http.StatusOK, releaseToDTO(rel))
}

func (h *releaseController) Delete(c core.Context) error {
	idParam := core.GetParam(c, "releaseID")
	id, err := uuid.Parse(idParam)
	if err != nil {
		return echo.NewHTTPError(400, "invalid release id")
	}

	if err := h.service.Delete(id); err != nil {
		return echo.NewHTTPError(500, "could not delete release").WithInternal(err)
	}

	return c.NoContent(http.StatusNoContent)
}

// add item to a release (artifact or child release)
func (h *releaseController) AddItem(c core.Context) error {
	relIDParam := core.GetParam(c, "releaseID")
	relID, err := uuid.Parse(relIDParam)
	if err != nil {
		return echo.NewHTTPError(400, "invalid release id")
	}

	var dto ReleaseItemDTO
	if err := c.Bind(&dto); err != nil {
		return echo.NewHTTPError(400, "invalid payload").WithInternal(err)
	}

	item := models.ReleaseItem{
		ID:               dto.ID,
		ReleaseID:        relID,
		ChildReleaseID:   dto.ChildReleaseID,
		ArtifactName:     dto.ArtifactName,
		AssetVersionName: dto.AssetVersionName,
		AssetID:          dto.AssetID,
	}

	if err := h.service.AddItem(&item); err != nil {
		return echo.NewHTTPError(500, "could not add release item").WithInternal(err)
	}

	return c.JSON(http.StatusCreated, releaseItemToDTO(item))
}

// remove an item from a release
func (h *releaseController) RemoveItem(c core.Context) error {
	itemIDParam := core.GetParam(c, "itemID")
	itemID, err := uuid.Parse(itemIDParam)
	if err != nil {
		return echo.NewHTTPError(400, "invalid item id")
	}

	if err := h.service.RemoveItem(itemID); err != nil {
		return echo.NewHTTPError(500, "could not remove release item").WithInternal(err)
	}

	return c.NoContent(http.StatusNoContent)
}

func (h *releaseController) ListCandidates(c core.Context) error {
	project := core.GetProject(c)
	// check if a release id is provided
	releaseIDParam := c.Param("releaseID")
	var releaseID *uuid.UUID
	if releaseIDParam != "" {
		id, err := uuid.Parse(releaseIDParam)
		if err != nil {
			return echo.NewHTTPError(400, "invalid release id")
		}
		releaseID = &id
	}

	artifacts, releases, err := h.service.ListCandidates(project.GetID(), releaseID)
	if err != nil {
		return echo.NewHTTPError(500, "could not list candidates").WithInternal(err)
	}

	// map artifacts to DTOs and include asset name
	artDTOs := []ArtifactDTO{}
	for _, a := range artifacts {
		artDTOs = append(artDTOs, ArtifactDTO{
			ArtifactName:     a.ArtifactName,
			AssetVersionName: a.AssetVersionName,
			AssetID:          a.AssetID,
		})
	}

	dto := CandidatesResponseDTO{
		Artifacts: artDTOs,
		Releases:  utils.Map(releases, releaseToDTO),
	}

	return c.JSON(http.StatusOK, dto)
}
