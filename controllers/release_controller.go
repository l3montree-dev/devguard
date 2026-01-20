package controllers

import (
	"fmt"
	"net/http"
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
)

type ReleaseController struct {
	service                shared.ReleaseService
	assetVersionService    shared.AssetVersionService
	assetVersionRepository shared.AssetVersionRepository
	componentRepository    shared.ComponentRepository
	licenseRiskRepository  shared.LicenseRiskRepository
	dependencyVulnRepo     shared.DependencyVulnRepository
	assetRepository        shared.AssetRepository
}

func NewReleaseController(service shared.ReleaseService, avService shared.AssetVersionService, avRepo shared.AssetVersionRepository, compRepo shared.ComponentRepository, licRepo shared.LicenseRiskRepository, dvRepo shared.DependencyVulnRepository, assetRepository shared.AssetRepository) *ReleaseController {
	return &ReleaseController{service: service, assetVersionService: avService, assetVersionRepository: avRepo, componentRepository: compRepo, licenseRiskRepository: licRepo, dependencyVulnRepo: dvRepo, assetRepository: assetRepository}
}

// @Summary List releases
// @Tags Releases
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param search query string false "Search term"
// @Success 200 {object} object
// @Router /organizations/{organization}/projects/{projectSlug}/releases [get]
func (h *ReleaseController) List(c shared.Context) error {
	project := shared.GetProject(c)

	filter := shared.GetFilterQuery(c)
	pageInfo := shared.GetPageInfo(c)
	search := c.QueryParam("search")
	sort := shared.GetSortQuery(c)

	paged, err := h.service.ListByProjectPaged(project.GetID(), pageInfo, search, filter, sort)
	if err != nil {
		return echo.NewHTTPError(500, "could not list releases").WithInternal(err)
	}

	// map releases to DTOs
	pagedDTO := paged.Map(func(r models.Release) any {
		return transformer.ReleaseToDTO(r)
	})

	return c.JSON(http.StatusOK, pagedDTO)
}

// @Summary Get release SBOM as JSON
// @Tags Releases
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param releaseID path string true "Release ID"
// @Success 200 {object} object
// @Router /organizations/{organization}/projects/{projectSlug}/releases/{releaseID}/sbom.json [get]
func (h *ReleaseController) SBOMJSON(c shared.Context) error {
	idParam := shared.GetParam(c, "releaseID")
	id, err := uuid.Parse(idParam)
	if err != nil {
		return echo.NewHTTPError(400, "invalid release id")
	}

	rel, err := h.service.ReadRecursive(id)
	if err != nil {
		return echo.NewHTTPError(404, "release not found").WithInternal(err)
	}

	org := shared.GetOrg(c)
	project := shared.GetProject(c)
	frontendURL := os.Getenv("FRONTEND_URL")
	if frontendURL == "" {
		return echo.NewHTTPError(http.StatusInternalServerError, "FRONTEND_URL is not configured")
	}

	bom, err := h.buildMergedSBOM(c, rel, org.Name, org.Slug, project.Slug, frontendURL)
	if err != nil {
		return echo.NewHTTPError(500, "could not build sbom").WithInternal(err)
	}

	c.Response().Header().Set(echo.HeaderContentType, "application/json")
	return cdx.NewBOMEncoder(c.Response().Writer, cdx.BOMFileFormatJSON).Encode(bom)
}

// @Summary Get release SBOM as XML
// @Tags Releases
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param releaseID path string true "Release ID"
// @Success 200 {object} object
// @Router /organizations/{organization}/projects/{projectSlug}/releases/{releaseID}/sbom.xml [get]
func (h *ReleaseController) SBOMXML(c shared.Context) error {
	idParam := shared.GetParam(c, "releaseID")
	id, err := uuid.Parse(idParam)
	if err != nil {
		return echo.NewHTTPError(400, "invalid release id")
	}

	rel, err := h.service.ReadRecursive(id)
	if err != nil {
		return echo.NewHTTPError(404, "release not found").WithInternal(err)
	}

	org := shared.GetOrg(c)
	project := shared.GetProject(c)
	frontendURL := os.Getenv("FRONTEND_URL")
	if frontendURL == "" {
		return echo.NewHTTPError(http.StatusInternalServerError, "FRONTEND_URL is not configured")
	}

	bom, err := h.buildMergedSBOM(c, rel, org.Name, org.Slug, project.Slug, frontendURL)
	if err != nil {
		return echo.NewHTTPError(500, "could not build sbom").WithInternal(err)
	}

	c.Response().Header().Set(echo.HeaderContentType, "application/xml")
	return cdx.NewBOMEncoder(c.Response().Writer, cdx.BOMFileFormatXML).Encode(bom)
}

// @Summary Get release VEX as JSON
// @Tags Releases
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param releaseID path string true "Release ID"
// @Success 200 {object} object
// @Router /organizations/{organization}/projects/{projectSlug}/releases/{releaseID}/vex.json [get]
func (h *ReleaseController) VEXJSON(c shared.Context) error {
	idParam := shared.GetParam(c, "releaseID")
	id, err := uuid.Parse(idParam)
	if err != nil {
		return echo.NewHTTPError(400, "invalid release id")
	}

	rel, err := h.service.ReadRecursive(id)
	if err != nil {
		return echo.NewHTTPError(404, "release not found").WithInternal(err)
	}

	org := shared.GetOrg(c)
	project := shared.GetProject(c)
	frontendURL := os.Getenv("FRONTEND_URL")
	if frontendURL == "" {
		return echo.NewHTTPError(http.StatusInternalServerError, "FRONTEND_URL is not configured")
	}

	bom, err := h.buildMergedVEX(c, rel, org.Name, org.Slug, project.Slug, frontendURL)
	if err != nil {
		return echo.NewHTTPError(500, "could not build vex").WithInternal(err)
	}

	c.Response().Header().Set(echo.HeaderContentType, "application/json")
	return cdx.NewBOMEncoder(c.Response().Writer, cdx.BOMFileFormatJSON).Encode(bom)
}

// @Summary Get release VEX as XML
// @Tags Releases
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param releaseID path string true "Release ID"
// @Success 200 {object} object
// @Router /organizations/{organization}/projects/{projectSlug}/releases/{releaseID}/vex.xml [get]
func (h *ReleaseController) VEXXML(c shared.Context) error {
	idParam := shared.GetParam(c, "releaseID")
	id, err := uuid.Parse(idParam)
	if err != nil {
		return echo.NewHTTPError(400, "invalid release id")
	}

	rel, err := h.service.ReadRecursive(id)
	if err != nil {
		return echo.NewHTTPError(404, "release not found").WithInternal(err)
	}

	project := shared.GetProject(c)
	org := shared.GetOrg(c)
	frontendURL := os.Getenv("FRONTEND_URL")
	if frontendURL == "" {
		return echo.NewHTTPError(http.StatusInternalServerError, "FRONTEND_URL is not configured")
	}

	bom, err := h.buildMergedVEX(c, rel, org.Name, org.Slug, project.Slug, frontendURL)
	if err != nil {
		return echo.NewHTTPError(500, "could not build vex").WithInternal(err)
	}

	c.Response().Header().Set(echo.HeaderContentType, "application/xml")
	return cdx.NewBOMEncoder(c.Response().Writer, cdx.BOMFileFormatXML).Encode(bom)
}

// buildMergedSBOM builds per-artifact SBOMs and merges them into a single CycloneDX BOM.
func (h *ReleaseController) buildMergedSBOM(c shared.Context, release models.Release, orgName, orgSlug, projectSlug string, frontendURL string) (*cdx.BOM, error) {
	merged, err := h.mergeReleaseSBOM(release, orgName, orgSlug, projectSlug, frontendURL, map[uuid.UUID]struct{}{})
	if err != nil {
		return nil, err
	}

	return merged.ToCycloneDX(normalize.BOMMetadata{
		RootName: release.Name,
	}), nil
}

// buildMergedVEX builds per-artifact VeX (CycloneDX with vulnerabilities) and merges them.
func (h *ReleaseController) buildMergedVEX(c shared.Context, release models.Release, orgName, orgSlug, projectSlug, frontendURL string) (*cdx.BOM, error) {
	merged, err := h.mergeReleaseVEX(release, orgName, orgSlug, projectSlug, frontendURL, map[uuid.UUID]struct{}{})
	if err != nil {
		return nil, err
	}

	return merged.ToCycloneDX(normalize.BOMMetadata{
		RootName: release.Name,
	}), nil
}

// mergeReleaseSBOM loops over release items, resolving each item either as an artifact
// reference (by asset ID, asset version name, or artifact name) or as a child release
// reference with no asset fields, and guards against bugs such as nil-pointer access.
func (h *ReleaseController) mergeReleaseSBOM(release models.Release, orgName, orgSlug, projectSlug, frontendURL string, visiting map[uuid.UUID]struct{}) (*normalize.SBOMGraph, error) {
	if _, ok := visiting[release.ID]; ok {
		return nil, fmt.Errorf("cycle detected in release items for %s", release.ID)
	}
	visiting[release.ID] = struct{}{}
	defer delete(visiting, release.ID)

	var boms []*normalize.SBOMGraph

	for _, item := range release.Items {
		if item.ChildRelease != nil || item.ChildReleaseID != nil {
			child := item.ChildRelease
			if child == nil && item.ChildReleaseID != nil {
				rel, err := h.service.ReadRecursive(*item.ChildReleaseID)
				if err != nil {
					return nil, err
				}
				child = &rel
			}
			if child == nil {
				return nil, fmt.Errorf("release item %s is missing child release data", item.ID)
			}
			childBom, err := h.mergeReleaseSBOM(*child, orgName, orgSlug, projectSlug, frontendURL, visiting)
			if err != nil {
				return nil, err
			}
			if childBom != nil {
				boms = append(boms, childBom)
			}
			continue
		}

		if item.AssetID == nil || item.AssetVersionName == nil || item.ArtifactName == nil {
			return nil, fmt.Errorf("release item %s is missing asset reference", item.ID)
		}

		bom, err := h.assetVersionService.LoadFullSBOMGraph(models.AssetVersion{AssetID: *item.AssetID, Name: *item.AssetVersionName})
		if err != nil {
			return nil, err
		}

		bom.ScopeToArtifact(*item.ArtifactName)
		// scope to artifact
		boms = append(boms, bom)
	}

	result := normalize.NewSBOMGraph()
	for _, b := range boms {
		result.MergeGraph(b)
	}

	return result, nil
}

func (h *ReleaseController) mergeReleaseVEX(release models.Release, orgName, orgSlug, projectSlug, frontendURL string, visiting map[uuid.UUID]struct{}) (*normalize.SBOMGraph, error) {
	if _, ok := visiting[release.ID]; ok {
		return nil, fmt.Errorf("cycle detected in release items for %s", release.ID)
	}
	visiting[release.ID] = struct{}{}
	defer delete(visiting, release.ID)

	var boms []*normalize.SBOMGraph

	for _, item := range release.Items {
		if item.ChildRelease != nil || item.ChildReleaseID != nil {
			child := item.ChildRelease
			if child == nil && item.ChildReleaseID != nil {
				rel, err := h.service.ReadRecursive(*item.ChildReleaseID)
				if err != nil {
					return nil, err
				}
				child = &rel
			}
			if child == nil {
				return nil, fmt.Errorf("release item %s is missing child release data", item.ID)
			}
			childBom, err := h.mergeReleaseVEX(*child, orgName, orgSlug, projectSlug, frontendURL, visiting)
			if err != nil {
				return nil, err
			}
			if childBom != nil {
				boms = append(boms, childBom)
			}
			continue
		}

		if item.AssetID == nil || item.AssetVersionName == nil || item.ArtifactName == nil {
			return nil, fmt.Errorf("release item %s is missing asset reference", item.ID)
		}

		depVulns, err := h.dependencyVulnRepo.GetDependencyVulnsByAssetVersion(nil, *item.AssetVersionName, *item.AssetID, item.ArtifactName)
		if err != nil {
			return nil, err
		}

		av, err := h.assetVersionRepository.Read(*item.AssetVersionName, *item.AssetID)
		if err != nil {
			return nil, err
		}
		asset, err := h.assetRepository.Read(av.AssetID)
		if err != nil {
			return nil, err
		}

		bom := h.assetVersionService.BuildVeX(frontendURL, orgName, orgSlug, projectSlug, asset, av, *item.ArtifactName, depVulns)
		if bom != nil {
			boms = append(boms, bom)
		}
	}
	result := normalize.NewSBOMGraph()
	for _, b := range boms {
		result.MergeGraph(b)
	}

	return result, nil
}

// @Summary Get release details
// @Tags Releases
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param releaseID path string true "Release ID"
// @Success 200 {object} dtos.ReleaseDTO
// @Router /organizations/{organization}/projects/{projectSlug}/releases/{releaseID} [get]
func (h *ReleaseController) Read(c shared.Context) error {
	idParam := shared.GetParam(c, "releaseID")
	id, err := uuid.Parse(idParam)
	if err != nil {
		return echo.NewHTTPError(400, "invalid release id")
	}

	rel, err := h.service.ReadRecursive(id)
	if err != nil {
		return echo.NewHTTPError(404, "release not found").WithInternal(err)
	}

	return c.JSON(http.StatusOK, transformer.ReleaseToDTO(rel))
}

// @Summary Create release
// @Tags Releases
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param body body dtos.ReleaseCreateRequest true "Release data"
// @Success 201 {object} dtos.ReleaseDTO
// @Router /organizations/{organization}/projects/{projectSlug}/releases [post]
func (h *ReleaseController) Create(c shared.Context) error {
	var req dtos.ReleaseCreateRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "invalid payload").WithInternal(err)
	}

	project := shared.GetProject(c)
	model := transformer.ReleaseCreateRequestToModel(req, project.GetID())

	if err := h.service.Create(&model); err != nil {
		return echo.NewHTTPError(500, "could not create release").WithInternal(err)
	}

	return c.JSON(http.StatusCreated, transformer.ReleaseToDTO(model))
}

// @Summary Update release
// @Tags Releases
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param releaseID path string true "Release ID"
// @Param body body dtos.ReleasePatchRequest true "Release data"
// @Success 200 {object} dtos.ReleaseDTO
// @Router /organizations/{organization}/projects/{projectSlug}/releases/{releaseID} [patch]
func (h *ReleaseController) Update(c shared.Context) error {
	idParam := shared.GetParam(c, "releaseID")
	id, err := uuid.Parse(idParam)
	if err != nil {
		return echo.NewHTTPError(400, "invalid release id")
	}

	var req dtos.ReleasePatchRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "invalid payload").WithInternal(err)
	}

	rel, err := h.service.Read(id)
	if err != nil {
		return echo.NewHTTPError(404, "release not found").WithInternal(err)
	}

	transformer.ApplyReleasePatchRequestToModel(req, &rel)

	if err := h.service.Update(&rel); err != nil {
		return echo.NewHTTPError(500, "could not update release").WithInternal(err)
	}

	return c.JSON(http.StatusOK, transformer.ReleaseToDTO(rel))
}

// @Summary Delete release
// @Tags Releases
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param releaseID path string true "Release ID"
// @Success 204
// @Router /organizations/{organization}/projects/{projectSlug}/releases/{releaseID} [delete]
func (h *ReleaseController) Delete(c shared.Context) error {
	idParam := shared.GetParam(c, "releaseID")
	id, err := uuid.Parse(idParam)
	if err != nil {
		return echo.NewHTTPError(400, "invalid release id")
	}

	if err := h.service.Delete(id); err != nil {
		return echo.NewHTTPError(500, "could not delete release").WithInternal(err)
	}

	return c.NoContent(http.StatusNoContent)
}

// @Summary Add item to release
// @Tags Releases
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param releaseID path string true "Release ID"
// @Param body body dtos.ReleaseItemDTO true "Release item data"
// @Success 201 {object} dtos.ReleaseItemDTO
// @Router /organizations/{organization}/projects/{projectSlug}/releases/{releaseID}/items [post]
func (h *ReleaseController) AddItem(c shared.Context) error {
	relIDParam := shared.GetParam(c, "releaseID")
	relID, err := uuid.Parse(relIDParam)
	if err != nil {
		return echo.NewHTTPError(400, "invalid release id")
	}

	var dto dtos.ReleaseItemDTO
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

	return c.JSON(http.StatusCreated, transformer.ReleaseItemToDTO(item))
}

// @Summary Remove item from release
// @Tags Releases
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param releaseID path string true "Release ID"
// @Param itemID path string true "Item ID"
// @Success 204
// @Router /organizations/{organization}/projects/{projectSlug}/releases/{releaseID}/items/{itemID} [delete]
func (h *ReleaseController) RemoveItem(c shared.Context) error {
	itemIDParam := shared.GetParam(c, "itemID")
	itemID, err := uuid.Parse(itemIDParam)
	if err != nil {
		return echo.NewHTTPError(400, "invalid item id")
	}

	if err := h.service.RemoveItem(itemID); err != nil {
		return echo.NewHTTPError(500, "could not remove release item").WithInternal(err)
	}

	return c.NoContent(http.StatusNoContent)
}

// @Summary List release candidates
// @Tags Releases
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param releaseID query string false "Release ID"
// @Success 200 {object} dtos.CandidatesResponseDTO
// @Router /organizations/{organization}/projects/{projectSlug}/releases/candidates [get]
func (h *ReleaseController) ListCandidates(c shared.Context) error {
	project := shared.GetProject(c)
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
	artDTOs := []dtos.ArtifactDTO{}
	for _, a := range artifacts {
		artDTOs = append(artDTOs, dtos.ArtifactDTO{
			ArtifactName:     a.ArtifactName,
			AssetVersionName: a.AssetVersionName,
			AssetID:          a.AssetID,
		})
	}

	dto := dtos.CandidatesResponseDTO{
		Artifacts: artDTOs,
		Releases:  utils.Map(releases, transformer.ReleaseToDTO),
	}

	return c.JSON(http.StatusOK, dto)
}
