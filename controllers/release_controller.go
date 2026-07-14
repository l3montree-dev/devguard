package controllers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
	gocsaf "github.com/gocsaf/csaf/v3/csaf"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
	"github.com/openvex/go-vex/pkg/vex"
	"gorm.io/gorm"
)

type ReleaseController struct {
	service                shared.ReleaseService
	assetVersionService    shared.AssetVersionService
	assetVersionRepository shared.AssetVersionRepository
	dependencyVulnRepo     shared.DependencyVulnRepository
	assetRepository        shared.AssetRepository
	csafService            shared.CSAFService
}

func NewReleaseController(service shared.ReleaseService, avService shared.AssetVersionService, avRepo shared.AssetVersionRepository, dvRepo shared.DependencyVulnRepository, assetRepository shared.AssetRepository, csafService shared.CSAFService) *ReleaseController {
	return &ReleaseController{service: service, assetVersionService: avService, assetVersionRepository: avRepo, dependencyVulnRepo: dvRepo, assetRepository: assetRepository, csafService: csafService}
}

// @Summary List releases
// @Tags Releases
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
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

	paged, err := h.service.ListByProjectPaged(c.Request().Context(), project.GetID(), pageInfo, search, filter, sort)
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
// @Security BearerAuth
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

	rel, err := h.service.ReadRecursive(c.Request().Context(), id)
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
	return cdx.NewBOMEncoder(c.Response().Writer, cdx.BOMFileFormatJSON).SetPretty(true).SetEscapeHTML(false).Encode(bom)
}

// @Summary Get release SBOM as XML
// @Tags Releases
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
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

	rel, err := h.service.ReadRecursive(c.Request().Context(), id)
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
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param releaseID path string true "Release ID"
// @Success 200 {object} object
// @Router /organizations/{organization}/projects/{projectSlug}/releases/{releaseID}/vex.json [get]
func (h *ReleaseController) CycloneDXVexJSON(c shared.Context) error {
	rel, err := h.readRelease(c)
	if err != nil {
		return err
	}
	bom, err := h.buildMergedVEX(c, rel)
	if err != nil {
		return echo.NewHTTPError(500, "could not build vex").WithInternal(err)
	}
	c.Response().Header().Set(echo.HeaderContentType, "application/json")
	return cdx.NewBOMEncoder(c.Response().Writer, cdx.BOMFileFormatJSON).SetPretty(true).SetEscapeHTML(false).Encode(bom)
}

// @Summary Get release VEX as XML
// @Tags Releases
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param releaseID path string true "Release ID"
// @Success 200 {object} object
// @Router /organizations/{organization}/projects/{projectSlug}/releases/{releaseID}/vex.xml [get]
func (h *ReleaseController) CycloneDXVexXML(c shared.Context) error {
	rel, err := h.readRelease(c)
	if err != nil {
		return err
	}
	bom, err := h.buildMergedVEX(c, rel)
	if err != nil {
		return echo.NewHTTPError(500, "could not build vex").WithInternal(err)
	}
	c.Response().Header().Set(echo.HeaderContentType, "application/xml")
	return cdx.NewBOMEncoder(c.Response().Writer, cdx.BOMFileFormatXML).Encode(bom)
}

// @Summary Get release VEX as CSAF
// @Tags Releases
// @Router /organizations/{organization}/projects/{projectSlug}/releases/{releaseID}/csaf.json [get]
func (h *ReleaseController) CSAFJSON(c shared.Context) error {
	rel, err := h.readRelease(c)
	if err != nil {
		return err
	}
	advisory, err := h.buildMergedCSAF(c, rel, shared.GetOrg(c).Name)
	if err != nil {
		return echo.NewHTTPError(500, "could not build csaf").WithInternal(err)
	}
	return c.JSON(http.StatusOK, advisory)
}

// @Summary Get release VEX as OpenVEX
// @Tags Releases
// @Router /organizations/{organization}/projects/{projectSlug}/releases/{releaseID}/openvex.json [get]
func (h *ReleaseController) OpenCycloneDXVexJSON(c shared.Context) error {
	rel, err := h.readRelease(c)
	if err != nil {
		return err
	}
	doc, err := h.buildMergedOpenVeX(c, rel, shared.GetOrg(c).Slug)
	if err != nil {
		return echo.NewHTTPError(500, "could not build openvex").WithInternal(err)
	}
	return c.JSON(http.StatusOK, doc)
}

// readRelease parses the releaseID path param and loads the release recursively.
func (h *ReleaseController) readRelease(c shared.Context) (models.Release, error) {
	id, err := uuid.Parse(shared.GetParam(c, "releaseID"))
	if err != nil {
		return models.Release{}, echo.NewHTTPError(400, "invalid release id")
	}
	rel, err := h.service.ReadRecursive(c.Request().Context(), id)
	if err != nil {
		return models.Release{}, echo.NewHTTPError(404, "release not found").WithInternal(err)
	}
	return rel, nil
}

// buildMergedSBOM builds per-artifact SBOMs and merges them into a single CycloneDX BOM.
func (h *ReleaseController) buildMergedSBOM(c shared.Context, release models.Release, orgName, orgSlug, projectSlug string, frontendURL string) (*cdx.BOM, error) {
	merged, err := h.mergeReleaseSBOM(c.Request().Context(), release, orgName, orgSlug, projectSlug, frontendURL, map[uuid.UUID]struct{}{})
	if err != nil {
		return nil, err
	}

	return merged.ToCycloneDX(normalize.BOMMetadata{
		RootName: release.Name,
	}), nil
}

// buildMergedVEX builds per-item CycloneDX VeX and merges them into one release BOM.
func (h *ReleaseController) buildMergedVEX(c shared.Context, release models.Release) (*cdx.BOM, error) {
	items, err := h.gatherReleaseVulns(c.Request().Context(), release, map[uuid.UUID]struct{}{})
	if err != nil {
		return nil, err
	}
	var boms []*cdx.BOM
	for _, item := range items {
		if bom := h.assetVersionService.BuildVeX(c.Request().Context(), nil, normalize.BOMMetadata{}, item.asset, item.assetVersion, item.vulns); bom != nil {
			boms = append(boms, bom)
		}
	}
	return normalize.MergeCycloneDXVEX(boms, release.Name), nil
}

// buildMergedOpenVeX builds per-item OpenVEX and merges their statements into one document.
func (h *ReleaseController) buildMergedOpenVeX(c shared.Context, release models.Release, orgSlug string) (vex.VEX, error) {
	items, err := h.gatherReleaseVulns(c.Request().Context(), release, map[uuid.UUID]struct{}{})
	if err != nil {
		return vex.VEX{}, err
	}
	doc := vex.New()
	doc.Author = orgSlug
	for _, item := range items {
		sub := h.assetVersionService.BuildOpenVeX(c.Request().Context(), nil, item.asset, item.assetVersion, orgSlug, item.vulns)
		doc.Statements = append(doc.Statements, sub.Statements...)
	}
	doc.GenerateCanonicalID() // nolint:errcheck
	return doc, nil
}

// buildMergedCSAF builds a single CSAF advisory covering all of the release's vulnerabilities.
func (h *ReleaseController) buildMergedCSAF(c shared.Context, release models.Release, orgName string) (gocsaf.Advisory, error) {
	items, err := h.gatherReleaseVulns(c.Request().Context(), release, map[uuid.UUID]struct{}{})
	if err != nil {
		return gocsaf.Advisory{}, err
	}
	var vulns []models.DependencyVuln
	for _, item := range items {
		vulns = append(vulns, item.vulns...)
	}
	title := fmt.Sprintf("Security advisory for release %s", release.Name)
	return h.csafService.GenerateCSAFReportForVulns(c.Request().Context(), orgName, &title, vulns)
}

// releaseItemVulns pairs a resolved release item (asset + version) with its vulnerabilities.
type releaseItemVulns struct {
	asset        models.Asset
	assetVersion models.AssetVersion
	vulns        []models.DependencyVuln
}

// mergeReleaseSBOM loops over release items, resolving each item either as an artifact
// reference (by asset ID, asset version name, or artifact name) or as a child release
// reference with no asset fields, and guards against bugs such as nil-pointer access.
func (h *ReleaseController) mergeReleaseSBOM(ctx context.Context, release models.Release, orgName, orgSlug, projectSlug, frontendURL string, visiting map[uuid.UUID]struct{}) (*normalize.SBOMGraph, error) {
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
				rel, err := h.service.ReadRecursive(ctx, *item.ChildReleaseID)
				if err != nil {
					return nil, err
				}
				child = &rel
			}
			if child == nil {
				return nil, fmt.Errorf("release item %s is missing child release data", item.ID)
			}
			childBom, err := h.mergeReleaseSBOM(ctx, *child, orgName, orgSlug, projectSlug, frontendURL, visiting)
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

		bom, err := h.assetVersionService.LoadFullSBOMGraph(ctx, nil, models.AssetVersion{AssetID: *item.AssetID, Name: *item.AssetVersionName})
		if err != nil {
			return nil, err
		}

		err = bom.ScopeToArtifact(*item.ArtifactName)
		if err != nil {
			return nil, err
		}
		// scope to artifact
		boms = append(boms, bom)
	}

	result := normalize.NewSBOMGraph()
	for _, b := range boms {
		result.MergeGraph(b)
	}

	return result, nil
}

// gatherReleaseVulns resolves every release item (recursing into child releases) into its
// asset, asset version and dependency vulnerabilities. It is the shared basis for all three
// release VEX formats.
func (h *ReleaseController) gatherReleaseVulns(ctx context.Context, release models.Release, visiting map[uuid.UUID]struct{}) ([]releaseItemVulns, error) {
	if _, ok := visiting[release.ID]; ok {
		return nil, fmt.Errorf("cycle detected in release items for %s", release.ID)
	}
	visiting[release.ID] = struct{}{}
	defer delete(visiting, release.ID)

	var items []releaseItemVulns

	for _, item := range release.Items {
		if item.ChildRelease != nil || item.ChildReleaseID != nil {
			child := item.ChildRelease
			if child == nil && item.ChildReleaseID != nil {
				rel, err := h.service.ReadRecursive(ctx, *item.ChildReleaseID)
				if err != nil {
					return nil, err
				}
				child = &rel
			}
			if child == nil {
				return nil, fmt.Errorf("release item %s is missing child release data", item.ID)
			}
			childItems, err := h.gatherReleaseVulns(ctx, *child, visiting)
			if err != nil {
				return nil, err
			}
			items = append(items, childItems...)
			continue
		}

		if item.AssetID == nil || item.AssetVersionName == nil || item.ArtifactName == nil {
			return nil, fmt.Errorf("release item %s is missing asset reference", item.ID)
		}

		depVulns, err := h.dependencyVulnRepo.GetDependencyVulnsByAssetVersion(ctx, nil, *item.AssetVersionName, *item.AssetID, item.ArtifactName)
		if err != nil {
			return nil, err
		}

		av, err := h.assetVersionRepository.Read(ctx, nil, *item.AssetVersionName, *item.AssetID)
		if err != nil {
			return nil, err
		}
		asset, err := h.assetRepository.Read(ctx, nil, av.AssetID) // nosemgrep: bola-controller-read-without-tenant-check -- av.AssetID comes from a previously-loaded AssetVersion, not from a user-controlled path param
		if err != nil {
			return nil, err
		}

		items = append(items, releaseItemVulns{asset: asset, assetVersion: av, vulns: depVulns})
	}

	return items, nil
}

// @Summary Get release details
// @Tags Releases
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
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

	rel, err := h.service.ReadRecursive(c.Request().Context(), id)
	if err != nil {
		return echo.NewHTTPError(404, "release not found").WithInternal(err)
	}

	return c.JSON(http.StatusOK, transformer.ReleaseToDTO(rel))
}

// @Summary Create release
// @Tags Releases
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
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

	if err := h.validateReleaseItemRefs(c.Request().Context(), req.Items); err != nil {
		return err
	}

	project := shared.GetProject(c)
	model := transformer.ReleaseCreateRequestToModel(req, project.GetID())

	if err := h.service.Create(c.Request().Context(), &model); err != nil {
		return echo.NewHTTPError(500, "could not create release").WithInternal(err)
	}

	return c.JSON(http.StatusCreated, transformer.ReleaseToDTO(model))
}

// @Summary Update release
// @Tags Releases
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
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

	rel, err := h.service.Read(c.Request().Context(), id)
	if err != nil {
		return echo.NewHTTPError(404, "release not found").WithInternal(err)
	}

	if err := h.validateReleaseItemRefs(c.Request().Context(), req.Items); err != nil {
		return err
	}

	transformer.ApplyReleasePatchRequestToModel(req, &rel)

	if err := h.service.Update(c.Request().Context(), &rel); err != nil {
		return echo.NewHTTPError(500, "could not update release").WithInternal(err)
	}

	return c.JSON(http.StatusOK, transformer.ReleaseToDTO(rel))
}

// @Summary Delete release
// @Tags Releases
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
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

	if err := h.service.Delete(c.Request().Context(), id); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return echo.NewHTTPError(404, "release not found")
		}
		return echo.NewHTTPError(500, "could not delete release").WithInternal(err)
	}

	return c.NoContent(http.StatusNoContent)
}

// @Summary Add item to release
// @Tags Releases
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
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

	// verify the target release belongs to the caller's tenant before attaching anything to it
	if _, err := h.service.Read(c.Request().Context(), relID); err != nil {
		return echo.NewHTTPError(404, "release not found").WithInternal(err)
	}

	if err := h.validateReleaseItemRefs(c.Request().Context(), []dtos.ReleaseItemDTO{dto}); err != nil {
		return err
	}

	item := models.ReleaseItem{
		ID:               dto.ID,
		ReleaseID:        relID,
		ChildReleaseID:   dto.ChildReleaseID,
		ArtifactName:     dto.ArtifactName,
		AssetVersionName: dto.AssetVersionName,
		AssetID:          dto.AssetID,
	}

	if err := h.service.AddItem(c.Request().Context(), &item); err != nil {
		return echo.NewHTTPError(500, "could not add release item").WithInternal(err)
	}

	return c.JSON(http.StatusCreated, transformer.ReleaseItemToDTO(item))
}

// validateReleaseItemRefs verifies that every foreign reference embedded in the given release
// items (a child release, or an asset) belongs to the caller's tenant before it is persisted.
// Without this check a user could embed a release or asset belonging to a different
// organization/project into their own release merely by knowing its UUID.
func (h *ReleaseController) validateReleaseItemRefs(ctx context.Context, items []dtos.ReleaseItemDTO) error {
	for _, it := range items {
		if it.ChildReleaseID != nil {
			if _, err := h.service.Read(ctx, *it.ChildReleaseID); err != nil {
				return echo.NewHTTPError(400, "invalid child release id").WithInternal(err)
			}
		}
		if it.AssetID != nil {
			if _, err := h.assetRepository.Read(ctx, nil, *it.AssetID); err != nil {
				return echo.NewHTTPError(400, "invalid asset id").WithInternal(err)
			}
		}
	}
	return nil
}

// @Summary Remove item from release
// @Tags Releases
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
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

	if err := h.service.RemoveItem(c.Request().Context(), itemID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return echo.NewHTTPError(404, "release item not found")
		}
		return echo.NewHTTPError(500, "could not remove release item").WithInternal(err)
	}

	return c.NoContent(http.StatusNoContent)
}

// @Summary List release candidates
// @Tags Releases
// @Security CookieAuth
// @Security PATAuth
// @Security BearerAuth
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

	artifacts, releases, err := h.service.ListCandidates(c.Request().Context(), project.GetID(), releaseID)
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
