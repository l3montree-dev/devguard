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

// SBOMJSON returns a merged CycloneDX BOM for a release in JSON format.
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

// SBOMXML returns a merged CycloneDX BOM for a release in XML format.
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

// VEXJSON currently returns the merged CycloneDX BOM as JSON for compatibility.
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

// VEXXML currently returns the merged CycloneDX BOM as XML for compatibility.
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

	return merged.EjectSBOM(nil), nil
}

// buildMergedVEX builds per-artifact VeX (CycloneDX with vulnerabilities) and merges them.
func (h *ReleaseController) buildMergedVEX(c shared.Context, release models.Release, orgName, orgSlug, projectSlug, frontendURL string) (*cdx.BOM, error) {
	merged, err := h.mergeReleaseVEX(release, orgName, orgSlug, projectSlug, frontendURL, map[uuid.UUID]struct{}{})
	if err != nil {
		return nil, err
	}

	return merged.EjectVex(nil), nil
}

// Loop over release items and then check, an item can either be an artifact reference with an assetid, asset versioname, artifact name or be a childreleaseID reference with no asset fields, this is where the bug also happend, where it pointed to a nil pointer

func (h *ReleaseController) mergeReleaseSBOM(release models.Release, orgName, orgSlug, projectSlug, frontendURL string, visiting map[uuid.UUID]struct{}) (*normalize.CdxBom, error) {
	if _, ok := visiting[release.ID]; ok {
		return nil, fmt.Errorf("cycle detected in release items for %s", release.ID)
	}
	visiting[release.ID] = struct{}{}
	defer delete(visiting, release.ID)

	var boms []*normalize.CdxBom

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

		overwrittenLicenses, err := h.licenseRiskRepository.GetAllOverwrittenLicensesForAssetVersion(*item.AssetID, *item.AssetVersionName)
		if err != nil {
			return nil, err
		}

		compsPage, err := h.componentRepository.LoadComponentsWithProject(nil, overwrittenLicenses, *item.AssetVersionName, *item.AssetID, shared.PageInfo{PageSize: 1000, Page: 1}, "", nil, nil)
		if err != nil {
			return nil, err
		}
		asset, err := h.assetRepository.Read(*item.AssetID)
		if err != nil {
			return nil, err
		}

		av := models.AssetVersion{AssetID: *item.AssetID, Name: *item.AssetVersionName}

		bom, err := h.assetVersionService.BuildSBOM(frontendURL, orgName, orgSlug, projectSlug, asset, av, *item.ArtifactName, compsPage.Data)
		if err != nil {
			return nil, err
		}

		boms = append(boms, bom)
	}

	return normalize.MergeCdxBoms(&cdx.Metadata{
		Component: &cdx.Component{
			Type: cdx.ComponentTypeApplication,
			Name: release.Name,
		},
	}, release.Name, boms...), nil
}

func (h *ReleaseController) mergeReleaseVEX(release models.Release, orgName, orgSlug, projectSlug, frontendURL string, visiting map[uuid.UUID]struct{}) (*normalize.CdxBom, error) {
	if _, ok := visiting[release.ID]; ok {
		return nil, fmt.Errorf("cycle detected in release items for %s", release.ID)
	}
	visiting[release.ID] = struct{}{}
	defer delete(visiting, release.ID)

	var boms []*normalize.CdxBom

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

	return normalize.MergeCdxBoms(&cdx.Metadata{
		Component: &cdx.Component{
			Type: cdx.ComponentTypeApplication,
			Name: release.Name,
		},
	}, release.Name, boms...), nil
}

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

// add item to a release (artifact or child release)
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

// remove an item from a release
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
