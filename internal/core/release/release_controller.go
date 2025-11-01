package release

import (
	"net/http"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/normalize"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/labstack/echo/v4"
)

type releaseController struct {
	service                *service
	assetVersionService    core.AssetVersionService
	assetVersionRepository core.AssetVersionRepository
	componentRepository    core.ComponentRepository
	licenseRiskRepository  core.LicenseRiskRepository
	dependencyVulnRepo     core.DependencyVulnRepository
	assetRepository        core.AssetRepository
}

func NewReleaseController(s *service, avService core.AssetVersionService, avRepo core.AssetVersionRepository, compRepo core.ComponentRepository, licRepo core.LicenseRiskRepository, dvRepo core.DependencyVulnRepository, assetRepository core.AssetRepository) *releaseController {
	return &releaseController{service: s, assetVersionService: avService, assetVersionRepository: avRepo, componentRepository: compRepo, licenseRiskRepository: licRepo, dependencyVulnRepo: dvRepo, assetRepository: assetRepository}
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

// SBOMJSON returns a merged CycloneDX BOM for a release in JSON format.
func (h *releaseController) SBOMJSON(c core.Context) error {
	idParam := core.GetParam(c, "releaseID")
	id, err := uuid.Parse(idParam)
	if err != nil {
		return echo.NewHTTPError(400, "invalid release id")
	}

	rel, err := h.service.ReadRecursive(id)
	if err != nil {
		return echo.NewHTTPError(404, "release not found").WithInternal(err)
	}

	org := core.GetOrg(c)

	bom, err := h.buildMergedSBOM(c, rel, org.Name)
	if err != nil {
		return echo.NewHTTPError(500, "could not build sbom").WithInternal(err)
	}

	c.Response().Header().Set(echo.HeaderContentType, "application/json")
	return cdx.NewBOMEncoder(c.Response().Writer, cdx.BOMFileFormatJSON).Encode(bom)
}

// SBOMXML returns a merged CycloneDX BOM for a release in XML format.
func (h *releaseController) SBOMXML(c core.Context) error {
	idParam := core.GetParam(c, "releaseID")
	id, err := uuid.Parse(idParam)
	if err != nil {
		return echo.NewHTTPError(400, "invalid release id")
	}

	rel, err := h.service.ReadRecursive(id)
	if err != nil {
		return echo.NewHTTPError(404, "release not found").WithInternal(err)
	}

	org := core.GetOrg(c)

	bom, err := h.buildMergedSBOM(c, rel, org.Name)
	if err != nil {
		return echo.NewHTTPError(500, "could not build sbom").WithInternal(err)
	}

	c.Response().Header().Set(echo.HeaderContentType, "application/xml")
	return cdx.NewBOMEncoder(c.Response().Writer, cdx.BOMFileFormatXML).Encode(bom)
}

// VEXJSON currently returns the merged CycloneDX BOM as JSON for compatibility.
func (h *releaseController) VEXJSON(c core.Context) error {
	idParam := core.GetParam(c, "releaseID")
	id, err := uuid.Parse(idParam)
	if err != nil {
		return echo.NewHTTPError(400, "invalid release id")
	}

	rel, err := h.service.ReadRecursive(id)
	if err != nil {
		return echo.NewHTTPError(404, "release not found").WithInternal(err)
	}

	org := core.GetOrg(c)

	bom, err := h.buildMergedVEX(c, rel, org.Name)
	if err != nil {
		return echo.NewHTTPError(500, "could not build vex").WithInternal(err)
	}

	c.Response().Header().Set(echo.HeaderContentType, "application/json")
	return cdx.NewBOMEncoder(c.Response().Writer, cdx.BOMFileFormatJSON).Encode(bom)
}

// VEXXML currently returns the merged CycloneDX BOM as XML for compatibility.
func (h *releaseController) VEXXML(c core.Context) error {
	idParam := core.GetParam(c, "releaseID")
	id, err := uuid.Parse(idParam)
	if err != nil {
		return echo.NewHTTPError(400, "invalid release id")
	}

	rel, err := h.service.ReadRecursive(id)
	if err != nil {
		return echo.NewHTTPError(404, "release not found").WithInternal(err)
	}

	org := core.GetOrg(c)

	bom, err := h.buildMergedVEX(c, rel, org.Name)
	if err != nil {
		return echo.NewHTTPError(500, "could not build vex").WithInternal(err)
	}

	c.Response().Header().Set(echo.HeaderContentType, "application/xml")
	return cdx.NewBOMEncoder(c.Response().Writer, cdx.BOMFileFormatXML).Encode(bom)
}

// buildMergedSBOM builds per-artifact SBOMs and merges them into a single CycloneDX BOM.
func (h *releaseController) buildMergedSBOM(c core.Context, release models.Release, orgName string) (*cdx.BOM, error) {
	var boms []*normalize.CdxBom

	// iterate over items and build SBOM per artifact
	for _, item := range release.Items {
		// load overwritten licenses for the asset version
		overwrittenLicenses, err := h.licenseRiskRepository.GetAllOverwrittenLicensesForAssetVersion(*item.AssetID, *item.AssetVersionName)
		if err != nil {
			return nil, err
		}

		// load components for this artifact (page size large enough to include all components)
		compsPage, err := h.componentRepository.LoadComponentsWithProject(nil, overwrittenLicenses, *item.AssetVersionName, *item.AssetID, core.PageInfo{PageSize: 1000, Page: 1}, "", nil, nil)
		if err != nil {
			return nil, err
		}
		asset, err := h.assetRepository.Read(*item.AssetID)
		if err != nil {
			return nil, err
		}
		// build sbom for this artifact via assetVersionService
		av := models.AssetVersion{AssetID: *item.AssetID, Name: *item.AssetVersionName}

		bom, err := h.assetVersionService.BuildSBOM(asset, av, *item.ArtifactName, orgName, compsPage.Data)
		if err != nil {
			return nil, err
		}

		boms = append(boms, bom)
	}

	if len(boms) == 0 {
		// Use the same merge helper so Components/Dependencies are initialized correctly
		return normalize.MergeCdxBoms(&cdx.Metadata{
			Component: &cdx.Component{
				Type: cdx.ComponentTypeApplication,
				Name: release.Name,
			},
		}), nil
	}

	merged := normalize.MergeCdxBoms(&cdx.Metadata{
		Component: &cdx.Component{
			Type: cdx.ComponentTypeApplication,
			Name: release.Name,
		},
	}, boms...)

	return merged, nil
}

// buildMergedVEX builds per-artifact VeX (CycloneDX with vulnerabilities) and merges them.
func (h *releaseController) buildMergedVEX(c core.Context, release models.Release, orgName string) (*cdx.BOM, error) {
	var boms []*normalize.CdxBom

	for _, item := range release.Items {
		// gather dependency vulns for this artifact (empty artifactName for release-level vulns)
		depVulns, err := h.dependencyVulnRepo.GetDependencyVulnsByAssetVersion(nil, *item.AssetVersionName, *item.AssetID, item.ArtifactName)
		if err != nil {
			return nil, err
		}

		// fetch the asset version - preload the Asset relation
		av, err := h.assetVersionRepository.Read(*item.AssetVersionName, *item.AssetID)
		if err != nil {
			return nil, err
		}
		asset, err := h.assetRepository.Read(av.AssetID)
		if err != nil {
			return nil, err
		}

		bom := h.assetVersionService.BuildVeX(asset, av, *item.ArtifactName, orgName, depVulns)
		if bom != nil {
			boms = append(boms, bom)
		}
	}

	if len(boms) == 0 {
		return normalize.MergeCdxBoms(&cdx.Metadata{
			Component: &cdx.Component{
				Type: cdx.ComponentTypeApplication,
				Name: release.Name,
			},
		}), nil
	}

	merged := normalize.MergeCdxBoms(&cdx.Metadata{
		Component: &cdx.Component{
			Type: cdx.ComponentTypeApplication,
			Name: release.Name,
		},
	}, boms...)

	return merged, nil
}

func (h *releaseController) Read(c core.Context) error {
	idParam := core.GetParam(c, "releaseID")
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
	idParam := core.GetParam(c, "releaseID")
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
