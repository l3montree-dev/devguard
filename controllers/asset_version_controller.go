package controllers

import (
	"maps"
	"net/url"
	"strings"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
	"golang.org/x/exp/slog"
)

type AssetVersionController struct {
	assetVersionRepository   shared.AssetVersionRepository
	assetVersionService      shared.AssetVersionService
	dependencyVulnRepository shared.DependencyVulnRepository
	componentRepository      shared.ComponentRepository
	supplyChainRepository    shared.SupplyChainRepository
	componentService         shared.ComponentService
	statisticsService        shared.StatisticsService
	artifactService          shared.ArtifactService
	dependencyVulnService    shared.DependencyVulnService
}

func NewAssetVersionController(
	assetVersionRepository shared.AssetVersionRepository,
	assetVersionService shared.AssetVersionService,
	dependencyVulnRepository shared.DependencyVulnRepository,
	componentRepository shared.ComponentRepository,
	supplyChainRepository shared.SupplyChainRepository,
	componentService shared.ComponentService,
	statisticsService shared.StatisticsService,
	artifactService shared.ArtifactService,
	dependencyVulnService shared.DependencyVulnService,

) *AssetVersionController {
	return &AssetVersionController{
		assetVersionRepository:   assetVersionRepository,
		assetVersionService:      assetVersionService,
		dependencyVulnRepository: dependencyVulnRepository,
		componentRepository:      componentRepository,
		supplyChainRepository:    supplyChainRepository,
		componentService:         componentService,
		statisticsService:        statisticsService,
		artifactService:          artifactService,
		dependencyVulnService:    dependencyVulnService,
	}
}

// @Summary Get asset version details
// @Tags Asset Versions
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Success 200 {object} models.AssetVersion
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug} [get]
func (a *AssetVersionController) Read(ctx shared.Context) error {
	assetVersion := shared.GetAssetVersion(ctx)
	return ctx.JSON(200, assetVersion)
}

// @Summary Create asset version
// @Tags Asset Versions
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param body body object{name=string,tag=bool,defaultBranch=bool} true "Request body"
// @Success 201 {object} models.AssetVersion
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs [post]
func (a *AssetVersionController) Create(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)

	type requestBody struct {
		Name          string `json:"name"`
		Tag           bool   `json:"tag"`
		DefaultBranch bool   `json:"defaultBranch"`
	}

	var body requestBody
	if err := ctx.Bind(&body); err != nil {
		return err
	}

	var defaultBranch *string
	if body.DefaultBranch {
		defaultBranch = &body.Name
	}

	assetVersion, err := a.assetVersionRepository.FindOrCreate(body.Name, asset.ID, body.Tag, defaultBranch)
	if err != nil {
		return err
	}
	return ctx.JSON(201, assetVersion)
}

// @Summary Delete asset version
// @Tags Asset Versions
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Success 200
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug} [delete]
func (a *AssetVersionController) Delete(ctx shared.Context) error {
	assetVersion := shared.GetAssetVersion(ctx)                //Get the asset provided in the context / URL
	err := a.assetVersionRepository.Delete(nil, &assetVersion) //Call delete on the returned assetVersion
	if err != nil {
		slog.Error("error when trying to call delete function in assetVersionRepository", "err", err)
		return err
	}
	return ctx.JSON(200, "deleted asset version successfully")
}

// @Summary List asset versions
// @Tags Asset Versions
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Success 200 {array} models.AssetVersion
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs [get]
func (a *AssetVersionController) GetAssetVersionsByAssetID(ctx shared.Context) error {
	asset := shared.GetAsset(ctx)

	assetVersions, err := a.assetVersionService.GetAssetVersionsByAssetID(asset.ID)
	if err != nil {
		return err
	}
	return ctx.JSON(200, assetVersions)
}

func (a *AssetVersionController) AffectedComponents(ctx shared.Context) error {
	artifactName := ctx.QueryParam("artifactName")

	assetVersion := shared.GetAssetVersion(ctx)
	_, dependencyVulns, err := a.getComponentsAndDependencyVulns(assetVersion, utils.EmptyThenNil(artifactName))
	if err != nil {
		return err
	}

	return ctx.JSON(200, utils.Map(dependencyVulns, func(m models.DependencyVuln) dtos.DependencyVulnDTO {
		return transformer.DependencyVulnToDTO(m)
	}))
}

func (a *AssetVersionController) getComponentsAndDependencyVulns(assetVersion models.AssetVersion, artifactName *string) ([]models.ComponentDependency, []models.DependencyVuln, error) {
	components, err := a.componentRepository.LoadComponents(nil, assetVersion.Name, assetVersion.AssetID, artifactName)
	if err != nil {
		return nil, nil, err
	}

	dependencyVulns, err := a.dependencyVulnRepository.ListUnfixedByAssetAndAssetVersion(nil, assetVersion.Name, assetVersion.AssetID, artifactName)
	if err != nil {
		return nil, nil, err
	}
	return components, dependencyVulns, nil
}

func (a *AssetVersionController) DependencyGraph(ctx shared.Context) error {
	app := shared.GetAssetVersion(ctx)

	sbom, err := a.assetVersionService.LoadFullSBOMGraph(app)
	if err != nil {
		return echo.NewHTTPError(500, "could not build sbom").WithInternal(err)
	}

	artifactName := ctx.QueryParam("artifactName")
	if artifactName != "" {
		artifactName, _ := url.PathUnescape(artifactName)
		err = sbom.ScopeToArtifact(artifactName)
		if err != nil {
			return echo.NewHTTPError(500, "could not scope sbom to artifact").WithInternal(err)
		}
	}

	minimalTree := sbom.ToMinimalTree()

	return ctx.JSON(200, minimalTree)
}

// function to return a graph of all dependencies which lead to the requested pURL
func (a *AssetVersionController) GetDependencyPathFromPURL(ctx shared.Context) error {

	assetVersion := shared.GetAssetVersion(ctx)

	pURL := ctx.QueryParam("purl")
	artifactName := ctx.QueryParam("artifactName")

	// Load the full SBOM and find paths using in-memory tree traversal
	sbom, err := a.assetVersionService.LoadFullSBOMGraph(assetVersion)
	if err != nil {
		return echo.NewHTTPError(500, "could not load sbom").WithInternal(err)
	}

	// If artifact name is specified, extract just that artifact's subtree
	if artifactName != "" {
		err = sbom.ScopeToArtifact(artifactName)
		if err != nil {
			return echo.NewHTTPError(500, "could not scope sbom to artifact").WithInternal(err)
		}
	}

	// Return minimal tree structure with only paths leading to the target PURL
	return ctx.JSON(200, sbom.FindAllComponentOnlyPathsToPURL(pURL, 12))
}

// @Summary Get asset version metrics
// @Tags Asset Versions
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Param artifactName query string false "Artifact name"
// @Success 200 {object} object
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/metrics [get]
func (a *AssetVersionController) Metrics(ctx shared.Context) error {
	assetVersion := shared.GetAssetVersion(ctx)
	//artifactName := ctx.QueryParam("artifact")
	// get the latest events of this asset per scan type
	/* 	err := a.assetVersionRepository.GetDB(nil).Table("dependency_vulns").Select("DISTINCT scanner_ids").Where("asset_version_name  = ? AND asset_id = ?", assetVersion.Name, assetVersion.AssetID).Pluck("scanner_ids", &scannerIDs).Error

	   	if err != nil {
	   		return err
	   	}
	*/
	var enabledSca = false
	var enabledContainerScanning = false
	var enabledImageSigning = assetVersion.SigningPubKey != nil

	//TODO
	/* 	for _, scannerID := range scannerIDs {
	   		if scannerID == "github.com/l3montree-dev/devguard/cmd/devguard-scanner/sca" {
	   			enabledSca = true
	   		}
	   		if scannerID == "github.com/l3montree-dev/devguard/cmd/devguard-scanner/container-scanning" {
	   			enabledContainerScanning = true
	   		}
	   	}
	*/
	// check if in-toto is enabled
	verifiedSupplyChainsPercentage, err := a.supplyChainRepository.PercentageOfVerifiedSupplyChains(assetVersion.Name, assetVersion.AssetID)
	if err != nil {
		return err
	}

	return ctx.JSON(200, dtos.AssetMetrics{
		EnabledContainerScanning:       enabledContainerScanning,
		EnabledSCA:                     enabledSca,
		EnabledImageSigning:            enabledImageSigning,
		VerifiedSupplyChainsPercentage: verifiedSupplyChainsPercentage,
	})
}

// RefetchLicenses forces re-fetching license information for all components of the current asset version
func (a *AssetVersionController) RefetchLicenses(ctx shared.Context) error {
	assetVersion := shared.GetAssetVersion(ctx)
	artifactName := ctx.Param("artifactName")

	_, err := a.componentService.GetAndSaveLicenseInformation(nil, assetVersion, utils.EmptyThenNil(artifactName), true)
	if err != nil {
		return err
	}

	return ctx.JSON(200, map[string]any{
		"message": "refetched licenses for all components",
	})
}

var latexReplacer = strings.NewReplacer(
	"\\", "\\textbackslash{}",
	"&", "\\&",
	"%", "\\%",
	"$", "\\$",
	"#", "\\#",
	"_", "\\_",
	"{", "\\{",
	"}", "\\}",
	"~", "\\textasciitilde{}",
	"^", "\\textasciicircum{}",
)

func escapeLatex(input string) string {

	return latexReplacer.Replace(input)
}

func (a *AssetVersionController) ListArtifacts(ctx shared.Context) error {

	assetID := shared.GetAsset(ctx).ID
	assetVersion := shared.GetAssetVersion(ctx)

	// get the artifacts for this asset version
	artifacts, err := a.artifactService.GetArtifactsByAssetIDAndAssetVersionName(assetID, assetVersion.Name)
	if err != nil {
		return echo.NewHTTPError(500, "could not get artifacts").WithInternal(err)
	}

	return ctx.JSON(200, artifacts)
}

func (a *AssetVersionController) MakeDefault(ctx shared.Context) error {
	assetVersion := shared.GetAssetVersion(ctx)

	err := a.assetVersionRepository.UpdateAssetDefaultBranch(assetVersion.AssetID, assetVersion.Name)
	if err != nil {
		return err
	}
	assetVersion.DefaultBranch = true
	return ctx.JSON(200, assetVersion)
}
func extractInformationSourceFromPurl(purl string) dtos.InformationSourceDTO {

	InformationSourcesDTO := dtos.InformationSourceDTO{}
	if strings.HasPrefix(purl, "vex:") {
		InformationSourcesDTO.Type = "vex"
		InformationSourcesDTO.URL = strings.TrimPrefix(purl, "vex:")
	} else if strings.HasPrefix(purl, "sbom:") {
		InformationSourcesDTO.Type = "sbom"
		InformationSourcesDTO.URL = strings.TrimPrefix(purl, "sbom:")
	} else if strings.HasPrefix(purl, "csaf:") {
		InformationSourcesDTO.Type = "csaf"
		p := strings.TrimPrefix(purl, "csaf:")
		parts := strings.SplitN(p, ":http", 2)
		if len(parts) > 1 {
			InformationSourcesDTO.Purl = parts[0]
			InformationSourcesDTO.URL = "http" + parts[1]
		} else {
			InformationSourcesDTO.URL = p
		}
	} else {
		InformationSourcesDTO.URL = purl
	}
	return InformationSourcesDTO
}

func (a *AssetVersionController) ReadRootNodes(ctx shared.Context) error {
	// get all artifacts from the asset version
	assetVersion := shared.GetAssetVersion(ctx)
	// get the artifacts for this asset version
	artifacts, err := a.artifactService.GetArtifactsByAssetIDAndAssetVersionName(assetVersion.AssetID, assetVersion.Name)
	if err != nil {
		return echo.NewHTTPError(500, "could not read artifacts").WithInternal(err)
	}
	// fetch all root nodes
	errgroup := utils.ErrGroup[map[string][]dtos.InformationSourceDTO](10)
	for _, artifact := range artifacts {
		errgroup.Go(func() (map[string][]dtos.InformationSourceDTO, error) {
			rootNodes, err := a.componentService.FetchInformationSources(&artifact)
			if err != nil {
				return nil, err
			}
			return map[string][]dtos.InformationSourceDTO{
				artifact.ArtifactName: utils.UniqBy(utils.Map(rootNodes, func(
					el models.ComponentDependency,
				) dtos.InformationSourceDTO {
					return extractInformationSourceFromPurl(el.DependencyID)
				}), func(s dtos.InformationSourceDTO) dtos.InformationSourceDTO {
					return s
				}),
			}, nil
		})
	}
	results, err := errgroup.WaitAndCollect()
	if err != nil {
		return echo.NewHTTPError(500, "could not fetch root nodes of artifacts").WithInternal(err)
	}

	result := make(map[string][]dtos.InformationSourceDTO)
	// merge the maps
	for _, r := range results {
		maps.Copy(result, r)
	}

	return ctx.JSON(200, result)
}
