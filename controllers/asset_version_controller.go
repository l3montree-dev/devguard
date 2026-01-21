package controllers

import (
	"archive/zip"
	"bytes"
	"embed"
	"fmt"
	"io"
	"maps"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"time"

	"text/template"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
	"github.com/openvex/go-vex/pkg/vex"
	"golang.org/x/exp/slog"
	"gopkg.in/yaml.v2"
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

	// Find all paths to the component using CdxBom's tree traversal
	return ctx.JSON(200, sbom.FindAllPathsToPURL(pURL))
}

// @Summary Get SBOM in JSON format
// @Tags Asset Versions
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Param artifactName query string false "Artifact name"
// @Success 200 {object} object
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/sbom.json [get]
func (a *AssetVersionController) SBOMJSON(ctx shared.Context) error {
	assetVersion := shared.GetAssetVersion(ctx)
	sbom, err := a.assetVersionService.LoadFullSBOMGraph(assetVersion)
	if err != nil {
		return err
	}
	asset := shared.GetAsset(ctx)
	ctx.Response().Header().Set("Content-Type", "application/json")

	encoder := cdx.NewBOMEncoder(ctx.Response().Writer, cdx.BOMFileFormatJSON).SetPretty(true).SetEscapeHTML(false)

	return encoder.Encode(sbom.ToCycloneDX(ctxToBOMMetadata(ctx, asset)))
}

func (a *AssetVersionController) SBOMXML(ctx shared.Context) error {
	assetVersion := shared.GetAssetVersion(ctx)
	sbom, err := a.assetVersionService.LoadFullSBOMGraph(assetVersion)
	if err != nil {
		return err
	}
	asset := shared.GetAsset(ctx)
	encoder := cdx.NewBOMEncoder(ctx.Response().Writer, cdx.BOMFileFormatXML).SetPretty(true).SetEscapeHTML(false)
	return encoder.Encode(sbom.ToCycloneDX(ctxToBOMMetadata(ctx, asset)))
}

func (a *AssetVersionController) VEXXML(ctx shared.Context) error {
	sbom, err := a.buildVeX(ctx)
	if err != nil {
		return err
	}
	asset := shared.GetAsset(ctx)
	encoder := cdx.NewBOMEncoder(ctx.Response().Writer, cdx.BOMFileFormatXML).SetPretty(true).SetEscapeHTML(false)

	return encoder.Encode(sbom.ToCycloneDX(ctxToBOMMetadata(ctx, asset)))
}

// @Summary Get VEX in JSON format
// @Tags Asset Versions
// @Security CookieAuth
// @Security PATAuth
// @Param organization path string true "Organization slug"
// @Param projectSlug path string true "Project slug"
// @Param assetSlug path string true "Asset slug"
// @Param assetVersionSlug path string true "Asset version slug"
// @Param artifactName query string false "Artifact name"
// @Success 200 {object} object
// @Router /organizations/{organization}/projects/{projectSlug}/assets/{assetSlug}/refs/{assetVersionSlug}/vex.json [get]
func (a *AssetVersionController) VEXJSON(ctx shared.Context) error {
	sbom, err := a.buildVeX(ctx)
	if err != nil {
		return err
	}
	asset := shared.GetAsset(ctx)
	ctx.Response().Header().Set("Content-Type", "application/json")

	encoder := cdx.NewBOMEncoder(ctx.Response().Writer, cdx.BOMFileFormatJSON).SetPretty(true).SetEscapeHTML(false)
	return encoder.Encode(sbom.ToCycloneDX(ctxToBOMMetadata(ctx, asset)))
}

func (a *AssetVersionController) OpenVEXJSON(ctx shared.Context) error {
	vex, err := a.buildOpenVeX(ctx)
	if err != nil {
		return err
	}

	return vex.ToJSON(ctx.Response().Writer)
}

func (a *AssetVersionController) buildOpenVeX(ctx shared.Context) (vex.VEX, error) {
	asset := shared.GetAsset(ctx)
	assetVersion := shared.GetAssetVersion(ctx)
	org := shared.GetOrg(ctx)

	var dependencyVulns []models.DependencyVuln
	artifact, err := shared.MaybeGetArtifact(ctx)
	if err == nil {
		dependencyVulns, err = a.gatherVexInformationIncludingResolvedMarking(assetVersion, &artifact.ArtifactName)
	} else {
		dependencyVulns, err = a.gatherVexInformationIncludingResolvedMarking(assetVersion, nil)
	}

	if err != nil {
		return vex.VEX{}, err
	}

	return a.assetVersionService.BuildOpenVeX(asset, assetVersion, org.Slug, dependencyVulns), nil
}

func (a *AssetVersionController) gatherVexInformationIncludingResolvedMarking(assetVersion models.AssetVersion, artifactName *string) ([]models.DependencyVuln, error) {
	// get all associated dependencyVulns
	dependencyVulns, err := a.dependencyVulnRepository.ListUnfixedByAssetAndAssetVersion(nil, assetVersion.Name, assetVersion.AssetID, artifactName)

	if err != nil {
		return nil, err
	}

	var defaultVulns []models.DependencyVuln
	if assetVersion.DefaultBranch {
		return dependencyVulns, nil
	}

	// get the dependency vulns for the default asset version to check if any are resolved already
	defaultVulns, err = a.dependencyVulnRepository.GetDependencyVulnsByDefaultAssetVersion(nil, assetVersion.AssetID, artifactName)
	if err != nil {
		return nil, err
	}

	// create a map to mark all defaultFixed vulns as fixed in the dependency vulns slice - this will lead to the vex containing a resolved key
	m := make(map[string]bool)
	for _, v := range defaultVulns {
		if v.State == dtos.VulnStateFixed {
			m[fmt.Sprintf("%s/%s", v.CVEID, v.ComponentPurl)] = true
		}
	}

	// mark all vulns as fixed if they are in the map
	for i := range dependencyVulns {
		if m[fmt.Sprintf("%s/%s", dependencyVulns[i].CVEID, dependencyVulns[i].ComponentPurl)] {
			dependencyVulns[i].State = dtos.VulnStateFixed
		}
	}
	return dependencyVulns, nil
}

func (a *AssetVersionController) buildVeX(ctx shared.Context) (*normalize.SBOMGraph, error) {
	project := shared.GetProject(ctx)
	asset := shared.GetAsset(ctx)
	assetVersion := shared.GetAssetVersion(ctx)
	org := shared.GetOrg(ctx)
	artifact, err := shared.MaybeGetArtifact(ctx)

	frontendURL := os.Getenv("FRONTEND_URL")
	if frontendURL == "" {
		return nil, fmt.Errorf("FRONTEND_URL environment variable is not set")
	}

	var dependencyVulns []models.DependencyVuln

	if err != nil {
		dependencyVulns, err = a.gatherVexInformationIncludingResolvedMarking(assetVersion, nil)
	} else {
		dependencyVulns, err = a.gatherVexInformationIncludingResolvedMarking(assetVersion, &artifact.ArtifactName)
	}

	if err != nil {
		return nil, err
	}

	return a.assetVersionService.BuildVeX(frontendURL, org.Name, org.Slug, project.Slug, asset, assetVersion, artifact.ArtifactName, dependencyVulns), nil
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

	_, err := a.componentService.GetAndSaveLicenseInformation(assetVersion, utils.EmptyThenNil(artifactName), true, dtos.UpstreamStateInternal)
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

func (a *AssetVersionController) BuildVulnerabilityReportPDF(ctx shared.Context) error {
	// get the vex from the asset version
	assetVersion := shared.GetAssetVersion(ctx)
	org := shared.GetOrg(ctx)
	project := shared.GetProject(ctx)
	asset := shared.GetAsset(ctx)
	artifact := ctx.QueryParam("artifactName")

	// check if external entity provider
	templateName := "default"
	if asset.ExternalEntityProviderID != nil {
		templateName = strings.ToLower(*asset.ExternalEntityProviderID)
	}
	// read the template
	markdownTemplate, err := resourceFiles.ReadFile("report-templates/" + templateName + "/vulnerability-report/markdown/markdown.gotmpl")
	if err != nil {
		slog.Warn("could not read embedded resource files for vulnerability report template", "error", err)
		templateName = "default"
		markdownTemplate, err = resourceFiles.ReadFile("report-templates/" + templateName + "/vulnerability-report/markdown/markdown.gotmpl")
		if err != nil {
			return echo.NewHTTPError(500, fmt.Sprintf("could not read embedded resource files for vulnerability report template: %v", err))
		}
	}

	// parse the template
	parsedTemplate, err := template.New("markdown").Parse(string(markdownTemplate))
	if err != nil {
		return echo.NewHTTPError(500, fmt.Sprintf("could not parse template: %v", err))
	}

	result := utils.Concurrently(
		func() (any, error) {
			// get the vex from the asset version
			dependencyVulns, err := a.gatherVexInformationIncludingResolvedMarking(assetVersion, utils.EmptyThenNil(artifact))
			if err != nil {
				return nil, err
			}
			frontendURL := os.Getenv("FRONTEND_URL")
			if frontendURL == "" {
				return nil, fmt.Errorf("FRONTEND_URL is not set")
			}

			vex := a.assetVersionService.BuildVeX(frontendURL, org.Name, org.Slug, project.Slug, asset, assetVersion, artifact, dependencyVulns)

			// convert to vulnerability
			result := make([]dtos.VulnerabilityInReport, 0, len(dependencyVulns))

			// create a map of all dependency vulns by vuln ID for easy lookup
			m := make(map[string]models.DependencyVuln)
			for _, dv := range dependencyVulns {
				m[dv.CVEID] = dv
			}

			for v := range vex.Vulnerabilities() {
				dv, ok := m[v.ID]
				if !ok {
					continue
				}

				response := ""
				if v.Analysis != nil && v.Analysis.Response != nil && len(*v.Analysis.Response) > 0 {
					response = string((*v.Analysis.Response)[0])
				}
				result = append(result, dtos.VulnerabilityInReport{
					CVEID:               escapeLatex(v.ID),
					SourceName:          escapeLatex(v.Source.Name),
					SourceURL:           escapeLatex(v.Source.URL),
					AffectedComponent:   escapeLatex(dv.ComponentPurl),
					CveDescription:      escapeLatex(dv.CVE.Description),
					AnalysisState:       escapeLatex(string(v.Analysis.State)),
					AnalysisResponse:    escapeLatex(response),
					AnalysisDetail:      escapeLatex(v.Analysis.Detail),
					AnalysisFirstIssued: escapeLatex(v.Analysis.FirstIssued),
					AnalysisLastUpdated: escapeLatex(v.Analysis.LastUpdated),
					CVSS:                *(*v.Ratings)[0].Score,
					Severity:            escapeLatex(string((*v.Ratings)[0].Severity)),
					Vector:              escapeLatex((*v.Ratings)[0].Vector),
					CVSSMethod:          escapeLatex(string((*v.Ratings)[0].Method)),
					DevguardScore:       *(*v.Ratings)[1].Score,
					DevguardSeverity:    escapeLatex(string((*v.Ratings)[1].Severity)),
					DevguardVector:      escapeLatex((*v.Ratings)[1].Vector),
				})
			}

			return result, nil
		},
		func() (any, error) {
			distribution, err := a.statisticsService.GetArtifactRiskHistory(utils.EmptyThenNil(artifact), assetVersion.Name, assetVersion.AssetID, time.Now(), time.Now()) // only the last entry
			if len(distribution) == 0 {
				return models.Distribution{}, nil
			}

			return distribution[0].Distribution, err
		},
		func() (any, error) {
			return a.statisticsService.GetAverageFixingTime(utils.EmptyThenNil(artifact), assetVersion.Name, assetVersion.AssetID, "critical")
		},
		func() (any, error) {
			return a.statisticsService.GetAverageFixingTime(utils.EmptyThenNil(artifact), assetVersion.Name, assetVersion.AssetID, "high")
		},
		func() (any, error) {
			return a.statisticsService.GetAverageFixingTime(utils.EmptyThenNil(artifact), assetVersion.Name, assetVersion.AssetID, "medium")
		},
		func() (any, error) {
			return a.statisticsService.GetAverageFixingTime(utils.EmptyThenNil(artifact), assetVersion.Name, assetVersion.AssetID, "low")
		},
	)

	if result.HasErrors() {
		return echo.NewHTTPError(500, fmt.Sprintf("could not get average fixing times: %v", result.Errors()))
	}

	vulns := result.GetValue(0).([]dtos.VulnerabilityInReport)
	// group the vulns by severity
	vulnsBySeverity := make(map[string][]dtos.VulnerabilityInReport)
	for _, v := range vulns {
		vulnsBySeverity[v.Severity] = append(vulnsBySeverity[v.Severity], v)
	}

	distribution := result.GetValue(1).(models.Distribution)
	avgCritical := result.GetValue(2).(time.Duration)
	avgHigh := result.GetValue(3).(time.Duration)
	avgMedium := result.GetValue(4).(time.Duration)
	avgLow := result.GetValue(5).(time.Duration)

	markdown := bytes.Buffer{}
	err = parsedTemplate.Execute(&markdown, dtos.VulnerabilityReport{
		AppTitle:           fmt.Sprintf("%s@%s", escapeLatex(asset.Slug), escapeLatex(assetVersion.Slug)),
		AppVersion:         escapeLatex(assetVersion.Name),
		ReportCreationDate: escapeLatex(time.Now().Format("2006-01-02 15:04")),

		AmountCritical: distribution.CriticalCVSS,
		AmountHigh:     distribution.HighCVSS,
		AmountMedium:   distribution.MediumCVSS,
		AmountLow:      distribution.LowCVSS,

		AvgFixTimeCritical: fmt.Sprintf("%d Tage", int(avgCritical.Hours()/24)),
		AvgFixTimeHigh:     fmt.Sprintf("%d Tage", int(avgHigh.Hours()/24)),
		AvgFixTimeMedium:   fmt.Sprintf("%d Tage", int(avgMedium.Hours()/24)),
		AvgFixTimeLow:      fmt.Sprintf("%d Tage", int(avgLow.Hours()/24)),

		CriticalVulns: vulnsBySeverity["critical"],
		HighVulns:     vulnsBySeverity["high"],
		MediumVulns:   vulnsBySeverity["medium"],
		LowVulns:      vulnsBySeverity["low"],
	})
	if err != nil {
		return echo.NewHTTPError(500, fmt.Sprintf("could not execute template: %v", err))
	}

	// create the metadata for the pdf and writing it into a buffer
	metaDataFile := bytes.Buffer{}
	metaData := services.CreateYAMLMetadata(shared.GetOrg(ctx).Name, shared.GetAsset(ctx).Name, shared.GetAssetVersion(ctx).Name)
	parsedYAML, err := yaml.Marshal(metaData)
	if err != nil {
		return err
	}
	_, err = metaDataFile.Write(parsedYAML)
	if err != nil {
		return err
	}

	//build the multipart form data for the http request
	var multipartBuffer bytes.Buffer
	multipartWriter := multipart.NewWriter(&multipartBuffer)
	zipFileWriter, err := multipartWriter.CreateFormFile("file", "archive.zip")
	if err != nil {
		return err
	}
	//Create zip of all the necessary files
	err = buildVulnReportZipInMemory(zipFileWriter, templateName, &metaDataFile, &markdown)
	if err != nil {
		return err
	}

	err = multipartWriter.Close()
	if err != nil {
		return err
	}

	//build the rest of the http request
	pdfAPIURL := os.Getenv("PDF_GENERATION_API")
	if pdfAPIURL == "" {
		return fmt.Errorf("missing env variable 'PDF_GENERATION_API'")
	}
	req, err := http.NewRequest(http.MethodPost, pdfAPIURL, &multipartBuffer)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", multipartWriter.FormDataContentType())

	client := &http.Client{}
	client.Timeout = 10 * time.Minute

	//process http response
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		// return the rendered markdown as well for easier debugging
		ctx.Response().Header().Set(echo.HeaderContentType, "text/markdown ; charset=utf-8")
		ctx.Response().WriteHeader(http.StatusInternalServerError)
		_, _ = io.Copy(ctx.Response().Writer, &markdown)
		return fmt.Errorf("http request to %s was unsuccessful (Code %d)", req.URL, resp.StatusCode)
	}

	// construct the http response header
	// ctx.Response().Header().Set(echo.HeaderContentDisposition, `attachment; filename="sbom.pdf"`)
	ctx.Response().Header().Set(echo.HeaderContentType, "application/pdf")
	ctx.Response().WriteHeader(http.StatusOK)

	_, err = io.Copy(ctx.Response().Writer, resp.Body)

	return err
}

func (a *AssetVersionController) BuildPDFFromSBOM(ctx shared.Context) error {
	assetVersion := shared.GetAssetVersion(ctx)
	sbom, err := a.assetVersionService.LoadFullSBOMGraph(assetVersion)
	if err != nil {
		return err

	}

	asset := shared.GetAsset(ctx)

	//write the components as markdown table to the buffer
	markdownFile := bytes.Buffer{}
	err = services.MarkdownTableFromSBOM(&markdownFile, sbom.ToCycloneDX(ctxToBOMMetadata(ctx, asset)))
	if err != nil {
		return err
	}

	// create the metadata for the pdf and writing it into a buffer
	metaDataFile := bytes.Buffer{}
	metaData := services.CreateYAMLMetadata(shared.GetOrg(ctx).Name, shared.GetAsset(ctx).Name, shared.GetAssetVersion(ctx).Name)
	parsedYAML, err := yaml.Marshal(metaData)
	if err != nil {
		return err
	}
	_, err = metaDataFile.Write(parsedYAML)
	if err != nil {
		return err
	}
	// check if external entity provider
	templateName := "default"
	if asset.ExternalEntityProviderID != nil {
		templateName = strings.ToLower(*asset.ExternalEntityProviderID)
	}

	//build the multipart form data for the http request
	var multipartBuffer bytes.Buffer
	multipartWriter := multipart.NewWriter(&multipartBuffer)
	zipFileWriter, err := multipartWriter.CreateFormFile("file", "archive.zip")
	if err != nil {
		return err
	}
	//Create zip of all the necessary files
	err = buildSbomZipInMemory(zipFileWriter, templateName, &metaDataFile, &markdownFile)
	if err != nil {
		return err
	}

	err = multipartWriter.Close()
	if err != nil {
		return err
	}

	//build the rest of the http request
	pdfAPIURL := os.Getenv("PDF_GENERATION_API")
	if pdfAPIURL == "" {
		return fmt.Errorf("missing env variable 'PDF_GENERATION_API'")
	}
	req, err := http.NewRequest(http.MethodPost, pdfAPIURL, &multipartBuffer)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", multipartWriter.FormDataContentType())

	client := &http.Client{}
	client.Timeout = 10 * time.Minute

	//process http response
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("http request to %s was unsuccessful (Code %d)", req.URL, resp.StatusCode)
	}

	// construct the http response header
	ctx.Response().Header().Set(echo.HeaderContentDisposition, `attachment; filename="sbom.pdf"`)
	ctx.Response().Header().Set(echo.HeaderContentType, "application/pdf")
	ctx.Response().WriteHeader(http.StatusOK)

	_, err = io.Copy(ctx.Response().Writer, resp.Body)

	return err
}

//go:embed report-templates/*
var resourceFiles embed.FS

func buildSbomZipInMemory(writer io.Writer, templateName string, metadata, markdown *bytes.Buffer) error {

	if _, err := resourceFiles.ReadDir(fmt.Sprintf("report-templates/%s/sbom", templateName)); err != nil {
		slog.Warn("could not read embedded resource files for sbom report template", "error", err)
		templateName = "default"
	}

	path := fmt.Sprintf("report-templates/%s/sbom/", templateName)
	zipWriter := zip.NewWriter(writer)
	defer zipWriter.Close()

	// set of all the static files which are embedded
	fileNames := []string{
		path + "template/template.tex", path + "template/assets/background.png", path + "template/assets/qr.png",
		path + "template/assets/font/Inter-Bold.ttf", path + "template/assets/font/Inter-BoldItalic.ttf", path + "template/assets/font/Inter-Italic-VariableFont_opsz,wght.ttf", path + "template/assets/font/Inter-Italic.ttf", path + "template/assets/font/Inter-Regular.ttf", path + "template/assets/font/Inter-VariableFont_opsz,wght.ttf",
	}

	// manually add the two generated files to the zip archive
	zipFileDescriptor, err := zipWriter.Create("template/metadata.yaml")
	if err != nil {
		return err
	}
	_, err = zipFileDescriptor.Write(metadata.Bytes())
	if err != nil {
		zipWriter.Close()
		return err
	}

	zipFileDescriptor, err = zipWriter.Create("markdown/sbom.md")
	if err != nil {
		zipWriter.Close()
		return err
	}
	_, err = zipFileDescriptor.Write(markdown.Bytes())
	if err != nil {
		zipWriter.Close()
		return err
	}

	// then loop over every static file and write it at the respective relative position in the directory
	for _, filePath := range fileNames {
		fileContent, err := resourceFiles.ReadFile(filePath)
		if err != nil {
			zipWriter.Close()
			return err
		}
		localFilePath, _ := strings.CutPrefix(filePath, path)
		zipFileDescriptor, err := zipWriter.Create(localFilePath)
		if err != nil {
			zipWriter.Close()
			return err
		}
		_, err = zipFileDescriptor.Write(fileContent)
		if err != nil {
			zipWriter.Close()
			return err
		}
	}

	//finalize the zip-archive and return it
	zipWriter.Close()
	return nil
}

func buildVulnReportZipInMemory(writer io.Writer, templateName string, metadata, markdown *bytes.Buffer) error {

	if _, err := resourceFiles.ReadDir(fmt.Sprintf("report-templates/%s/vulnerability-report", templateName)); err != nil {
		slog.Warn("could not read embedded resource files for vulnerability report template", "error", err)
		templateName = "default"
	}

	path := fmt.Sprintf("report-templates/%s/vulnerability-report/", templateName)
	zipWriter := zip.NewWriter(writer)
	defer zipWriter.Close()

	// set of all the static files which are embedded
	fileNames := []string{
		path + "template/template.tex", path + "template/assets/background.png", path + "template/assets/qr.png",
		path + "template/assets/font/Inter-Bold.ttf", path + "template/assets/font/Inter-BoldItalic.ttf", path + "template/assets/font/Inter-Italic-VariableFont_opsz,wght.ttf", path + "template/assets/font/Inter-Italic.ttf", path + "template/assets/font/Inter-Regular.ttf", path + "template/assets/font/Inter-VariableFont_opsz,wght.ttf",

		path + "template/assets/by-cvss.png",
	}

	// manually add the two generated files to the zip archive
	zipFileDescriptor, err := zipWriter.Create("template/metadata.yaml")
	if err != nil {
		return err
	}
	_, err = zipFileDescriptor.Write(metadata.Bytes())
	if err != nil {
		zipWriter.Close()
		return err
	}

	zipFileDescriptor, err = zipWriter.Create("markdown/sbom.md")
	if err != nil {
		zipWriter.Close()
		return err
	}
	_, err = zipFileDescriptor.Write(markdown.Bytes())
	if err != nil {
		zipWriter.Close()
		return err
	}

	// then loop over every static file and write it at the respective relative position in the directory
	for _, filePath := range fileNames {
		fileContent, err := resourceFiles.ReadFile(filePath)
		if err != nil {
			zipWriter.Close()
			return err
		}
		localFilePath, _ := strings.CutPrefix(filePath, path)
		zipFileDescriptor, err := zipWriter.Create(localFilePath)
		if err != nil {
			zipWriter.Close()
			return err
		}
		_, err = zipFileDescriptor.Write(fileContent)
		if err != nil {
			zipWriter.Close()
			return err
		}
	}

	//finalize the zip-archive and return it
	zipWriter.Close()
	return nil
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
