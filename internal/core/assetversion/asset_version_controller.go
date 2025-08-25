package assetversion

import (
	"archive/zip"
	"bytes"
	"embed"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"time"

	"text/template"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/normalize"
	"github.com/l3montree-dev/devguard/internal/core/vuln"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/labstack/echo/v4"
	"github.com/openvex/go-vex/pkg/vex"
	"golang.org/x/exp/slog"
	"gopkg.in/yaml.v2"
)

type AssetVersionController struct {
	assetVersionRepository   core.AssetVersionRepository
	assetVersionService      core.AssetVersionService
	dependencyVulnRepository core.DependencyVulnRepository
	componentRepository      core.ComponentRepository
	dependencyVulnService    core.DependencyVulnService
	supplyChainRepository    core.SupplyChainRepository
	licenseRiskRepository    core.LicenseRiskRepository
	componentService         core.ComponentService
	statisticsService        core.StatisticsService
	artifactService          core.ArtifactService
}

func NewAssetVersionController(
	assetVersionRepository core.AssetVersionRepository,
	assetVersionService core.AssetVersionService,
	dependencyVulnRepository core.DependencyVulnRepository,
	componentRepository core.ComponentRepository,
	dependencyVulnService core.DependencyVulnService,
	supplyChainRepository core.SupplyChainRepository,
	licenseRiskRepository core.LicenseRiskRepository,
	componentService core.ComponentService,
	statisticsService core.StatisticsService,
	artifactService core.ArtifactService,
) *AssetVersionController {
	return &AssetVersionController{
		assetVersionRepository:   assetVersionRepository,
		assetVersionService:      assetVersionService,
		dependencyVulnRepository: dependencyVulnRepository,
		componentRepository:      componentRepository,
		dependencyVulnService:    dependencyVulnService,
		supplyChainRepository:    supplyChainRepository,
		licenseRiskRepository:    licenseRiskRepository,
		componentService:         componentService,
		statisticsService:        statisticsService,
		artifactService:          artifactService,
	}
}

func (a *AssetVersionController) Read(ctx core.Context) error {
	assetVersion := core.GetAssetVersion(ctx)
	return ctx.JSON(200, assetVersion)
}

// Function to delete provided asset version
func (a *AssetVersionController) Delete(ctx core.Context) error {
	assetVersion := core.GetAssetVersion(ctx)                  //Get the asset provided in the context / URL
	err := a.assetVersionRepository.Delete(nil, &assetVersion) //Call delete on the returned assetVersion
	if err != nil {
		slog.Error("error when trying to call delete function in assetVersionRepository", "err", err)
		return err
	}
	return ctx.JSON(200, "deleted asset version successfully")
}

func (a *AssetVersionController) GetAssetVersionsByAssetID(ctx core.Context) error {
	asset := core.GetAsset(ctx)

	assetVersions, err := a.assetVersionService.GetAssetVersionsByAssetID(asset.ID)
	if err != nil {
		return err
	}
	return ctx.JSON(200, assetVersions)
}

func (a *AssetVersionController) AffectedComponents(ctx core.Context) error {
	artifactName := ""
	filter := core.GetFilterQuery(ctx)
	for _, f := range filter {
		if f.SQL() == "artifact= ?" {
			artifactName = f.Value().(string)
			break
		}
	}

	assetVersion := core.GetAssetVersion(ctx)
	_, dependencyVulns, err := a.getComponentsAndDependencyVulns(assetVersion, artifactName)
	if err != nil {
		return err
	}

	return ctx.JSON(200, utils.Map(dependencyVulns, func(m models.DependencyVuln) vuln.DependencyVulnDTO {
		return vuln.DependencyVulnToDto(m)
	}))
}

func (a *AssetVersionController) getComponentsAndDependencyVulns(assetVersion models.AssetVersion, artifactName string) ([]models.ComponentDependency, []models.DependencyVuln, error) {
	components, err := a.componentRepository.LoadComponents(nil, assetVersion.Name, assetVersion.AssetID, artifactName)
	if err != nil {
		return nil, nil, err
	}

	dependencyVulns, err := a.dependencyVulnRepository.GetDependencyVulnsByAssetVersion(nil, assetVersion.Name, assetVersion.AssetID, artifactName)
	if err != nil {
		return nil, nil, err
	}
	return components, dependencyVulns, nil
}

func (a *AssetVersionController) DependencyGraph(ctx core.Context) error {
	app := core.GetAssetVersion(ctx)

	artifactName := ctx.QueryParam("artifact-name")

	components, err := a.componentRepository.LoadComponents(nil, app.Name, app.AssetID, artifactName)
	if err != nil {
		return err
	}

	tree := BuildDependencyTree(components)
	if tree.Root.Children == nil {
		tree.Root.Children = make([]*treeNode, 0)
	}

	return ctx.JSON(200, tree)
}

// function to return a graph of all dependencies which lead to the requested pURL
func (a *AssetVersionController) GetDependencyPathFromPURL(ctx core.Context) error {
	assetVersion := core.GetAssetVersion(ctx)

	pURL := ctx.QueryParam("purl")

	artifactName := ctx.QueryParam("artifact-name")

	components, err := a.componentRepository.LoadPathToComponent(nil, assetVersion.Name, assetVersion.AssetID, pURL, artifactName)
	if err != nil {
		return err
	}

	tree := BuildDependencyTree(components)
	if tree.Root.Children == nil {
		tree.Root.Children = make([]*treeNode, 0)
	}

	return ctx.JSON(200, tree)
}

func (a *AssetVersionController) SBOMJSON(ctx core.Context) error {
	sbom, err := a.buildSBOM(ctx)
	if err != nil {
		return err
	}
	return cdx.NewBOMEncoder(ctx.Response().Writer, cdx.BOMFileFormatJSON).Encode(sbom)
}

func (a *AssetVersionController) SBOMXML(ctx core.Context) error {
	sbom, err := a.buildSBOM(ctx)
	if err != nil {
		return err
	}

	return cdx.NewBOMEncoder(ctx.Response().Writer, cdx.BOMFileFormatXML).Encode(sbom)
}

func (a *AssetVersionController) VEXXML(ctx core.Context) error {
	sbom, err := a.buildVeX(ctx)
	if err != nil {
		return err
	}

	return cdx.NewBOMEncoder(ctx.Response().Writer, cdx.BOMFileFormatXML).Encode(sbom)
}

func (a *AssetVersionController) VEXJSON(ctx core.Context) error {
	sbom, err := a.buildVeX(ctx)
	if err != nil {
		return err
	}

	return cdx.NewBOMEncoder(ctx.Response().Writer, cdx.BOMFileFormatJSON).Encode(sbom)
}

func (a *AssetVersionController) OpenVEXJSON(ctx core.Context) error {
	vex, err := a.buildOpenVeX(ctx)
	if err != nil {
		return err
	}

	return vex.ToJSON(ctx.Response().Writer)
}

// UploadVEX accepts a multipart file upload (field name "file") containing an OpenVEX JSON document.
// It updates existing dependency vulnerabilities on the target asset version and creates vuln events.
func (a *AssetVersionController) UploadVEX(ctx core.Context) error {
	var maxSize int64 = 32 * 1024 * 1024 // 32MB
	if err := ctx.Request().ParseMultipartForm(maxSize); err != nil {
		slog.Error("error when parsing data", "err", err)
		return err
	}

	file, _, err := ctx.Request().FormFile("file")
	if err != nil {
		slog.Error("error when forming file", "err", err)
		return err
	}
	defer file.Close()

	// decode CycloneDX VEX (a CycloneDX BOM with vulnerabilities)
	// read file into buffer because BOM decoder may need seekable reader
	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, file); err != nil {
		slog.Error("could not read uploaded file", "err", err)
		return echo.NewHTTPError(400, "could not read vex file").WithInternal(err)
	}

	var bom cdx.BOM
	dec := cdx.NewBOMDecoder(bytes.NewReader(buf.Bytes()), cdx.BOMFileFormatJSON)
	if err := dec.Decode(&bom); err != nil {
		slog.Error("could not decode cyclonedx vex bom", "err", err)
		return echo.NewHTTPError(400, "could not decode vex file as CycloneDX BOM").WithInternal(err)
	}

	asset := core.GetAsset(ctx)
	assetVersion := core.GetAssetVersion(ctx)
	userID := core.GetSession(ctx).GetUserID()

	// load existing dependency vulns for this asset version
	existing, err := a.dependencyVulnRepository.GetDependencyVulnsByAssetVersion(nil, assetVersion.Name, assetVersion.AssetID, "")
	if err != nil {
		slog.Error("could not load dependency vulns", "err", err)
		return echo.NewHTTPError(500, "could not load dependency vulns").WithInternal(err)
	}

	// index by CVE id
	vulnsByCVE := make(map[string][]models.DependencyVuln)
	for _, v := range existing {
		if v.CVE != nil && v.CVE.CVE != "" {
			vulnsByCVE[v.CVE.CVE] = append(vulnsByCVE[v.CVE.CVE], v)
		} else if v.CVEID != nil && *v.CVEID != "" {
			vulnsByCVE[*v.CVEID] = append(vulnsByCVE[*v.CVEID], v)
		}
	}

	updated := 0
	notFound := 0

	// helper to extract cve id from CycloneDX vulnerability id or source url
	extractCVE := func(s string) string {
		if s == "" {
			return ""
		}
		s = strings.TrimSpace(s)
		if strings.HasPrefix(s, "http") {
			parts := strings.Split(s, "/")
			return parts[len(parts)-1]
		}
		return s
	}

	// iterate vulnerabilities in the CycloneDX BOM
	if bom.Vulnerabilities != nil {
		for _, vuln := range *bom.Vulnerabilities {
			cveID := extractCVE(vuln.ID)
			if cveID == "" && vuln.Source != nil && vuln.Source.URL != "" {
				cveID = extractCVE(vuln.Source.URL)
			}
			if cveID == "" {
				notFound++
				continue
			}

			cveID = strings.ToUpper(strings.TrimSpace(cveID))

			vlist, ok := vulnsByCVE[cveID]
			if !ok || len(vlist) == 0 {
				notFound++
				continue
			}

			statusType := normalize.MapCDXToStatus(vuln.Analysis)
			if statusType == "" {
				// skip unknown/unspecified statuses
				continue
			}

			justification := "[VEX-Upload]"
			if vuln.Analysis != nil && vuln.Analysis.Detail != "" {
				justification = fmt.Sprintf("[VEX-Upload] %s", vuln.Analysis.Detail)
			}

			for i := range vlist {
				_, err := a.dependencyVulnService.UpdateDependencyVulnState(nil, asset.ID, userID, &vlist[i], statusType, justification, models.MechanicalJustificationType(""), assetVersion.Name) // mechanical justification is not part of cyclonedx spec.
				if err != nil {
					slog.Error("could not update dependency vuln state", "err", err, "cve", cveID)
					continue
				}
				updated++
			}
		}
	}

	return ctx.JSON(200, map[string]int{"updated": updated, "notFound": notFound})
}

func (a *AssetVersionController) buildSBOM(ctx core.Context) (*cdx.BOM, error) {

	assetVersion := core.GetAssetVersion(ctx)
	org := core.GetOrg(ctx)
	// check for version query param
	version := ctx.QueryParam("version")
	if version == "" {
		version = models.NoVersion
	} else {
		var err error
		version, err = normalize.SemverFix(version)
		if err != nil {
			return nil, err
		}
	}

	filter := core.GetFilterQuery(ctx)

	overwrittenLicenses, err := a.licenseRiskRepository.GetAllOverwrittenLicensesForAssetVersion(assetVersion.AssetID, assetVersion.Name)
	if err != nil {
		return nil, err
	}

	components, err := a.componentRepository.LoadComponentsWithProject(nil, overwrittenLicenses, assetVersion.Name, assetVersion.AssetID, core.PageInfo{
		PageSize: 1000,
		Page:     1,
	}, "", filter, nil)
	if err != nil {
		return nil, err
	}

	return a.assetVersionService.BuildSBOM(assetVersion, version, org.Name, components.Data)
}

func (a *AssetVersionController) buildOpenVeX(ctx core.Context) (vex.VEX, error) {
	asset := core.GetAsset(ctx)
	assetVersion := core.GetAssetVersion(ctx)
	org := core.GetOrg(ctx)

	artifactName := ctx.QueryParam("artifact-name")

	dependencyVulns, err := a.gatherVexInformationIncludingResolvedMarking(assetVersion, artifactName)
	if err != nil {
		return vex.VEX{}, err
	}

	return a.assetVersionService.BuildOpenVeX(asset, assetVersion, org.Slug, dependencyVulns), nil
}

func (a *AssetVersionController) gatherVexInformationIncludingResolvedMarking(assetVersion models.AssetVersion, artifactName string) ([]models.DependencyVuln, error) {

	// get all associated dependencyVulns
	dependencyVulns, err := a.dependencyVulnRepository.ListUnfixedByAssetAndAssetVersionAndArtifactName(assetVersion.Name, assetVersion.AssetID, artifactName)
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
		if v.State == models.VulnStateFixed {
			m[v.ID] = true
		}
	}

	// mark all vulns as fixed if they are in the map
	for i := range dependencyVulns {
		if _, ok := m[dependencyVulns[i].ID]; ok {
			dependencyVulns[i].State = models.VulnStateFixed
		}
	}
	return dependencyVulns, nil
}

func (a *AssetVersionController) buildVeX(ctx core.Context) (*cdx.BOM, error) {
	asset := core.GetAsset(ctx)
	assetVersion := core.GetAssetVersion(ctx)
	org := core.GetOrg(ctx)
	artifactName := ctx.QueryParam("artifact-name")

	dependencyVulns, err := a.gatherVexInformationIncludingResolvedMarking(assetVersion, artifactName)
	if err != nil {
		return nil, err
	}

	return a.assetVersionService.BuildVeX(asset, assetVersion, org.Name, dependencyVulns), nil
}

func (a *AssetVersionController) Metrics(ctx core.Context) error {
	assetVersion := core.GetAssetVersion(ctx)
	//artifactName := ctx.QueryParam("artifact-name")
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

	return ctx.JSON(200, assetMetrics{
		EnabledContainerScanning:       enabledContainerScanning,
		EnabledSCA:                     enabledSca,
		EnabledImageSigning:            enabledImageSigning,
		VerifiedSupplyChainsPercentage: verifiedSupplyChainsPercentage,
	})
}

// RefetchLicenses forces re-fetching license information for all components of the current asset version
func (a *AssetVersionController) RefetchLicenses(ctx core.Context) error {
	assetVersion := core.GetAssetVersion(ctx)
	scannerID := ctx.QueryParam("scanner")

	updated, err := a.componentService.RefreshAllLicenses(assetVersion, scannerID)
	if err != nil {
		return err
	}

	return ctx.JSON(200, updated)
}

type yamlVars struct {
	DocumentTitle    string `yaml:"document_title"`
	PrimaryColor     string `yaml:"primary_color"`
	Version          string `yaml:"version"`
	TimeOfGeneration string `yaml:"generation_date"`
	ProjectTitle1    string `yaml:"app_title_part_one"`
	ProjectTitle2    string `yaml:"app_title_part_two"`
	OrganizationName string `yaml:"organization_name"`
	Integrity        string `yaml:"integrity"`
}

type yamlMetadata struct {
	Vars yamlVars `yaml:"metadata_vars"`
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

func (a *AssetVersionController) BuildVulnerabilityReportPDF(ctx core.Context) error {
	// get the vex from the asset version
	assetVersion := core.GetAssetVersion(ctx)
	org := core.GetOrg(ctx)
	asset := core.GetAsset(ctx)
	scannerID := ctx.QueryParam("scanner")

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
			dependencyVulns, err := a.gatherVexInformationIncludingResolvedMarking(assetVersion, scannerID)
			if err != nil {
				return nil, err
			}
			vex := a.assetVersionService.BuildVeX(asset, assetVersion, org.Name, dependencyVulns)

			// convert to vulnerability
			result := make([]VulnerabilityInReport, 0, len(dependencyVulns))

			// create a map of all dependency vulns by vuln ID for easy lookup
			m := make(map[string]models.DependencyVuln)
			for _, dv := range dependencyVulns {
				m[*dv.CVEID] = dv
			}

			for _, v := range *vex.Vulnerabilities {
				dv, ok := m[v.ID]
				if !ok {
					continue
				}

				response := ""
				if v.Analysis != nil && v.Analysis.Response != nil && len(*v.Analysis.Response) > 0 {
					response = string((*v.Analysis.Response)[0])
				}
				result = append(result, VulnerabilityInReport{
					CVEID:               escapeLatex(v.ID),
					SourceName:          escapeLatex(v.Source.Name),
					SourceURL:           escapeLatex(v.Source.URL),
					AffectedComponent:   escapeLatex(*dv.ComponentPurl),
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
			distribution, err := a.statisticsService.GetAssetVersionCvssDistribution(assetVersion.Name, assetVersion.AssetID, asset.Name)
			return distribution, err
		},
		func() (any, error) {
			return a.statisticsService.GetAverageFixingTime(assetVersion.Name, assetVersion.AssetID, "critical")
		},
		func() (any, error) {
			return a.statisticsService.GetAverageFixingTime(assetVersion.Name, assetVersion.AssetID, "high")
		},
		func() (any, error) {
			return a.statisticsService.GetAverageFixingTime(assetVersion.Name, assetVersion.AssetID, "medium")
		},
		func() (any, error) {
			return a.statisticsService.GetAverageFixingTime(assetVersion.Name, assetVersion.AssetID, "low")
		},
	)

	if result.HasErrors() {
		return echo.NewHTTPError(500, fmt.Sprintf("could not get average fixing times: %v", result.Errors()))
	}

	vulns := result.GetValue(0).([]VulnerabilityInReport)
	// group the vulns by severity
	vulnsBySeverity := make(map[string][]VulnerabilityInReport)
	for _, v := range vulns {
		vulnsBySeverity[v.Severity] = append(vulnsBySeverity[v.Severity], v)
	}

	distribution := result.GetValue(1).(models.AssetRiskDistribution)
	avgCritical := result.GetValue(2).(time.Duration)
	avgHigh := result.GetValue(3).(time.Duration)
	avgMedium := result.GetValue(4).(time.Duration)
	avgLow := result.GetValue(5).(time.Duration)

	markdown := bytes.Buffer{}
	err = parsedTemplate.Execute(&markdown, VulnerabilityReport{
		AppTitle:           fmt.Sprintf("%s@%s", escapeLatex(asset.Slug), escapeLatex(assetVersion.Slug)),
		AppVersion:         escapeLatex(assetVersion.Name),
		ReportCreationDate: escapeLatex(time.Now().Format("2006-01-02 15:04")),

		AmountCritical: distribution.Critical,
		AmountHigh:     distribution.High,
		AmountMedium:   distribution.Medium,
		AmountLow:      distribution.Low,

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
	metaData := createYAMLMetadata(core.GetOrg(ctx).Name, core.GetAsset(ctx).Name, core.GetAssetVersion(ctx).Name)
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

func (a *AssetVersionController) BuildPDFFromSBOM(ctx core.Context) error {

	//build the SBOM of this asset version
	bom, err := a.buildSBOM(ctx)
	if err != nil {
		return err
	}

	//write the components as markdown table to the buffer
	markdownFile := bytes.Buffer{}
	err = markdownTableFromSBOM(&markdownFile, bom)
	if err != nil {
		return err
	}

	// create the metadata for the pdf and writing it into a buffer
	metaDataFile := bytes.Buffer{}
	metaData := createYAMLMetadata(core.GetOrg(ctx).Name, core.GetAsset(ctx).Name, core.GetAssetVersion(ctx).Name)
	parsedYAML, err := yaml.Marshal(metaData)
	if err != nil {
		return err
	}
	_, err = metaDataFile.Write(parsedYAML)
	if err != nil {
		return err
	}
	// check if external entity provider
	asset := core.GetAsset(ctx)
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

func (a *AssetVersionController) ListArtifacts(ctx core.Context) error {

	assetID := core.GetAsset(ctx).ID
	assetVersion := core.GetAssetVersion(ctx)

	// get the artifacts for this asset version
	artifacts, err := a.artifactService.GetArtifactNamesByAssetIDAndAssetVersionName(assetID, assetVersion.Name)
	if err != nil {
		return echo.NewHTTPError(500, "could not get artifacts").WithInternal(err)
	}

	return ctx.JSON(200, artifacts)
}
