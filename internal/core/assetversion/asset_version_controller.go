package assetversion

import (
	"archive/zip"
	"bytes"
	"embed"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

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
	assetVersionRepository     core.AssetVersionRepository
	assetVersionService        core.AssetVersionService
	dependencyVulnRepository   core.DependencyVulnRepository
	componentRepository        core.ComponentRepository
	dependencyVulnService      core.DependencyVulnService
	supplyChainRepository      core.SupplyChainRepository
	licenseOverwriteRepository core.LicenseOverwriteRepository
}

func NewAssetVersionController(
	assetVersionRepository core.AssetVersionRepository,
	assetVersionService core.AssetVersionService,
	dependencyVulnRepository core.DependencyVulnRepository,
	componentRepository core.ComponentRepository,
	dependencyVulnService core.DependencyVulnService,
	supplyChainRepository core.SupplyChainRepository,
	licenseOverwriteRepository core.LicenseOverwriteRepository,
) *AssetVersionController {
	return &AssetVersionController{
		assetVersionRepository:     assetVersionRepository,
		assetVersionService:        assetVersionService,
		dependencyVulnRepository:   dependencyVulnRepository,
		componentRepository:        componentRepository,
		dependencyVulnService:      dependencyVulnService,
		supplyChainRepository:      supplyChainRepository,
		licenseOverwriteRepository: licenseOverwriteRepository,
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
	scannerID := ctx.QueryParam("scanner")
	if scannerID == "" {
		return echo.NewHTTPError(400, "scanner query param is required")
	}

	assetVersion := core.GetAssetVersion(ctx)
	_, dependencyVulns, err := a.getComponentsAndDependencyVulns(assetVersion, scannerID)
	if err != nil {
		return err
	}

	return ctx.JSON(200, utils.Map(dependencyVulns, func(m models.DependencyVuln) vuln.DependencyVulnDTO {
		return vuln.DependencyVulnToDto(m)
	}))
}

func (a *AssetVersionController) getComponentsAndDependencyVulns(assetVersion models.AssetVersion, scannerID string) ([]models.ComponentDependency, []models.DependencyVuln, error) {
	components, err := a.componentRepository.LoadComponents(nil, assetVersion.Name, assetVersion.AssetID, scannerID)
	if err != nil {
		return nil, nil, err
	}

	dependencyVulns, err := a.dependencyVulnRepository.GetDependencyVulnsByAssetVersion(nil, assetVersion.Name, assetVersion.AssetID, scannerID)
	if err != nil {
		return nil, nil, err
	}
	return components, dependencyVulns, nil
}

func (a *AssetVersionController) DependencyGraph(ctx core.Context) error {
	app := core.GetAssetVersion(ctx)

	scannerID := ctx.QueryParam("scanner")
	if scannerID == "" {
		return echo.NewHTTPError(400, "scanner query param is required")
	}

	components, err := a.componentRepository.LoadComponents(nil, app.Name, app.AssetID, scannerID)
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

	scannerID := ctx.QueryParam("scanner")
	pURL := ctx.QueryParam("purl")

	if scannerID == "" {
		return echo.NewHTTPError(400, "scanner query param is required")
	}

	components, err := a.componentRepository.LoadPathToComponent(nil, assetVersion.Name, assetVersion.AssetID, pURL, scannerID)
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

	scannerID := ctx.QueryParam("scanner")

	overwrittenLicenses, err := a.licenseOverwriteRepository.GetAllOverwritesForOrganization(org.ID)
	if err != nil {
		return nil, err
	}

	components, err := a.componentRepository.LoadComponentsWithProject(nil, overwrittenLicenses, assetVersion.Name, assetVersion.AssetID, scannerID, core.PageInfo{
		PageSize: 1000,
		Page:     1,
	}, "", nil, nil)
	if err != nil {
		return nil, err
	}

	return a.assetVersionService.BuildSBOM(assetVersion, version, org.Name, components.Data), nil
}

func (a *AssetVersionController) buildOpenVeX(ctx core.Context) (vex.VEX, error) {
	asset := core.GetAsset(ctx)
	assetVersion := core.GetAssetVersion(ctx)
	org := core.GetOrg(ctx)

	scannerID := ctx.QueryParam("scanner")

	dependencyVulns, err := a.gatherVexInformationIncludingResolvedMarking(assetVersion, scannerID)
	if err != nil {
		return vex.VEX{}, err
	}

	return a.assetVersionService.BuildOpenVeX(asset, assetVersion, org.Slug, dependencyVulns), nil
}

func (a *AssetVersionController) gatherVexInformationIncludingResolvedMarking(assetVersion models.AssetVersion, scannerID string) ([]models.DependencyVuln, error) {
	// url decode the scanner
	if scannerID != "" {
		var err error
		scannerID, err = url.QueryUnescape(scannerID)
		if err != nil {
			return nil, err
		}
	}

	// get all associated dependencyVulns
	dependencyVulns, err := a.dependencyVulnRepository.ListUnfixedByAssetAndAssetVersionAndScannerID(assetVersion.Name, assetVersion.AssetID, scannerID)
	if err != nil {
		return nil, err
	}

	var defaultVulns []models.DependencyVuln
	if assetVersion.DefaultBranch {
		return dependencyVulns, nil
	}

	// get the dependency vulns for the default asset version to check if any are resolved already
	defaultVulns, err = a.dependencyVulnRepository.GetDependencyVulnsByDefaultAssetVersion(nil, assetVersion.AssetID, scannerID)
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
	scannerID := ctx.QueryParam("scanner")

	dependencyVulns, err := a.gatherVexInformationIncludingResolvedMarking(assetVersion, scannerID)
	if err != nil {
		return nil, err
	}

	return a.assetVersionService.BuildVeX(asset, assetVersion, org.Name, dependencyVulns), nil
}

func (a *AssetVersionController) Metrics(ctx core.Context) error {
	assetVersion := core.GetAssetVersion(ctx)
	scannerIDs := []string{}
	// get the latest events of this asset per scan type
	err := a.assetVersionRepository.GetDB(nil).Table("dependency_vulns").Select("DISTINCT scanner_ids").Where("asset_version_name  = ? AND asset_id = ?", assetVersion.Name, assetVersion.AssetID).Pluck("scanner_ids", &scannerIDs).Error

	if err != nil {
		return err
	}

	var enabledSca = false
	var enabledContainerScanning = false
	var enabledImageSigning = assetVersion.SigningPubKey != nil

	for _, scannerID := range scannerIDs {
		if scannerID == "github.com/l3montree-dev/devguard/cmd/devguard-scanner/sca" {
			enabledSca = true
		}
		if scannerID == "github.com/l3montree-dev/devguard/cmd/devguard-scanner/container-scanning" {
			enabledContainerScanning = true
		}
	}

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
	metaData := createYAMLMetadata(core.GetOrg(ctx).Name, core.GetProject(ctx).Name, core.GetAssetVersion(ctx).Name)
	parsedYAML, err := yaml.Marshal(metaData)
	if err != nil {
		return err
	}
	_, err = metaDataFile.Write(parsedYAML)
	if err != nil {
		return err
	}

	//Create zip of all the necessary files
	zipBomb, err := buildZIPInMemory(&metaDataFile, &markdownFile)
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
	_, err = io.Copy(zipFileWriter, zipBomb)
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

	//create the pdf and copy the data from the response to it
	pdf := bytes.Buffer{}
	_, err = io.Copy(&pdf, resp.Body)
	if err != nil {
		return err
	}

	// construct the http response header
	ctx.Response().Header().Set(echo.HeaderContentDisposition, `attachment; filename="sbom.pdf"`)
	ctx.Response().Header().Set(echo.HeaderContentType, "application/pdf")
	ctx.Response().WriteHeader(http.StatusOK)

	_, err = ctx.Response().Write(pdf.Bytes())
	return err
}

//go:embed report-templates/*
var ressourceFiles embed.FS

func buildZIPInMemory(metadata, markdown *bytes.Buffer) (*bytes.Buffer, error) {

	path := "report-templates/default/sbom/"
	archive := bytes.Buffer{}
	zipWriter := zip.NewWriter(&archive)
	defer zipWriter.Close()

	// set of all the static files which are embedded
	fileNames := []string{
		path + "markdown/abkuerzungen.yaml", path + "markdown/glossar.yaml",
		path + "template/template.tex", path + "template/assets/background.png", path + "template/assets/qr.png",
		path + "template/assets/font/Inter-Bold.ttf", path + "template/assets/font/Inter-BoldItalic.ttf", path + "template/assets/font/Inter-Italic-VariableFont_opsz,wght.ttf", path + "template/assets/font/Inter-Italic.ttf", path + "template/assets/font/Inter-Regular.ttf", path + "template/assets/font/Inter-VariableFont_opsz,wght.ttf",
	}

	// manually add the two generated files to the zip archive
	zipFileDescriptor, err := zipWriter.Create("template/metadata.yaml")
	if err != nil {
		return &archive, err
	}
	_, err = zipFileDescriptor.Write(metadata.Bytes())
	if err != nil {
		zipWriter.Close()
		return &archive, err
	}

	zipFileDescriptor, err = zipWriter.Create("markdown/sbom.md")
	if err != nil {
		zipWriter.Close()
		return &archive, err
	}
	_, err = zipFileDescriptor.Write(markdown.Bytes())
	if err != nil {
		zipWriter.Close()
		return &archive, err
	}

	// then loop over every static file and write it at the respective relative position in the directory
	for _, filePath := range fileNames {
		fileContent, err := ressourceFiles.ReadFile(filePath)
		if err != nil {
			zipWriter.Close()
			return &archive, err
		}
		localFilePath, _ := strings.CutPrefix(filePath, path)
		zipFileDescriptor, err := zipWriter.Create(localFilePath)
		if err != nil {
			zipWriter.Close()
			return &archive, err
		}
		_, err = zipFileDescriptor.Write(fileContent)
		if err != nil {
			zipWriter.Close()
			return &archive, err
		}
	}

	//finalize the zip-archive and return it
	zipWriter.Close()
	return &archive, nil
}
