package assetversion

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/normalize"
	"github.com/l3montree-dev/devguard/internal/core/vuln"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/labstack/echo/v4"
	"github.com/openvex/go-vex/pkg/vex"
	"golang.org/x/exp/slog"
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

func (a *AssetVersionController) BuildPDFFromSBOM(ctx core.Context) error {
	//build the SBOM of this asset version
	bom, err := a.buildSBOM(ctx)
	if err != nil {
		return err
	}
	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	//WARNING if we change the hierarchy of the project we need to change this as well!! (workingDir needs to be root folder of the devguard backend)
	filePathMarkdown := workingDir + "/report-templates/sbom/markdown/sbom.md"
	filePathMetaData := workingDir + "/report-templates/sbom/template/metadata.yaml"

	//Create a new file to write the markdown to
	markdownFile, err := os.Create(filePathMarkdown)
	if err != nil {
		return err
	}
	defer markdownFile.Close()
	defer os.Remove(filePathMarkdown) //since we generate new files every time we can delete them after use

	//Convert SBOM to Markdown string
	markdownTable := markdownTableFromSBOM(bom)
	_, err = markdownFile.Write([]byte(markdownTable))
	if err != nil {
		return err
	}

	//Create metadata.yaml
	metaDataFile, err := os.Create(filePathMetaData)
	if err != nil {
		return err
	}
	defer metaDataFile.Close()
	defer os.Remove(filePathMetaData)

	//Build the meta data for the yaml file
	metaData := createYAMLMetadata(core.GetOrg(ctx).Name, core.GetProject(ctx).Name, core.GetAssetVersion(ctx).Name)
	_, err = metaDataFile.Write([]byte(metaData))
	if err != nil {
		return err
	}

	//Create zip of all the necessary files
	zipBomb, err := buildZIPForPDF(workingDir + "/report-templates/sbom/")
	if err != nil {
		return err
	}
	defer zipBomb.Close()
	defer os.Remove(workingDir + "/report-templates/sbom/archive.zip")

	//prepare the http request as multipart form data
	var buf bytes.Buffer
	mpw := multipart.NewWriter(&buf)
	fileWriter, err := mpw.CreateFormFile("file", "archive.zip")
	if err != nil {
		return err
	}
	_, err = io.Copy(fileWriter, zipBomb)
	if err != nil {
		return err
	}
	err = mpw.Close()
	if err != nil {
		return err
	}
	pdfAPIURL := os.Getenv("PDF_GENERATION_API")
	if pdfAPIURL == "" {
		return fmt.Errorf("missing env variable for the pdf endpoint")
	}
	req, err := http.NewRequest("POST", pdfAPIURL, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", mpw.FormDataContentType())

	//do the http request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("http request to %s was unsuccessful", req.URL)
	}

	//create the pdf and write the data to it
	pdf, err := os.Create("sbom.pdf")
	if err != nil {
		return err
	}
	defer pdf.Close()
	defer os.Remove("sbom.pdf")
	_, err = io.Copy(pdf, resp.Body)
	if err != nil {
		return err
	}
	return ctx.Attachment("sbom.pdf", "sbom.pdf")
}
func buildZIPForPDF(path string) (*os.File, error) {
	archive, err := os.Create(path + "archive.zip")
	if err != nil {
		return nil, err
	}
	zipWriter := zip.NewWriter(archive)
	defer zipWriter.Close()
	fileNames := []string{
		path + "markdown/abkuerzungen.yaml", path + "markdown/glossar.yaml", path + "markdown/sbom.md",
		path + "template/metadata.yaml", path + "template/template.tex", path + "template/assets/background.png", path + "template/assets/qr.png",
		path + "template/assets/font/Inter-Bold.ttf", path + "template/assets/font/Inter-BoldItalic.ttf", path + "template/assets/font/Inter-Italic-VariableFont_opsz,wght.ttf", path + "template/assets/font/Inter-Italic.ttf", path + "template/assets/font/Inter-Regular.ttf", path + "template/assets/font/Inter-VariableFont_opsz,wght.ttf",
	}
	for _, file := range fileNames {
		fileDescriptor, err := os.Open(file)
		if err != nil {
			return nil, err
		}
		localFilePath, _ := strings.CutPrefix(file, path)
		zipFileDescriptor, err := zipWriter.Create(localFilePath)
		if err != nil {
			return nil, err
		}
		_, err = io.Copy(zipFileDescriptor, fileDescriptor)
		if err != nil {
			return nil, err
		}
		fileDescriptor.Close()
	}
	return os.Open(path + "archive.zip")
}
