package assetversion

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"
)

func TestDiffScanResults(t *testing.T) {

	t.Run("should correctly identify a vulnerability which now gets found by another scanner", func(t *testing.T) {
		currentScanner := "new-scanner"

		foundVulnerabilities := []models.DependencyVuln{
			{CVEID: utils.Ptr("CVE-1234")},
		}

		existingDependencyVulns := []models.DependencyVuln{
			{CVEID: utils.Ptr("CVE-1234"), Vulnerability: models.Vulnerability{ScannerIDs: "scanner-1"}},
		}

		foundByScannerAndNotExisting, fixedVulns, detectedByCurrentScanner, notDetectedByCurrentScannerAnymore := diffScanResults(currentScanner, foundVulnerabilities, existingDependencyVulns)

		assert.Empty(t, foundByScannerAndNotExisting)
		assert.Empty(t, fixedVulns)
		assert.Empty(t, notDetectedByCurrentScannerAnymore)
		assert.Equal(t, 1, len(detectedByCurrentScanner))
	})

	t.Run("should correctly identify a vulnerability which now is fixed, since it was not found by the scanner anymore", func(t *testing.T) {
		currentScanner := "new-scanner"

		foundVulnerabilities := []models.DependencyVuln{}

		existingDependencyVulns := []models.DependencyVuln{
			{CVEID: utils.Ptr("CVE-1234"), Vulnerability: models.Vulnerability{ScannerIDs: currentScanner}},
		}

		foundByScannerAndNotExisting, fixedVulns, detectedByCurrentScanner, notDetectedByCurrentScannerAnymore := diffScanResults(currentScanner, foundVulnerabilities, existingDependencyVulns)

		assert.Empty(t, foundByScannerAndNotExisting)
		assert.Equal(t, 1, len(fixedVulns))
		assert.Empty(t, detectedByCurrentScanner)
		assert.Empty(t, notDetectedByCurrentScannerAnymore)
	})

	t.Run("should correctly identify a vulnerability which is not detected by the current scanner anymore", func(t *testing.T) {
		currentScanner := "new-scanner"

		foundVulnerabilities := []models.DependencyVuln{}

		existingDependencyVulns := []models.DependencyVuln{
			{CVEID: utils.Ptr("CVE-1234"), Vulnerability: models.Vulnerability{ScannerIDs: currentScanner + " scanner-1"}},
		}

		foundByScannerAndNotExisting, fixedVulns, detectedByCurrentScanner, notDetectedByCurrentScannerAnymore := diffScanResults(currentScanner, foundVulnerabilities, existingDependencyVulns)

		assert.Empty(t, foundByScannerAndNotExisting)
		assert.Empty(t, fixedVulns)
		assert.Empty(t, detectedByCurrentScanner)
		assert.Equal(t, 1, len(notDetectedByCurrentScannerAnymore))
	})

	t.Run("should identify new vulnerabilities", func(t *testing.T) {
		currentScanner := "new-scanner"

		foundVulnerabilities := []models.DependencyVuln{
			{CVEID: utils.Ptr("CVE-1234")},
			{CVEID: utils.Ptr("CVE-5678")},
		}

		existingDependencyVulns := []models.DependencyVuln{}

		foundByScannerAndNotExisting, fixedVulns, detectedByCurrentScanner, notDetectedByCurrentScannerAnymore := diffScanResults(currentScanner, foundVulnerabilities, existingDependencyVulns)

		assert.Equal(t, 2, len(foundByScannerAndNotExisting))
		assert.Empty(t, fixedVulns)
		assert.Empty(t, detectedByCurrentScanner)
		assert.Empty(t, notDetectedByCurrentScannerAnymore)
	})
}

func TestFileCreationForPDFSBOM(t *testing.T) {
	t.Run("test the new functions", func(t *testing.T) {
		bom := cdx.BOM{
			Components: &[]cdx.Component{
				{BOMRef: "pkg:deb/debian/gcc-12@12.2.0", Name: "debian/gcc-12", Version: "12.2.0-14", Type: "application", Licenses: &cdx.Licenses{cdx.LicenseChoice{License: &cdx.License{ID: "Apache-2.0"}}}},
				{BOMRef: "pkg:deb/debian/libc6@2.36-9+deb12u10", Name: "debian/libc6", Version: "2.36-9+deb12u10", Type: "library", Licenses: &cdx.Licenses{cdx.LicenseChoice{License: &cdx.License{ID: "MIT"}}}},
				{BOMRef: "pkg:deb/debian/libstdc++6@12.2.0-14", Name: "debian/libstdc++6", Version: "12.2.0-14", Type: "library", Licenses: &cdx.Licenses{}},
			},
		}
		markdownFile := bytes.Buffer{}

		err := markdownTableFromSBOM(&markdownFile, &bom)
		if err != nil {
			slog.Error(err.Error())
			t.Fail()
		}
		wd, err := os.Getwd()
		assert.Nil(t, err)
		fmt.Printf("Current working Dir in Test: %s\n", wd)
		//Create metadata.yaml
		metaDataFile := bytes.Buffer{}

		metaData := createYAMLMetadata("testOrga", "", "main")
		yamlData, err := yaml.Marshal(metaData)
		assert.Nil(t, err)
		_, err = metaDataFile.Write(yamlData)
		if err != nil {
			slog.Error(err.Error())
			t.Fail()
		}

		//Create zip of all the necessary files
		zipBomb, err := buildZIPInMemory(&metaDataFile, &markdownFile)
		assert.Nil(t, err)

		var buf bytes.Buffer
		mpw := multipart.NewWriter(&buf)
		fileWriter, err := mpw.CreateFormFile("file", "archive.zip")
		assert.Nil(t, err)
		n, err := io.Copy(fileWriter, zipBomb)
		fmt.Printf("Copied %d bytes", n)
		assert.Nil(t, err)
		err = mpw.Close()
		assert.Nil(t, err)
		os.Setenv("PDF_GENERATION_API", "https://dwt-api.dev-l3montree.cloud/pdf")
		pdfAPIURL := os.Getenv("PDF_GENERATION_API")
		if pdfAPIURL == "" {
			slog.Error("URL of the pdf api is missing")
			t.Fail()
		}
		temp, err := os.Create("test.zip")
		assert.Nil(t, err)
		_, err = temp.Write(buf.Bytes())
		assert.Nil(t, err)
		req, err := http.NewRequest("POST", pdfAPIURL, &buf)
		assert.Nil(t, err)
		req.Header.Set("Content-Type", mpw.FormDataContentType())
		client := &http.Client{}
		resp, err := client.Do(req)
		assert.Nil(t, err)
		fmt.Printf("Request url: %s", req.URL)
		defer resp.Body.Close()
		fmt.Printf("Received Status Code: %d", resp.StatusCode)
		assert.Nil(t, err)
		pdf, err := os.Create("sbom.pdf")
		assert.Nil(t, err)
		defer pdf.Close()
		_, err = io.Copy(pdf, resp.Body)
		assert.Nil(t, err)

	})
}

func TestYamlMetadata(t *testing.T) {
	t.Run("Test the created yaml", func(t *testing.T) {
		assetVersionName := "main"
		organizationName := "TestOrga"
		projectTitle := "Komplette Fantasie"

		metaData := createYAMLMetadata(organizationName, projectTitle, assetVersionName)
		yamlData, err := yaml.Marshal(metaData)
		today := time.Now()
		assert.Nil(t, err)
		fmt.Printf("----------YAML-------------\n%s", yamlData)
		assert.Equal(t, fmt.Sprintf("metadata_vars:\n  document_title: DevGuard Report\n  primary_color: '\"#FF5733\"'\n  version: main\n  generation_date: %s. %s %s\n  app_title_part_one: Komplette\n  app_title_part_two: Fantasie\n  organization_name: TestOrga\n  integrity: sha265:3d8ce29bd449af3709535e12a93e0 fa2cea666912c3d37cf316369613533888d\n", strconv.Itoa(today.Day()), today.Month().String(), strconv.Itoa(today.Year())), string(yamlData))
	})
	t.Run("Test the created yaml with empty title", func(t *testing.T) {
		assetVersionName := "main"
		organizationName := "TestOrga"
		projectTitle := ""

		metaData := createYAMLMetadata(organizationName, projectTitle, assetVersionName)
		yamlData, err := yaml.Marshal(metaData)
		today := time.Now()
		assert.Nil(t, err)
		fmt.Printf("----------YAML-------------\n%s", yamlData)
		assert.Equal(t, fmt.Sprintf("metadata_vars:\n  document_title: DevGuard Report\n  primary_color: '\"#FF5733\"'\n  version: main\n  generation_date: %s. %s %s\n  app_title_part_one: \"\"\n  app_title_part_two: \"\"\n  organization_name: TestOrga\n  integrity: sha265:3d8ce29bd449af3709535e12a93e0 fa2cea666912c3d37cf316369613533888d\n", strconv.Itoa(today.Day()), today.Month().String(), strconv.Itoa(today.Year())), string(yamlData))
	})
}

func TestCreateProjectTitle(t *testing.T) {
	t.Run("empty project name should return two empty titles", func(t *testing.T) {
		projectTitle := ""
		title1, title2 := createTitlesFromProjectName(projectTitle)
		assert.Equal(t, "", title1, title2)
		assert.LessOrEqual(t, len(title1), 14)
		assert.LessOrEqual(t, len(title2), 14)
	})
	t.Run("project name <= 14 characters should just return project name in title1 and title2 should be empty", func(t *testing.T) {
		projectTitle := "One Two Fields"
		title1, title2 := createTitlesFromProjectName(projectTitle)
		assert.Equal(t, projectTitle, title1)
		assert.Equal(t, "", title2)
		assert.LessOrEqual(t, len(title1), 14)
		assert.LessOrEqual(t, len(title2), 14)
	})
	t.Run("project name > 14 characters and <= 28 characters should split up the name at the optimal whitespace", func(t *testing.T) {
		projectTitle := "One Two Three Four Fields"
		title1, title2 := createTitlesFromProjectName(projectTitle)
		assert.Equal(t, "One Two Three", title1)
		assert.Equal(t, "Four Fields", title2)
		assert.LessOrEqual(t, len(title1), 14)
		assert.LessOrEqual(t, len(title2), 14)
	})
	t.Run("project name > 28 characters with fields < 14 should cut off after the titles are full", func(t *testing.T) {
		projectTitle := "One Two Three Four Fields More Fields?"
		title1, title2 := createTitlesFromProjectName(projectTitle)
		assert.Equal(t, "One Two Three", title1)
		assert.Equal(t, "Four Fields", title2)
		assert.LessOrEqual(t, len(title1), 14)
		assert.LessOrEqual(t, len(title2), 14)
	})
	t.Run("project name > 28 characters with fields < 14 should cut off the last title", func(t *testing.T) {
		projectTitle := "One Two Three Four Taco Fields More Fields?"
		title1, title2 := createTitlesFromProjectName(projectTitle)
		assert.Equal(t, "One Two Three", title1)
		assert.Equal(t, "Four Taco Fi..", title2)
		assert.LessOrEqual(t, len(title1), 14)
		assert.LessOrEqual(t, len(title2), 14)
	})
	t.Run("project name > 28 characters with fields > 14 should cut off first title with a -, not enough space for api so it gets left out", func(t *testing.T) {
		projectTitle := "WhoWouldUseSuchALongName Api"
		title1, title2 := createTitlesFromProjectName(projectTitle)
		assert.Equal(t, "WhoWouldUseSu-", title1)
		assert.Equal(t, "chALongName", title2)
		assert.LessOrEqual(t, len(title1), 14)
		assert.LessOrEqual(t, len(title2), 14)
	})
	t.Run("project name > 28 characters with fields > 14 should cut off first title with a -, enough space for api so it gets inserted", func(t *testing.T) {
		projectTitle := "WhoWouldUseSuchLongName Api"
		title1, title2 := createTitlesFromProjectName(projectTitle)
		assert.Equal(t, "WhoWouldUseSu-", title1)
		assert.Equal(t, "chLongName Api", title2)
		assert.LessOrEqual(t, len(title1), 14)
		assert.LessOrEqual(t, len(title2), 14)
	})
}

func TestMarkdownTableFromSBOM(t *testing.T) {
	t.Run("test an sbom with 3 components which have 2 , 1 and 0 licenses respectively ", func(t *testing.T) {
		bom := cdx.BOM{
			Components: &[]cdx.Component{
				{BOMRef: "pkg:deb/debian/gcc-12@12.2.0", Name: "debian/gcc-12", Version: "12.2.0-14", Type: "application", Licenses: &cdx.Licenses{cdx.LicenseChoice{License: &cdx.License{ID: "Apache-2.0"}}, {License: &cdx.License{ID: "Apache-4.0"}}}},
				{BOMRef: "pkg:deb/debian/libc6@2.36-9+deb12u10", Name: "debian/libc6", Version: "2.36-9+deb12u10", Type: "library", Licenses: &cdx.Licenses{cdx.LicenseChoice{License: &cdx.License{ID: "MIT"}}}},
				{BOMRef: "pkg:deb/debian/libstdc++6@12.2.0-14", Name: "debian/libstdc++6", Version: "12.2.0-14", Type: "library", Licenses: &cdx.Licenses{}},
			},
		}
		markdownFile := bytes.Buffer{}
		err := markdownTableFromSBOM(&markdownFile, &bom)
		assert.Nil(t, err)
		assert.Equal(t, "# SBOM\n\n| PURL | Name | Version | Licenses  | Type |\n|-------------------|---------|---------|--------|-------|\n| pkg:deb/debian/gcc-12@12.2.0 | debian/gcc-12 | 12.2.0-14 | Apache-2.0 Apache-4.0 | application |\n| pkg:deb/debian/libc6@2.36-9&#43;deb12u10 | debian/libc6 | 2.36-9&#43;deb12u10 | MIT | library |\n| pkg:deb/debian/libstdc&#43;&#43;6@12.2.0-14 | debian/libstdc&#43;&#43;6 | 12.2.0-14 |  Unknown | library |\n", markdownFile.String())
	})
}
