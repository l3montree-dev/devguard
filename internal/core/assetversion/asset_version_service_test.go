package assetversion

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/stretchr/testify/assert"
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

		markdownTable := markdownTableFromSBOM(&bom)
		//Create a new file to write the markdown to
		workingDir, err := os.Getwd()
		assert.Nil(t, err)
		workingDir = filepath.Join(filepath.Join(filepath.Join(workingDir, ".."), ".."), "..")
		filePath1 := workingDir + "/report-templates/sbom/markdown/sbom.md"
		filePath2 := workingDir + "/report-templates/sbom/template/metadata.yaml"

		markdownFile, err := os.Create(filePath1)
		if err != nil {
			fmt.Println(err.Error())
			t.Fail()
		}

		_, err = markdownFile.Write([]byte(markdownTable))
		if err != nil {
			slog.Error(err.Error())
			t.Fail()
		}

		//Create metadata.yaml
		metaDataFile, err := os.Create(filePath2)
		if err != nil {
			slog.Error(err.Error())
			t.Fail()
		}

		metaData := createYAMLMetadata("testOrga", "OPENCODE BADGE API PROJECT", "main")
		_, err = metaDataFile.Write([]byte(metaData))
		if err != nil {
			slog.Error(err.Error())
			t.Fail()
		}

		//Create zip of all the necessary files
		zipBomb, err := buildZIPForPDF(workingDir + "/report-templates/sbom/")
		assert.Nil(t, err)
		defer zipBomb.Close()
		assert.Nil(t, err)
		fileInfo, err := zipBomb.Stat()
		assert.Nil(t, err)
		fmt.Printf("\n---------------Zip Bomb Stats:\nName: %s\nSize: %d\nModTime:%s\n", fileInfo.Name(), fileInfo.Size(), fileInfo.ModTime().String())

		var buf bytes.Buffer
		mpw := multipart.NewWriter(&buf)
		fileWriter, err := mpw.CreateFormFile("file", "archive.zip")
		assert.Nil(t, err)
		_, err = io.Copy(fileWriter, zipBomb)
		assert.Nil(t, err)
		err = mpw.Close()
		assert.Nil(t, err)
		req, err := http.NewRequest("POST", "https://dwt-api.dev-l3montree.cloud/pdf", &buf)
		assert.Nil(t, err)
		req.Header.Set("Content-Type", mpw.FormDataContentType())
		client := &http.Client{}

		resp, err := client.Do(req)
		if !assert.Nil(t, err) {
			t.Fail()
		}
		defer resp.Body.Close()
		fmt.Printf("Received Status Code: %d", resp.StatusCode)
		assert.Nil(t, err)
		pdf, err := os.Create("sbom.pdf")
		defer pdf.Close()
		_, err = io.Copy(pdf, resp.Body)
		assert.Nil(t, err)

	})
}
