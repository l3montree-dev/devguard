package assetversion

import (
	"fmt"
	"log/slog"
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
		workingDir = filepath.Join(workingDir, "..")
		workingDir = filepath.Join(workingDir, "..")
		workingDir = filepath.Join(workingDir, "..")
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

		//Build the meta data for the yaml file
		var metaData string
		metaData = createYAMLMetadata("testOrga", "verylongsentencewithshouldnotbeserpratedbyanymeans", "main")
		fmt.Printf("----------------project-----------------\n%s\n", metaData)
		metaData = createYAMLMetadata("testOrga", "projectProjectproject api api api", "main")
		fmt.Printf("----------------project-----------------\n%s\n", metaData)
		metaData = createYAMLMetadata("testOrga", "verylongsented ncewithshould.", "main")
		fmt.Printf("----------------project-----------------\n%s\n", metaData)
		_, err = metaDataFile.Write([]byte(metaData))
		if err != nil {
			slog.Error(err.Error())
			t.Fail()
		}
	})
}
