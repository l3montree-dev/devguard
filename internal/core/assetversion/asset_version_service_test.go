package assetversion

import (
	"testing"

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
