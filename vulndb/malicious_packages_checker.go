// Copyright (C) 2025 l3montree GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package vulndb

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/package-url/packageurl-go"
)

const (
	DefaultMaliciousPackageRepo = "https://github.com/ossf/malicious-packages/archive/refs/heads/main.tar.gz"
	BatchSize                   = 500 // Insert in batches to avoid memory spikes
)

// MaliciousPackageChecker checks packages against the malicious package database
type MaliciousPackageChecker struct {
	repository *repositories.MaliciousPackageRepository
	repoURL    string
}

func NewMaliciousPackageChecker(
	repository *repositories.MaliciousPackageRepository,
) (*MaliciousPackageChecker, error) {
	return &MaliciousPackageChecker{
		repository: repository,
		repoURL:    DefaultMaliciousPackageRepo,
	}, nil
}

// DownloadAndProcessDB downloads the repository archive and processes it directly to the database
func (c *MaliciousPackageChecker) DownloadAndProcessDB() error {
	slog.Info("Downloading and processing repository archive", "url", c.repoURL)
	// make sure both tables are empty before loading
	if err := c.repository.GetDB().Exec("DELETE FROM malicious_affected_components").Error; err != nil {
		return fmt.Errorf("failed to clear affected components table: %w", err)
	}
	if err := c.repository.GetDB().Exec("DELETE FROM malicious_packages").Error; err != nil {
		return fmt.Errorf("failed to clear packages table: %w", err)
	}

	// Download the archive
	resp, err := http.Get(c.repoURL)
	if err != nil {
		return fmt.Errorf("failed to download archive: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download archive: HTTP %d", resp.StatusCode)
	}

	// Decompress gzip
	gzr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzr.Close()

	// Process tar archive directly in memory
	tr := tar.NewReader(gzr)

	ecosystems := []string{"npm", "go", "maven", "pypi", "crates.io"}
	totalLoaded := 0

	// Batch collections
	packages := make([]models.MaliciousPackage, 0, BatchSize)
	affectedComponents := make([]models.MaliciousAffectedComponent, 0, BatchSize*2)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar: %w", err)
		}

		// Only process JSON files in the malicious package directories
		if header.Typeflag != tar.TypeReg || !strings.HasSuffix(header.Name, ".json") {
			continue
		}

		// Check if file is in one of our target ecosystems
		isTargetEcosystem := false
		for _, eco := range ecosystems {
			if strings.Contains(header.Name, "/osv/malicious/"+eco+"/") {
				isTargetEcosystem = true
				break
			}
		}

		if !isTargetEcosystem {
			continue
		}

		// Read and parse JSON directly from tar stream
		data, err := io.ReadAll(tr)
		if err != nil {
			slog.Debug("Failed to read file from tar", "name", header.Name, "error", err)
			continue
		}

		var entry dtos.OSV
		if err := json.Unmarshal(data, &entry); err != nil {
			slog.Debug("Failed to unmarshal JSON", "name", header.Name, "error", err)
			continue
		}

		if len(entry.Affected) == 0 {
			continue
		}

		// Create malicious package record
		pkg := models.MaliciousPackage{
			ID:        entry.ID,
			Summary:   entry.Summary,
			Details:   entry.Details,
			Published: entry.Published,
			Modified:  entry.Modified,
		}
		packages = append(packages, pkg)

		// Create affected components
		components := models.MaliciousAffectedComponentFromOSV(entry, entry.ID)
		affectedComponents = append(affectedComponents, components...)

		totalLoaded++

		// Batch insert when we reach batch size
		if len(packages) >= BatchSize {
			if err := c.repository.UpsertPackages(packages); err != nil {
				slog.Error("Failed to upsert packages batch", "error", err)
			}
			packages = packages[:0] // Reset slice
			if err := c.repository.UpsertAffectedComponents(affectedComponents); err != nil {
				slog.Error("Failed to upsert affected components batch", "error", err)
			}
			affectedComponents = affectedComponents[:0] // Reset slice
		}
	}

	// Insert remaining batches
	if len(packages) > 0 {
		if err := c.repository.UpsertPackages(packages); err != nil {
			slog.Error("Failed to upsert final packages batch", "error", err)
		}
	}
	if len(affectedComponents) > 0 {
		if err := c.repository.UpsertAffectedComponents(affectedComponents); err != nil {
			slog.Error("Failed to upsert final affected components batch", "error", err)
		}
	}

	// Add fake test packages
	if err := c.loadFakePackages(); err != nil {
		slog.Warn("Failed to load fake packages", "error", err)
	}

	slog.Info("Processed malicious packages from archive", "total", totalLoaded)

	// Log ecosystem counts
	counts, err := c.repository.CountByEcosystem()
	if err == nil {
		slog.Info("Malicious package database loaded",
			"npm", counts["npm"],
			"go", counts["go"],
			"pypi", counts["pypi"],
			"maven", counts["maven"],
			"crates.io", counts["crates.io"],
		)
	}

	return nil
}

func (c *MaliciousPackageChecker) loadFakePackages() error {
	testPackages := map[string][]string{
		"npm":       {"fake-malicious-npm-package", "@fake-org/malicious-package"},
		"go":        {"github.com/fake-org/malicious-package"},
		"pypi":      {"fake-malicious-pypi-package"},
		"maven":     {"com.fake:malicious-package"},
		"crates.io": {"fake-malicious-crate"},
	}

	packages := make([]models.MaliciousPackage, 0)
	affectedComponents := make([]models.MaliciousAffectedComponent, 0)

	for ecosystem, pkgNames := range testPackages {
		for _, pkgName := range pkgNames {
			fakeID := fmt.Sprintf("FAKE-TEST-%s-001", strings.ToUpper(ecosystem))
			fakeEntry := dtos.OSV{
				ID:      fakeID,
				Summary: fmt.Sprintf("Fake malicious %s package for testing", ecosystem),
				Details: "This is a fake malicious package entry used for testing the dependency proxy",
				Affected: []dtos.Affected{
					{
						Package: dtos.Pkg{
							Ecosystem: ecosystem,
							Name:      pkgName,
							Purl:      fmt.Sprintf("pkg:%s/%s", ecosystem, pkgName),
						},
						Versions: []string{}, // All versions affected
					},
				},
				Published: time.Now(),
			}

			pkg := models.MaliciousPackage{
				ID:        fakeID,
				Summary:   fakeEntry.Summary,
				Details:   fakeEntry.Details,
				Published: fakeEntry.Published,
				Modified:  fakeEntry.Published,
			}
			packages = append(packages, pkg)

			components := models.MaliciousAffectedComponentFromOSV(fakeEntry, fakeID)
			affectedComponents = append(affectedComponents, components...)
		}
	}

	if err := c.repository.UpsertPackages(packages); err != nil {
		return err
	}
	return c.repository.UpsertAffectedComponents(affectedComponents)
}

func (c *MaliciousPackageChecker) IsMalicious(ecosystem, packageName, version string) (bool, *dtos.OSV) {
	// Build a purl for the package
	purl := fmt.Sprintf("pkg:%s/%s", strings.ToLower(ecosystem), strings.ToLower(packageName))

	// Parse to normalize
	parsedPurl, err := packageurl.FromString(purl)
	if err != nil {
		slog.Debug("Failed to parse purl", "purl", purl, "error", err)
		return false, nil
	}

	// Remove version for lookup
	parsedPurl.Version = ""
	searchPurl := parsedPurl.ToString()

	// Query database using purl matching (similar to PurlComparer)
	components, err := c.repository.GetMaliciousAffectedComponents(searchPurl, version)
	if err != nil {
		slog.Debug("Failed to query malicious packages", "error", err)
		return false, nil
	}

	// If we got results from the query, the database already filtered by version ranges
	if len(components) > 0 {
		// Take the first match (database already did the version filtering)
		osv := components[0].MaliciousPackage.ToOSV()
		return true, &osv
	}

	return false, nil
}
