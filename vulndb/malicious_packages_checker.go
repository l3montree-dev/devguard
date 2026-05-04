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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/package-url/packageurl-go"
	"gorm.io/gorm"
)

const (
	DefaultMaliciousPackageRepo = "https://github.com/ossf/malicious-packages/archive/refs/heads/main.tar.gz"
	BatchSize                   = 700 // Insert in batches to avoid memory spikes
	malPkgNumOfGoRoutines       = 7
)

// MaliciousPackageChecker checks packages against the malicious package database
type MaliciousPackageChecker struct {
	repository *repositories.MaliciousPackageRepository
	repoURL    string
	httpClient *http.Client
}

func NewMaliciousPackageChecker(
	repository *repositories.MaliciousPackageRepository,
) (*MaliciousPackageChecker, error) {
	return &MaliciousPackageChecker{
		repository: repository,
		repoURL:    DefaultMaliciousPackageRepo,
		httpClient: &http.Client{Transport: utils.EgressTransport},
	}, nil
}

// FetchAll downloads the malicious packages archive and returns all parsed packages
// and affected components without touching the database.
func (c *MaliciousPackageChecker) FetchAll(ctx context.Context) ([]models.MaliciousPackage, []models.MaliciousAffectedComponent, error) {
	slog.Info("Downloading malicious packages archive", "url", c.repoURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.repoURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create download request: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to download archive: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("failed to download archive: HTTP %d", resp.StatusCode)
	}

	gzr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	ecosystems := []string{"npm", "go", "maven", "pypi", "crates.io"}

	processWG := &sync.WaitGroup{}
	collectWG := &sync.WaitGroup{}

	fileJobs := make(chan []byte, malPkgNumOfGoRoutines*20)
	resultJobs := make(chan processingResults, BatchSize*2)

	for range malPkgNumOfGoRoutines {
		processWG.Add(1)
		go processMaliciousPackageFile(processWG, fileJobs, resultJobs)
	}

	var (
		packages   []models.MaliciousPackage
		components []models.MaliciousAffectedComponent
		mu         sync.Mutex
	)
	collectWG.Add(1)
	go func() {
		defer collectWG.Done()
		for r := range resultJobs {
			// pre-compute component IDs so they are stable in the gob file
			for i := range r.AffectedComponents {
				if r.AffectedComponents[i].ID == "" {
					r.AffectedComponents[i].ID = r.AffectedComponents[i].CalculateHash()
				}
			}
			mu.Lock()
			packages = append(packages, r.Package)
			components = append(components, r.AffectedComponents...)
			mu.Unlock()
		}
	}()

	for {
		header, err := tr.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, nil, fmt.Errorf("failed to read tar: %w", err)
		}
		if !strings.HasSuffix(header.Name, ".json") || header.Typeflag != tar.TypeReg {
			continue
		}
		isTarget := false
		for _, eco := range ecosystems {
			if strings.Contains(header.Name, "/osv/malicious/"+eco+"/") {
				isTarget = true
				break
			}
		}
		if !isTarget {
			continue
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			slog.Debug("Failed to read file from tar", "name", header.Name, "error", err)
			continue
		}
		fileJobs <- data
	}

	close(fileJobs)
	processWG.Wait()
	close(resultJobs)
	collectWG.Wait()

	slog.Info("Fetched malicious packages", "packages", len(packages), "components", len(components))
	return packages, components, nil
}

// ApplyToDB clears the malicious packages tables and bulk-inserts the provided data
// within the given transaction. The caller is responsible for committing or rolling back.
func (c *MaliciousPackageChecker) ApplyToDB(ctx context.Context, tx shared.DB, packages []models.MaliciousPackage, components []models.MaliciousAffectedComponent) error {
	if err := clearMaliciousPackagesDB(tx); err != nil {
		return fmt.Errorf("could not clear malicious package database: %w", err)
	}

	for i := 0; i < len(packages); i += BatchSize {
		end := min(i+BatchSize, len(packages))
		if err := c.repository.UpsertPackages(ctx, tx, packages[i:end]); err != nil {
			return fmt.Errorf("failed to upsert packages: %w", err)
		}
	}
	for i := 0; i < len(components); i += BatchSize {
		end := min(i+BatchSize, len(components))
		if err := c.repository.UpsertAffectedComponents(ctx, tx, components[i:end]); err != nil {
			return fmt.Errorf("failed to upsert components: %w", err)
		}
	}
	return nil
}

type processingResults struct {
	Package            models.MaliciousPackage
	AffectedComponents []models.MaliciousAffectedComponent
}

// this function grabs json file contents from the jobs channel and builds the package as well as the affected components from it. These are then sent to the db worker function
func processMaliciousPackageFile(waitGroup *sync.WaitGroup, jobs chan []byte, results chan processingResults) {
	defer waitGroup.Done()
	for data := range jobs {
		var entry dtos.OSV
		if err := json.Unmarshal(data, &entry); err != nil {
			slog.Debug("Failed to unmarshal JSON", "error", err)
			continue
		}

		if entry.ID == "" {
			slog.Warn("Skipping malicious package with empty ID", "summary", entry.Summary)
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

		// Create affected components
		components := transformer.MaliciousAffectedComponentFromOSV(entry, entry.ID)
		// send both as a job to the db writer function
		results <- processingResults{
			Package:            pkg,
			AffectedComponents: components,
		}
	}
}

// this function runs in the background and grabs the processed malicious packages and affected components from the results channel, if the batch size is reached we write all packages and affected components to the db.
func (c *MaliciousPackageChecker) dbWriterFunction(ctx context.Context, waitGroup *sync.WaitGroup, jobs chan processingResults) {
	defer waitGroup.Done()
	// stash the received results until the batch size threshold is reached
	packagesBatch := make([]models.MaliciousPackage, 0, BatchSize)
	affectedComponentsBatch := make([]models.MaliciousAffectedComponent, 0, BatchSize*4)

	total := 0
	for job := range jobs {
		packagesBatch = append(packagesBatch, job.Package)
		affectedComponentsBatch = append(affectedComponentsBatch, job.AffectedComponents...)
		if len(packagesBatch) >= BatchSize {
			// if we reached the threshold save all to the db
			if err := c.repository.UpsertPackages(ctx, nil, packagesBatch); err != nil {
				slog.Error("Failed to upsert packages batch", "error", err)
			}
			packagesBatch = packagesBatch[:0] // Reset slice

			if err := c.repository.UpsertAffectedComponents(ctx, nil, affectedComponentsBatch); err != nil {
				slog.Error("Failed to upsert affected components batch", "error", err)
			}
			affectedComponentsBatch = affectedComponentsBatch[:0] // Reset slice
			total += 1
			if total*BatchSize%50000 == 0 {
				slog.Info(fmt.Sprintf("processed %d Packages", total*BatchSize))
			}
		}
	}

	// Insert remaining batches
	if len(packagesBatch) > 0 {
		if err := c.repository.UpsertPackages(ctx, nil, packagesBatch); err != nil {
			slog.Error("Failed to upsert final packages batch", "error", err)
		}
	}
	if len(affectedComponentsBatch) > 0 {
		if err := c.repository.UpsertAffectedComponents(ctx, nil, affectedComponentsBatch); err != nil {
			slog.Error("Failed to upsert final affected components batch", "error", err)
		}
	}
}

// deletes all entries from the malicious packages/affected_components table, in a single transaction
func clearMaliciousPackagesDB(tx *gorm.DB) error {
	if err := tx.Exec("DELETE FROM malicious_affected_components").Error; err != nil {
		return fmt.Errorf("failed to clear affected components table: %w", err)
	}
	if err := tx.Exec("DELETE FROM malicious_packages").Error; err != nil {
		return fmt.Errorf("failed to clear packages table: %w", err)
	}

	return nil
}

func (c *MaliciousPackageChecker) loadFakePackages(ctx context.Context) error {
	testPackages := map[string][]string{
		"npm":       {"fake-malicious-npm-package", "@fake-org/malicious-package"},
		"go":        {"github.com/fake-org/malicious-package"},
		"pypi":      {"fake-malicious-pypi-package"},
		"maven":     {"com.fake:malicious-package"},
		"crates.io": {"fake-malicious-crate"},
		"oci":       {"fake-org/malicious-image"},
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
						Package: dtos.Package{
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

			components := transformer.MaliciousAffectedComponentFromOSV(fakeEntry, fakeID)
			affectedComponents = append(affectedComponents, components...)
		}
	}

	if err := c.repository.UpsertPackages(ctx, nil, packages); err != nil {
		return err
	}
	return c.repository.UpsertAffectedComponents(ctx, nil, affectedComponents)
}

func (c *MaliciousPackageChecker) IsMalicious(ctx context.Context, ecosystem, packageName, version string) (bool, *dtos.OSV, error) {

	if version == "" {
		return false, nil, fmt.Errorf("version is required to check if a package is malicious")
	}

	// construct purl for querying, the database uses purl matching to filter by version ranges, so we need to construct a valid purl here
	purl := fmt.Sprintf("pkg:%s/%s@%s", strings.ToLower(ecosystem), strings.ToLower(packageName), version)

	// Parse to normalize
	parsedPurl, err := packageurl.FromString(purl)
	if err != nil {
		slog.Debug("Failed to parse purl", "purl", purl, "error", err)
		return false, nil, fmt.Errorf("failed to parse purl: %w", err)
	}

	// Query database using purl matching (similar to PurlComparer)
	components, err := c.repository.GetMaliciousAffectedComponents(ctx, nil, parsedPurl)
	if err != nil {
		slog.Debug("Failed to query malicious packages", "error", err)
		return false, nil, fmt.Errorf("failed to query malicious packages: %w", err)
	}

	// If we got results from the query, the database already filtered by version ranges
	if len(components) > 0 {
		// Take the first match (database already did the version filtering)
		maliciousPackage, err := c.repository.GetMaliciousPackageByID(ctx, nil, components[0].MaliciousPackageID)
		if err != nil {
			return false, nil, fmt.Errorf("failed to load malicious package metadata: %w", err)
		}
		osv := maliciousPackage.ToOSV()
		return true, &osv, nil
	}

	return false, nil, nil
}
