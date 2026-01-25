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
	"sync"
	"time"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/transformer"
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
func (c *MaliciousPackageChecker) DownloadAndProcessDB() (outError error) {
	tx := c.repository.GetDB().Begin()
	if err := tx.Error; err != nil {
		return fmt.Errorf("failed to start transaction for clearing tables: %w", err)
	}

	// make sure both tables are empty before loading
	err := clearMaliciousPackagesDB(tx)
	if err != nil {
		return fmt.Errorf("could not delete malicious package database: %w", err)
	}

	slog.Info("Downloading and processing repository archive", "url", c.repoURL)
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
	// need 2 different wait groups to handle the completion of the process functions independently of the completion of the db function
	processWaitGroup := &sync.WaitGroup{}
	dbWaitGroup := &sync.WaitGroup{}

	// channel to pass the file contents from the main routine to the processing Worker functions
	fileJobs := make(chan []byte, malPkgNumOfGoRoutines*20)
	// channel to pass the results of the processing functions to the database writer function
	dbJobs := make(chan processingResults, BatchSize*2)

	// start the processing worker functions
	for range malPkgNumOfGoRoutines {
		processWaitGroup.Add(1)
		go processMaliciousPackageFile(processWaitGroup, fileJobs, dbJobs)
	}

	// start the function which writes the malicious packages/components to the database when the batch SIze is reached
	dbWaitGroup.Add(1)
	go c.dbWriterFunction(dbWaitGroup, dbJobs)

	slog.Info("start working...")
	// feed the jobs into the worker functions
	for {
		// read the next file and determine if we want to process it
		header, err := tr.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("failed to read tar: %w", err)
		}
		// is this a file? is this a json file?
		if !strings.HasSuffix(header.Name, ".json") || header.Typeflag != tar.TypeReg {
			continue
		}

		// filter out ecosystems which we don't process
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

		data, err := io.ReadAll(tr)
		if err != nil {
			slog.Debug("Failed to read file from tar", "name", header.Name, "error", err)
			continue
		}
		// pass the data to processing functions
		fileJobs <- data
	}
	// there are no more jobs to give so we close the channel and wait for the processing workers to finish
	close(fileJobs)
	processWaitGroup.Wait()
	// when the processing workers are finished we can close the channel for the db jobs and wait for db to finish writing
	close(dbJobs)
	dbWaitGroup.Wait()

	// Add fake test packages
	if err := c.loadFakePackages(); err != nil {
		slog.Warn("Failed to load fake packages", "error", err)
	}

	slog.Info("Processed malicious packages from archive")

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
func (c *MaliciousPackageChecker) dbWriterFunction(waitGroup *sync.WaitGroup, jobs chan processingResults) {
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
			if err := c.repository.UpsertPackages(packagesBatch); err != nil {
				slog.Error("Failed to upsert packages batch", "error", err)
			}
			packagesBatch = packagesBatch[:0] // Reset slice

			if err := c.repository.UpsertAffectedComponents(affectedComponentsBatch); err != nil {
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
		if err := c.repository.UpsertPackages(packagesBatch); err != nil {
			slog.Error("Failed to upsert final packages batch", "error", err)
		}
	}
	if len(affectedComponentsBatch) > 0 {
		if err := c.repository.UpsertAffectedComponents(affectedComponentsBatch); err != nil {
			slog.Error("Failed to upsert final affected components batch", "error", err)
		}
	}
}

// deletes all entries from the malicious packages/affected_components table, in a single transaction
func clearMaliciousPackagesDB(tx *gorm.DB) error {
	if err := tx.Exec("DELETE FROM malicious_affected_components").Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to clear affected components table: %w", err)
	}
	if err := tx.Exec("DELETE FROM malicious_packages").Error; err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to clear packages table: %w", err)
	}

	if err := tx.Commit().Error; err != nil {
		return fmt.Errorf("failed to commit transaction for clearing tables: %w", err)
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

	if err := c.repository.UpsertPackages(packages); err != nil {
		return err
	}
	return c.repository.UpsertAffectedComponents(affectedComponents)
}

func (c *MaliciousPackageChecker) IsMalicious(ecosystem, packageName, version string) (bool, *dtos.OSV) {
	// Build a purl for the package (include version for proper version matching)
	var purl string
	if version != "" {
		purl = fmt.Sprintf("pkg:%s/%s@%s", strings.ToLower(ecosystem), strings.ToLower(packageName), version)
	} else {
		purl = fmt.Sprintf("pkg:%s/%s", strings.ToLower(ecosystem), strings.ToLower(packageName))
	}

	// Parse to normalize
	parsedPurl, err := packageurl.FromString(purl)
	if err != nil {
		slog.Debug("Failed to parse purl", "purl", purl, "error", err)
		return false, nil
	}

	// Query database using purl matching (similar to PurlComparer)
	components, err := c.repository.GetMaliciousAffectedComponents(parsedPurl)
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
