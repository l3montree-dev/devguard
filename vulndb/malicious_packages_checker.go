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

	"github.com/jackc/pgx/v5"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/transformer"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/package-url/packageurl-go"
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

type malRow struct {
	pkgs  []models.MaliciousPackage
	comps []models.MaliciousAffectedComponent
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

func buildFakePackages() ([]models.MaliciousPackage, []models.MaliciousAffectedComponent) {
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
			normalizedPkgName := strings.NewReplacer("/", "-", "@", "-", ":", "-", ".", "-").Replace(pkgName)
			fakeID := fmt.Sprintf("FAKE-TEST-%s-%s", strings.ToUpper(ecosystem), strings.ToUpper(normalizedPkgName))
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
						Versions: []string{},
					},
				},
				Published: time.Now(),
			}
			packages = append(packages, models.MaliciousPackage{
				ID:        fakeID,
				Summary:   fakeEntry.Summary,
				Details:   fakeEntry.Details,
				Published: fakeEntry.Published,
				Modified:  fakeEntry.Published,
			})
			affectedComponents = append(affectedComponents, transformer.MaliciousAffectedComponentFromOSV(fakeEntry, fakeID)...)
		}
	}
	return packages, affectedComponents
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

// insertMaliciousPackagesBulk streams malicious packages and components into staging tables. Call flushStagingTables once after all batches.
func insertMaliciousPackagesBulk(ctx context.Context, tx pgx.Tx, pkgs []models.MaliciousPackage, comps []models.MaliciousAffectedComponent) error {
	if len(pkgs) > 0 {
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"mal_pkgs_stage"},
			[]string{"id", "summary", "details", "published", "modified"},
			pgx.CopyFromSlice(len(pkgs), func(i int) ([]any, error) {
				p := pkgs[i]
				return []any{p.ID, p.Summary, p.Details, p.Published, p.Modified}, nil
			})); err != nil {
			return fmt.Errorf("could not copy malicious packages into staging table: %w", err)
		}
	}
	if len(comps) > 0 {
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"mal_comps_stage"},
			[]string{"id", "malicious_package_id", "purl", "ecosystem", "version", "semver_introduced", "semver_fixed", "version_introduced", "version_fixed"},
			pgx.CopyFromSlice(len(comps), func(i int) ([]any, error) {
				c := comps[i]
				return []any{c.ID, c.MaliciousPackageID, c.PurlWithoutVersion, c.Ecosystem, c.Version, c.SemverIntroduced, c.SemverFixed, c.VersionIntroduced, c.VersionFixed}, nil
			})); err != nil {
			return fmt.Errorf("could not copy malicious components into staging table: %w", err)
		}
	}
	return nil
}
