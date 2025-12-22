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
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/pkg/errors"

	"github.com/l3montree-dev/devguard/shared"
)

const (
	DefaultMaliciousPackageRepo = "https://github.com/ossf/malicious-packages/archive/refs/heads/main.tar.gz"
	DefaultUpdateInterval       = 2 * time.Hour
)

// MaliciousPackageChecker checks packages against the malicious package database
type MaliciousPackageChecker struct {
	packages       map[string]map[string]*dtos.OSV // ecosystem -> package name -> entry
	dbPath         string
	repoPath       string
	repoURL        string
	lastUpdate     time.Time
	updateTicker   *time.Ticker
	updateInterval time.Duration
	leaderElector  shared.LeaderElector
	databaseLoaded bool
}

func NewMaliciousPackageChecker(leaderElector shared.LeaderElector) (*MaliciousPackageChecker, error) {

	var dbPath string
	maliciousPackageDatabasePath := os.Getenv("MALICIOUS_PACKAGE_DATABASE_PATH")
	if maliciousPackageDatabasePath != "" {
		slog.Info("Using custom malicious package database path", "path", maliciousPackageDatabasePath)
		dbPath = maliciousPackageDatabasePath
	} else {
		dbPath = filepath.Join(os.TempDir(), "devguard-dependency-proxy-db")
		slog.Info("Using default malicious package database path")
	}

	// make sure the dbPath exists
	if err := os.MkdirAll(dbPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create db path: %w", err)
	}

	// Determine repo path (parent of OSV structure)
	repoPath := filepath.Join(dbPath, "malicious-packages")

	checker := &MaliciousPackageChecker{
		packages:       make(map[string]map[string]*dtos.OSV),
		dbPath:         dbPath,
		repoPath:       repoPath,
		repoURL:        DefaultMaliciousPackageRepo,
		updateInterval: DefaultUpdateInterval,
		leaderElector:  leaderElector,
	}

	if err := checker.loadDatabase(checker.dbPath); err != nil {
		go func() {
			slog.Info("Initial load of malicious package database failed, attempting to download and process the database", "err", err)
			if dlErr := checker.downloadDBAndSaveCache(); dlErr != nil {
				slog.Error("could not download and process malicious package database", "err", dlErr)
			} else {
				slog.Info("Malicious package database downloaded and processed successfully")
			}
		}()
	}

	return checker, nil
}

// IsReady returns true if the malicious package database has been loaded
func (c *MaliciousPackageChecker) IsReady() bool {
	return c.databaseLoaded
}

func (c *MaliciousPackageChecker) Start() {
	c.updateTicker = time.NewTicker(c.updateInterval)
	for range c.updateTicker.C {
		slog.Info("Updating malicious package database", "url", c.repoURL)

		if c.leaderElector.IsLeader() {
			// Download and process the repository archive in memory
			if err := c.downloadDBAndSaveCache(); err != nil {
				slog.Error("could not download db", "err", err)
				continue
			}
			slog.Info("Malicious package database updated successfully", "time", c.lastUpdate.Format(time.RFC3339))
		} else {
			if err := c.loadDatabase(c.dbPath); err != nil {
				slog.Error("could not load database", "err", err)
				continue
			}
			slog.Info("Malicious package database loaded successfully", "time", c.lastUpdate.Format(time.RFC3339))
		}
	}
}

// downloadDB downloads the repository archive and processes it in memory
func (c *MaliciousPackageChecker) downloadDBAndSaveCache() error {
	slog.Info("Downloading and processing repository archive in memory", "url", c.repoURL)

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

	c.databaseLoaded = false
	packages := make(map[string]map[string]*dtos.OSV)

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

		// Add to packages map
		c.loadEntry(packages, entry)
		totalLoaded++
	}

	slog.Info("Processed malicious packages from archive", "total", totalLoaded)

	// Include fake packages for testing
	c.loadFakePackages(packages)

	// Save to cache for faster subsequent loads
	cacheFile := filepath.Join(c.dbPath, "malicious-packages.cache.gob.gz")
	if err := c.saveCache(cacheFile, packages); err != nil {
		slog.Warn("Failed to save cache", "error", err)
	}
	// make sure to have pretty much atomic switch
	c.packages = packages

	return nil
}

func (c *MaliciousPackageChecker) loadDatabase(dbPath string) error {
	startTime := time.Now()
	cacheFile := filepath.Join(dbPath, "malicious-packages.cache.gob.gz")
	slog.Info("Loading malicious package database", "path", cacheFile)

	// Check if cache exists
	_, err := os.Stat(cacheFile)
	if err != nil {
		return err
	}

	file, err := os.Open(cacheFile)
	if err != nil {
		return err
	}
	defer file.Close()

	gz, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gz.Close()

	decoder := gob.NewDecoder(gz)

	if err := decoder.Decode(&c.packages); err != nil {
		return errors.Wrap(err, "could not load database from cache")
	}

	c.databaseLoaded = true
	slog.Info("Malicious package database loaded from cache",
		"duration", time.Since(startTime).String(), "npm", len(c.packages["npm"]),
		"go", len(c.packages["go"]), "pypi", len(c.packages["pypi"]),
		"maven", len(c.packages["maven"]), "crates.io", len(c.packages["crates.io"]),
	)

	return nil
}

func (c *MaliciousPackageChecker) saveCache(cacheFile string, packages map[string]map[string]*dtos.OSV) error {
	file, err := os.Create(cacheFile)
	if err != nil {
		return err
	}
	defer file.Close()

	gz := gzip.NewWriter(file)
	defer gz.Close()

	encoder := gob.NewEncoder(gz)
	return encoder.Encode(packages)
}

func (c *MaliciousPackageChecker) loadFakePackages(packages map[string]map[string]*dtos.OSV) {
	testPackages := map[string][]string{
		"npm":       {"fake-malicious-npm-package", "@fake-org/malicious-package"},
		"go":        {"github.com/fake-org/malicious-package"},
		"pypi":      {"fake-malicious-pypi-package"},
		"maven":     {"com.fake:malicious-package"},
		"crates.io": {"fake-malicious-crate"},
	}
	for ecosystem := range testPackages {
		if pkgNames, ok := testPackages[ecosystem]; ok {
			for _, pkgName := range pkgNames {
				fakeEntry := dtos.OSV{
					ID:      fmt.Sprintf("FAKE-TEST-%s-001", strings.ToUpper(ecosystem)),
					Summary: fmt.Sprintf("Fake malicious %s package for testing", ecosystem),
					Details: "This is a fake malicious package entry used for testing the dependency proxy",
					Affected: []dtos.Affected{
						{
							Package: dtos.Pkg{
								Ecosystem: ecosystem,
								Name:      pkgName,
							},
							Versions: []string{}, // All versions affected
						},
					},
					Published: time.Now(),
				}
				c.loadEntry(packages, fakeEntry)
			}
		}
	}
}

func (c *MaliciousPackageChecker) loadEntry(packages map[string]map[string]*dtos.OSV, entry dtos.OSV) {
	if len(entry.Affected) == 0 {
		return
	}

	for _, affected := range entry.Affected {
		pkgEcosystem := strings.ToLower(affected.Package.Ecosystem)
		pkgName := strings.ToLower(affected.Package.Name)

		if packages[pkgEcosystem] == nil {
			packages[pkgEcosystem] = make(map[string]*dtos.OSV)
		}

		packages[pkgEcosystem][pkgName] = &entry
	}
}

func (c *MaliciousPackageChecker) IsMalicious(ecosystem, packageName, version string) (bool, *dtos.OSV) {
	ecosystemKey := strings.ToLower(ecosystem)
	packageKey := strings.ToLower(packageName)

	if ecosystemMap, ok := c.packages[ecosystemKey]; ok {
		if entry, ok := ecosystemMap[packageKey]; ok {
			// Check if the version is affected
			for _, affected := range entry.Affected {
				if c.isVersionAffected(affected, version) {
					return true, entry
				}
			}
		}
	}

	return false, nil
}

func (c *MaliciousPackageChecker) isVersionAffected(affected dtos.Affected, version string) bool {
	// If no specific versions or ranges, consider all versions affected
	if len(affected.Versions) == 0 && len(affected.Ranges) == 0 {
		return true
	}

	// Check explicit versions
	if slices.Contains(affected.Versions, version) {
		return true
	}

	// Check ranges
	for _, r := range affected.Ranges {
		if r.Type == "SEMVER" {
			for _, event := range r.Events {
				if event.Introduced == "0" && event.Fixed == "" {
					// all versions are affected
					return true
				}
				if normalize.SemverCompare(version, event.Introduced) < 0 {
					continue
				}
				if event.Fixed != "" {
					if normalize.SemverCompare(version, event.Fixed) >= 0 {
						continue
					}
				}
				return true
			}
		}
	}

	return false
}
