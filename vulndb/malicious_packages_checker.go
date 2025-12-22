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
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/normalize"

	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
)

const (
	DefaultMaliciousPackageRepo = "https://github.com/ossf/malicious-packages/archive/refs/heads/main.tar.gz"
	DefaultUpdateInterval       = 2 * time.Hour
)

// MaliciousPackageChecker checks packages against the malicious package database
type MaliciousPackageChecker struct {
	mu             sync.RWMutex
	packages       map[string]map[string]*dtos.OSV // ecosystem -> package name -> entry
	dbPath         string
	repoPath       string
	repoURL        string
	lastUpdate     time.Time
	updateTicker   *time.Ticker
	updateInterval time.Duration
	updaterCtx     *context.Context
	cancelFn       context.CancelFunc
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
		return nil, fmt.Errorf("failed to load test database: %w", err)
	}

	return checker, nil
}

// Stop gracefully stops the background updater
func (c *MaliciousPackageChecker) Stop() {
	if c.updateTicker != nil {
		c.updateTicker.Stop()
	}

	if c.cancelFn != nil {
		c.cancelFn()
	}
}

// IsReady returns true if the malicious package database has been loaded
func (c *MaliciousPackageChecker) IsReady() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.databaseLoaded
}

func (c *MaliciousPackageChecker) Start() {
	for {
		if c.leaderElector.IsLeader() && c.updaterCtx == nil && c.cancelFn == nil {
			ctx, cancel := context.WithCancel(context.Background())
			c.updaterCtx = &ctx
			c.cancelFn = cancel
			// Start background updater
			go c.backgroundUpdater()
		} else if c.updaterCtx != nil && c.cancelFn != nil {
			slog.Info("skipping malicious package database update - not leader")
			c.cancelFn()
			c.updaterCtx = nil
			c.cancelFn = nil
		}
		time.Sleep(5 * time.Minute)
	}
}

// updateDatabase fetches the latest malicious packages via HTTP
func (c *MaliciousPackageChecker) updateDatabase() error {
	slog.Info("Updating malicious package database", "url", c.repoURL)

	// Download and extract the repository archive
	if err := c.downloadAndExtract(); err != nil {
		return fmt.Errorf("failed to download repository: %w", err)
	}

	// Load the database
	if err := c.loadDatabase(c.dbPath); err != nil {
		return fmt.Errorf("failed to load database after update: %w", err)
	}

	c.mu.Lock()
	c.lastUpdate = time.Now()
	c.mu.Unlock()

	slog.Info("Malicious package database updated successfully", "time", c.lastUpdate.Format(time.RFC3339))
	return nil
}

// downloadAndExtract downloads the repository archive and extracts it
func (c *MaliciousPackageChecker) downloadAndExtract() error {
	// check when it was last modified
	if info, err := os.Stat(c.repoPath); err == nil {
		modTime := info.ModTime()
		slog.Info("Existing repository found", "last_modified", modTime.Format(time.RFC3339), "path", c.repoPath)
		if time.Since(modTime) < c.updateInterval {
			slog.Info("Repository is up-to-date, skipping download")
			return nil
		}
	}
	slog.Info("Downloading repository archive", "url", c.repoURL)
	// Download the archive
	resp, err := http.Get(c.repoURL)
	if err != nil {
		return fmt.Errorf("failed to download archive: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download archive: HTTP %d", resp.StatusCode)
	}

	// Remove old directory if it exists
	if err := os.RemoveAll(c.repoPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove old directory: %w", err)
	}

	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(c.repoPath), 0755); err != nil {
		return fmt.Errorf("failed to create parent directory: %w", err)
	}

	// Decompress gzip
	gzr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzr.Close()

	// Extract tar archive
	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar: %w", err)
		}

		// Skip the root directory (malicious-packages-main/)
		parts := strings.SplitN(header.Name, "/", 2)
		if len(parts) < 2 {
			continue
		}
		targetPath := filepath.Join(c.repoPath, parts[1])

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, 0755); err != nil {
				return fmt.Errorf("failed to create directory: %w", err)
			}
		case tar.TypeReg:
			// Ensure parent directory exists
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return fmt.Errorf("failed to create parent directory: %w", err)
			}
			// Create file
			outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return fmt.Errorf("failed to create file: %w", err)
			}
			if _, err := io.Copy(outFile, tr); err != nil {
				outFile.Close()
				return fmt.Errorf("failed to write file: %w", err)
			}
			outFile.Close()
		}
	}

	slog.Info("Repository extracted successfully", "path", c.repoPath)
	return nil
}

// backgroundUpdater periodically updates the database
func (c *MaliciousPackageChecker) backgroundUpdater() {
	if err := c.updateDatabase(); err != nil {
		slog.Error("Failed to perform initial database update", "error", err)
	}
	c.updateTicker = time.NewTicker(c.updateInterval)
	slog.Info("Background database updater started", "interval", c.updateInterval)
	for {
		select {
		case <-c.updateTicker.C:
			slog.Info("Starting scheduled database update")
			if err := c.updateDatabase(); err != nil {
				slog.Error("Failed to update database", "error", err)
			}
		case <-(*c.updaterCtx).Done():
			slog.Info("Background updater stopped")
			return
		}
	}
}

func (c *MaliciousPackageChecker) loadDatabase(dbPath string) error {
	startTime := time.Now()
	slog.Info("Loading malicious package database", "path", dbPath)

	cacheFile := filepath.Join(dbPath, "malicious-packages.cache.gob.gz")

	// Try to load from cache first
	if err := c.loadFromCache(cacheFile, dbPath); err == nil {
		// Include fake packages for testing
		c.loadFakePackages()
		c.mu.Lock()
		c.databaseLoaded = true
		c.mu.Unlock()
		slog.Info("Malicious package database loaded from cache",
			"duration", time.Since(startTime).String())
		return nil
	}

	// Cache miss or invalid, load from JSON files
	slog.Info("Cache miss, loading from JSON files")
	if err := c.loadFromJSON(dbPath); err != nil {
		return err
	}

	// Save cache for next time
	if err := c.saveCache(cacheFile); err != nil {
		slog.Warn("Failed to save cache", "error", err)
	}

	// Include fake packages for testing
	c.loadFakePackages()

	c.mu.Lock()
	c.databaseLoaded = true
	c.mu.Unlock()

	slog.Info("Malicious package database loaded", "duration", time.Since(startTime).String())
	return nil
}

func (c *MaliciousPackageChecker) loadFromCache(cacheFile, dbPath string) error {
	// Check if cache exists
	cacheInfo, err := os.Stat(cacheFile)
	if err != nil {
		return err
	}

	// Check if source directory is newer than cache
	sourceDir := filepath.Join(dbPath, "malicious-packages")
	sourceInfo, err := os.Stat(sourceDir)
	if err == nil && sourceInfo.ModTime().After(cacheInfo.ModTime()) {
		return fmt.Errorf("cache is older than source")
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

	c.mu.Lock()
	defer c.mu.Unlock()

	decoder := gob.NewDecoder(gz)
	return decoder.Decode(&c.packages)
}

func (c *MaliciousPackageChecker) saveCache(cacheFile string) error {
	file, err := os.Create(cacheFile)
	if err != nil {
		return err
	}
	defer file.Close()

	gz := gzip.NewWriter(file)
	defer gz.Close()

	c.mu.RLock()
	defer c.mu.RUnlock()

	encoder := gob.NewEncoder(gz)
	return encoder.Encode(c.packages)
}

func (c *MaliciousPackageChecker) loadFromJSON(dbPath string) error {
	ecosystems := []string{"npm", "go", "maven", "pypi", "crates.io"}
	totalLoaded := 0

	errGroup := utils.ErrGroup[int](5)

	for _, ecosystem := range ecosystems {
		ecosystemPath := filepath.Join(dbPath, "malicious-packages", "osv", "malicious", ecosystem)
		if _, err := os.Stat(ecosystemPath); os.IsNotExist(err) {
			slog.Error("could not load ecosystem", "err", err)
			continue
		}

		errGroup.Go(func() (int, error) {
			count, err := c.loadEcosystem(ecosystemPath)
			if err != nil {
				return 0, fmt.Errorf("failed to load ecosystem %s: %w", ecosystem, err)
			}
			if count > 0 {
				slog.Info("Loaded malicious packages", "ecosystem", ecosystem, "count", count)
			}
			return count, nil
		})
	}

	results, err := errGroup.WaitAndCollect()
	if err != nil {
		return err
	}

	for _, res := range results {
		if res != 0 {
			totalLoaded += res
		}
	}

	return nil
}

func (c *MaliciousPackageChecker) loadEcosystem(ecosystemPath string) (int, error) {
	// Collect all JSON files first
	var files []string
	err := filepath.Walk(ecosystemPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(path, ".json") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}

	// Process files in parallel with larger batches
	const batchSize = 1000
	numWorkers := runtime.NumCPU() * 2
	errGroup := utils.ErrGroup[map[string]map[string]*dtos.OSV](numWorkers)

	for i := 0; i < len(files); i += batchSize {
		end := min(i+batchSize, len(files))
		batch := files[i:end]

		errGroup.Go(func() (map[string]map[string]*dtos.OSV, error) {
			// Build local map without locking
			localPackages := make(map[string]map[string]*dtos.OSV)

			for _, path := range batch {
				data, err := os.ReadFile(path)
				if err != nil {
					slog.Debug("Failed to read file", "path", path, "error", err)
					continue
				}

				var entry dtos.OSV
				if err := json.Unmarshal(data, &entry); err != nil {
					slog.Debug("Failed to unmarshal JSON", "path", path, "error", err)
					continue
				}

				if len(entry.Affected) == 0 {
					continue
				}

				// Add to local map
				for _, affected := range entry.Affected {
					ecosystem := strings.ToLower(affected.Package.Ecosystem)
					pkgName := strings.ToLower(affected.Package.Name)

					if localPackages[ecosystem] == nil {
						localPackages[ecosystem] = make(map[string]*dtos.OSV)
					}
					localPackages[ecosystem][pkgName] = &entry
				}
			}
			return localPackages, nil
		})
	}

	results, err := errGroup.WaitAndCollect()
	if err != nil {
		return 0, fmt.Errorf("failed to load ecosystem entries: %w", err)
	}

	// Merge all local maps into main map with single lock
	c.mu.Lock()
	for _, localMap := range results {
		for ecosystem, packages := range localMap {
			if c.packages[ecosystem] == nil {
				c.packages[ecosystem] = make(map[string]*dtos.OSV)
			}
			maps.Copy(c.packages[ecosystem], packages)
		}
	}
	c.mu.Unlock()

	return len(files), nil
}

func (c *MaliciousPackageChecker) loadFakePackages() {
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
				c.loadEntry(fakeEntry)
			}
		}
	}
}

func (c *MaliciousPackageChecker) loadEntry(entry dtos.OSV) {
	if len(entry.Affected) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, affected := range entry.Affected {
		pkgEcosystem := strings.ToLower(affected.Package.Ecosystem)
		pkgName := strings.ToLower(affected.Package.Name)

		if c.packages[pkgEcosystem] == nil {
			c.packages[pkgEcosystem] = make(map[string]*dtos.OSV)
		}

		c.packages[pkgEcosystem][pkgName] = &entry
	}
}

func (c *MaliciousPackageChecker) IsMalicious(ecosystem, packageName, version string) (bool, *dtos.OSV) {
	ecosystemKey := strings.ToLower(ecosystem)
	packageKey := strings.ToLower(packageName)

	c.mu.RLock()
	defer c.mu.RUnlock()

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
