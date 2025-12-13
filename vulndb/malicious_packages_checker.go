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
	"os"
	"path/filepath"
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
	stopChan       chan struct{}
	updateTicker   *time.Ticker
	updateInterval time.Duration
}

type MaliciousPackageCheckerConfig struct {
	DBPath            string
	RepoURL           string
	UpdateInterval    time.Duration
	SkipInitialUpdate bool // Skip initial download, useful for tests
}

func NewMaliciousPackageChecker(config MaliciousPackageCheckerConfig, leaderElector shared.LeaderElector) (*MaliciousPackageChecker, error) {
	// Set defaults
	if config.RepoURL == "" {
		config.RepoURL = DefaultMaliciousPackageRepo
	}
	if config.UpdateInterval == 0 {
		config.UpdateInterval = DefaultUpdateInterval
	}

	// make sure the dbPath exists
	if err := os.MkdirAll(config.DBPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create db path: %w", err)
	}

	// Determine repo path (parent of OSV structure)
	repoPath := filepath.Join(filepath.Dir(config.DBPath), "malicious-packages")

	checker := &MaliciousPackageChecker{
		packages:       make(map[string]map[string]*dtos.OSV),
		dbPath:         config.DBPath,
		repoPath:       repoPath,
		repoURL:        config.RepoURL,
		updateInterval: config.UpdateInterval,
		stopChan:       make(chan struct{}),
		updateTicker:   time.NewTicker(config.UpdateInterval),
	}

	// Initial fetch/update of the database
	if !config.SkipInitialUpdate {
		leaderElector.IfLeader(context.Background(), func() error {
			slog.Info("starting malicious package database update")
			if err := checker.updateDatabase(); err != nil {
				slog.Error("Failed to initialize malicious package database", "error", err)
				return err
			}
			// Start background updater
			checker.backgroundUpdater()
			return nil
		})
	} else {
		// Test mode: synchronous initialization, no background updater
		if err := checker.loadDatabase(checker.dbPath); err != nil {
			return nil, fmt.Errorf("failed to load test database: %w", err)
		}
	}

	return checker, nil
}

// Stop gracefully stops the background updater
func (c *MaliciousPackageChecker) Stop() {
	if c.updateTicker != nil {
		c.updateTicker.Stop()
	}
	close(c.stopChan)
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
	slog.Info("Downloading repository archive", "url", c.repoURL)

	// check when it was last modified
	if info, err := os.Stat(c.repoPath); err == nil {
		modTime := info.ModTime()
		slog.Info("Existing repository found", "last_modified", modTime.Format(time.RFC3339))
		if time.Since(modTime) < c.updateInterval {
			slog.Info("Repository is up-to-date, skipping download")
			return nil
		}
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
	slog.Info("Background database updater started", "interval", c.updateInterval)
	for {
		select {
		case <-c.updateTicker.C:
			slog.Info("Starting scheduled database update")
			if err := c.updateDatabase(); err != nil {
				slog.Error("Failed to update database", "error", err)
			}
		case <-c.stopChan:
			slog.Info("Background updater stopped")
			return
		}
	}
}

func (c *MaliciousPackageChecker) loadDatabase(dbPath string) error {
	slog.Info("Loading malicious package database", "path", dbPath)

	ecosystems := []string{"npm", "go", "maven", "pypi", "crates.io"}
	totalLoaded := 0

	errGroup := utils.ErrGroup[int](5)

	for _, ecosystem := range ecosystems {
		ecosystemPath := filepath.Join(dbPath, ecosystem)
		if _, err := os.Stat(ecosystemPath); os.IsNotExist(err) {
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

	slog.Info("Malicious package database loaded", "total", totalLoaded)
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

	// Process files in parallel batches
	const batchSize = 100
	errGroup := utils.ErrGroup[any](10)

	for i := 0; i < len(files); i += batchSize {
		end := min(i+batchSize, len(files))
		errGroup.Go(func() (any, error) {
			batch := files[i:end]
			for _, path := range batch {
				if err := c.loadPackageEntryPath(path); err != nil {
					slog.Debug("Failed to load malicious package entry", "path", path, "error", err)
				}

			}
			return nil, nil
		})
	}
	if _, err := errGroup.WaitAndCollect(); err != nil {
		return 0, fmt.Errorf("failed to load ecosystem entries: %w", err)
	}

	// create a fake package entry for testing purposes
	fakeEntry := dtos.OSV{
		ID:      "FAKE-TEST-001",
		Summary: "Fake malicious package for testing",
		Details: "This is a fake malicious package entry used for testing the dependency proxy",
		Affected: []dtos.Affected{
			{
				Package: dtos.Pkg{
					Ecosystem: strings.ToLower(ecosystemPath),
					Name:      "github.com/fake-malicious-package",
				},
				Versions: []string{}, // All versions affected
			},
		},
		Published: time.Now(),
	}
	c.loadEntry(fakeEntry)

	return len(files), nil
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

func (c *MaliciousPackageChecker) loadPackageEntryPath(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var entry dtos.OSV
	if err := json.Unmarshal(data, &entry); err != nil {
		return err
	}
	c.loadEntry(entry)
	return nil
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
	for _, v := range affected.Versions {
		if v == version || version == "" {
			return true
		}
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
