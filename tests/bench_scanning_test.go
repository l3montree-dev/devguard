// Copyright (C) 2026 l3montree GmbH
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
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package tests

import (
	"bytes"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/shared"

	"github.com/labstack/echo/v4"
)

// getEnvOrDefault returns the environment variable value or a default
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func initDevDatabase() (shared.DB, func()) {
	shared.LoadConfig()
	cfg := database.PoolConfig{
		Host:            getEnvOrDefault("POSTGRES_HOST", "localhost"),
		Port:            getEnvOrDefault("POSTGRES_PORT", "5432"),
		User:            getEnvOrDefault("POSTGRES_USER", "devguard"),
		Password:        getEnvOrDefault("POSTGRES_PASSWORD", "devguard"),
		DBName:          getEnvOrDefault("POSTGRES_DB", "devguard"),
		MaxOpenConns:    10,
		MinConns:        2,
		ConnMaxLifetime: 30 * time.Minute,
		ConnMaxIdleTime: 5 * time.Minute,
	}

	pool := database.NewPgxConnPool(cfg)
	db := database.NewGormDB(pool)

	cleanup := func() {
		pool.Close()
	}

	return db, cleanup
}

// loadSBOM loads an SBOM file from disk
func loadSBOM(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(file)
}

// MemStats holds memory statistics for reporting
type MemStats struct {
	AllocBytes      uint64
	TotalAllocBytes uint64
	HeapAllocBytes  uint64
	HeapObjects     uint64
	NumGC           uint32
}

// getMemStats captures current memory statistics
func getMemStats() MemStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return MemStats{
		AllocBytes:      m.Alloc,
		TotalAllocBytes: m.TotalAlloc,
		HeapAllocBytes:  m.HeapAlloc,
		HeapObjects:     m.HeapObjects,
		NumGC:           m.NumGC,
	}
}

// reportMemoryDiff reports the difference in memory between two snapshots
func reportMemoryDiff(b *testing.B, before, after MemStats) {
	b.ReportMetric(float64(after.HeapAllocBytes-before.HeapAllocBytes)/1024/1024, "heap_MB")
	b.ReportMetric(float64(after.TotalAllocBytes-before.TotalAllocBytes)/1024/1024, "total_alloc_MB")
	b.ReportMetric(float64(after.HeapObjects-before.HeapObjects), "heap_objects")
}

// Constants for benchmark entities - using fixed names makes it idempotent
const (
	benchOrgSlug     = "benchmark-org"
	benchProjectSlug = "benchmark-project"
	benchAssetSlug   = "benchmark-asset"
)

// findOrCreateBenchmarkEntities creates or retrieves benchmark test entities
// This makes the benchmark idempotent - running multiple times won't create duplicates
func findOrCreateBenchmarkEntities(db shared.DB) (models.Org, models.Project, models.Asset) {
	// Find or create org
	var org models.Org
	result := db.Where("slug = ?", benchOrgSlug).First(&org)
	if result.Error != nil {
		org = models.Org{Name: "Benchmark Org", Slug: benchOrgSlug}
		db.Create(&org)
	}

	// Find or create project
	var project models.Project
	result = db.Where("slug = ? AND organization_id = ?", benchProjectSlug, org.ID).First(&project)
	if result.Error != nil {
		project = models.Project{Name: "Benchmark Project", Slug: benchProjectSlug, OrganizationID: org.ID}
		db.Create(&project)
	}

	// Find or create asset
	var asset models.Asset
	result = db.Where("slug = ? AND project_id = ?", benchAssetSlug, project.ID).First(&asset)
	if result.Error != nil {
		asset = models.Asset{Name: "Benchmark Asset", Slug: benchAssetSlug, ProjectID: project.ID}
		db.Create(&asset)
	}

	return org, project, asset
}

// cleanupBenchmarkArtifacts removes artifacts created during benchmark runs
// This keeps the database clean between runs
func cleanupBenchmarkArtifacts(db shared.DB, assetID uuid.UUID) {
	// Delete artifacts with benchmark prefix
	db.Where("asset_id = ? AND artifact_name LIKE ?", assetID, "bench-%").Delete(&models.Artifact{})

	// Delete asset versions created during benchmark
	db.Where("asset_id = ? AND name LIKE ?", assetID, "bench-%").Delete(&models.AssetVersion{})
}

// BenchmarkScanLargeSBOMDevDB benchmarks scanning using the development database
// This connects to your local PostgreSQL instance for realistic performance testing
// Run with: go test -bench=BenchmarkScanLargeSBOMDevDB -benchmem ./tests/benchmark/...
func BenchmarkScanLargeSBOMDevDB(b *testing.B) {

	// Set required environment variable
	os.Setenv("FRONTEND_URL", "http://localhost:3000")

	// Load the large SBOM
	sbomData, err := loadSBOM("testdata/large-sbom2.json")
	if err != nil {
		b.Fatalf("failed to load large SBOM: %v", err)
	}
	b.Logf("Loaded SBOM with %d bytes", len(sbomData))

	// Connect to development database
	db, cleanup := initDevDatabase()
	defer cleanup()

	// Get the underlying pool for the test app
	cfg := database.PoolConfig{
		Host:            getEnvOrDefault("POSTGRES_HOST", "localhost"),
		Port:            getEnvOrDefault("POSTGRES_PORT", "5432"),
		User:            getEnvOrDefault("POSTGRES_USER", "devguard"),
		Password:        getEnvOrDefault("POSTGRES_PASSWORD", "devguard"),
		DBName:          getEnvOrDefault("POSTGRES_DB", "devguard"),
		MaxOpenConns:    10,
		MinConns:        2,
		ConnMaxLifetime: 30 * time.Minute,
		ConnMaxIdleTime: 5 * time.Minute,
	}
	pool := database.NewPgxConnPool(cfg)
	defer pool.Close()

	// Create test app with dev database
	app, _ := NewTestAppWithT(b, db, pool, &TestAppOptions{
		SuppressLogs: true,
	})

	// Find or create benchmark entities (idempotent)
	org, project, asset := findOrCreateBenchmarkEntities(db)

	// Clean up any leftover artifacts from previous runs
	cleanupBenchmarkArtifacts(db, asset.ID)

	// Also clean up at the end
	defer cleanupBenchmarkArtifacts(db, asset.ID)

	echoApp := echo.New()
	controller := app.ScanController

	setupContext := func(ctx shared.Context) {
		authSession := &mocks.AuthSession{}
		authSession.On("GetUserID").Return("bench-user")
		shared.SetAsset(ctx, asset)
		shared.SetProject(ctx, project)
		shared.SetOrg(ctx, org)
		shared.SetSession(ctx, authSession)
	}

	// Force GC and get baseline memory
	runtime.GC()
	beforeMem := getMemStats()

	b.ReportAllocs()

	iteration := 0
	for b.Loop() {
		// Use iteration counter for artifact name instead of UUID
		// This is more predictable and easier to clean up
		artifactName := fmt.Sprintf("bench-artifact-%d", iteration)
		iteration++

		recorder := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/scan", bytes.NewReader(sbomData))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Artifact-Name", artifactName)
		req.Header.Set("X-Asset-Default-Branch", "main")
		req.Header.Set("X-Asset-Ref", "main")
		req.Header.Set("X-Origin", "benchmark")

		ctx := echoApp.NewContext(req, recorder)
		setupContext(ctx)

		err := controller.ScanDependencyVulnFromProject(ctx)
		if err != nil {
			b.Fatalf("scan failed: %v", err)
		}

		if recorder.Code != 200 {
			b.Fatalf("unexpected status code: %d, body: %s", recorder.Code, recorder.Body.String())
		}
	}

	b.StopTimer()

	// Capture memory after benchmark
	runtime.GC()
	afterMem := getMemStats()

	// Report memory metrics
	reportMemoryDiff(b, beforeMem, afterMem)
	b.Logf("Memory Stats (Dev DB):")
	b.Logf("  Heap Alloc: %.2f MB", float64(afterMem.HeapAllocBytes)/1024/1024)
	b.Logf("  Total Alloc: %.2f MB", float64(afterMem.TotalAllocBytes)/1024/1024)
	b.Logf("  Heap Objects: %d", afterMem.HeapObjects)
	b.Logf("  GC Cycles: %d", afterMem.NumGC-beforeMem.NumGC)
}
