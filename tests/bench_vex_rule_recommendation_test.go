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
	"context"
	"runtime"
	"testing"
)

// BenchmarkVEXRuleRecommendationDaemonDevDB benchmarks a full run of
// RunVEXRuleRecommendationDaemon against your locally configured development
// database, the same way BenchmarkScanLargeSBOMDevDB benchmarks scanning: it
// connects with the POSTGRES_* env vars (defaulting to localhost:5432) and
// operates on whatever orgs/assets/vulns/rules already exist there, instead
// of spinning up a throwaway testcontainer.
//
// Run with: go test -bench=BenchmarkVEXRuleRecommendationDaemonDevDB -benchmem ./tests/...
func BenchmarkVEXRuleRecommendationDaemonDevDB(b *testing.B) {
	// Connect to development database (one pool for GORM and pgx)
	db, pool, cleanup := initDevDatabase()
	defer cleanup()

	// Count every statement the daemon issues so the benchmark surfaces N+1
	// patterns instead of hiding them inside the wall-clock number.
	queryCounter := NewQueryCounter()
	if err := db.Use(queryCounter); err != nil {
		b.Fatalf("failed to install query counter: %v", err)
	}

	app, _ := NewTestAppWithT(b, db, pool, &TestAppOptions{
		SuppressLogs: true,
	})

	fixture := &TestFixture{T: b, App: app, DB: db, Pool: pool}
	runner := fixture.CreateDaemonRunner()

	ctx := context.Background()

	// Warm up once outside the measurement: the first run pays for cold
	// caches/connections and any lazily-compiled CEL programs, while later
	// runs hit the warm path. Without a warmup, a benchmark that only manages
	// a single iteration measures the cold path and one that manages several
	// silently mixes both.
	if err := runner.RunVEXRuleRecommendationDaemon(ctx); err != nil {
		b.Fatalf("warmup run failed: %v", err)
	}

	// Force GC and get baseline memory
	runtime.GC()
	beforeMem := getMemStats()
	queryCounter.Reset()

	b.ReportAllocs()
	b.ResetTimer()

	iterations := 0
	for b.Loop() {
		if err := runner.RunVEXRuleRecommendationDaemon(ctx); err != nil {
			b.Fatalf("daemon run failed: %v", err)
		}
		iterations++
	}

	b.StopTimer()

	// Capture memory after benchmark
	runtime.GC()
	afterMem := getMemStats()

	// Report memory metrics
	reportMemoryDiff(b, beforeMem, afterMem)

	// Report DB pressure per run - these are the numbers to watch when
	// optimizing the daemon.
	b.ReportMetric(float64(queryCounter.Calls())/float64(iterations), "db_calls/op")
	b.ReportMetric(float64(queryCounter.Duration().Milliseconds())/float64(iterations), "db_ms/op")

	b.Logf("Memory Stats (Dev DB):")
	b.Logf("  Heap Alloc: %.2f MB", float64(afterMem.HeapAllocBytes)/1024/1024)
	b.Logf("  Total Alloc: %.2f MB", float64(afterMem.TotalAllocBytes)/1024/1024)
	b.Logf("  Heap Objects: %d", afterMem.HeapObjects)
	b.Logf("  GC Cycles: %d", afterMem.NumGC-beforeMem.NumGC)

	b.Logf("Database Stats (%d iteration(s)):", iterations)
	for _, line := range queryCounter.Report(15, iterations) {
		b.Logf("  %s", line)
	}
}
