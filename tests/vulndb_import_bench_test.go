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
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package tests

import (
	"context"
	"os"
	"runtime"
	"runtime/pprof"
	"sync/atomic"
	"testing"
	"time"

	"github.com/l3montree-dev/devguard/shared"
)

// BenchmarkImportRC measures the full memory and time cost of VulnDBService.ImportRC,
// including gob decoding and all database writes via a real PostgreSQL container.
//
// The benchmark writes a heap profile to mem.prof after each run.
// View it as an interactive HTML flamegraph with:
//
//	go tool pprof -http=:8080 mem.prof
//
// Enable the debugImport const in vulndb/vulndb_service.go to cache vulndb.tar.zst
// locally (in the working directory) so the archive is only downloaded once across
// repeated runs.
//
// Run with:
//
//	go test -bench=BenchmarkImportRC -benchmem -run=^$ -timeout=30m ./tests/
func BenchmarkImportRC(b *testing.B) {
	ctx := context.Background()

	fixture := NewTestFixture(b, "../initdb.sql", &TestAppOptions{SuppressLogs: true})

	for b.Loop() {
		var memBefore, memAfter runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&memBefore)

		var peakHeap atomic.Uint64
		done := make(chan struct{})
		go func() {
			var ms runtime.MemStats
			for {
				select {
				case <-done:
					return
				case <-time.After(100 * time.Millisecond):
					runtime.ReadMemStats(&ms)
					if ms.HeapInuse > peakHeap.Load() {
						peakHeap.Store(ms.HeapInuse)
					}
				}
			}
		}()

		if err := fixture.App.VulnDBService.ImportRC(ctx, shared.ImportOptions{}); err != nil {
			close(done)
			b.Fatalf("ImportRC failed: %v", err)
		}
		close(done)

		runtime.GC()
		runtime.ReadMemStats(&memAfter)

		b.ReportMetric(float64(peakHeap.Load())/1024/1024, "peak_heap_MiB")
		b.ReportMetric(float64(memAfter.HeapInuse-memBefore.HeapInuse)/1024/1024, "heap_MiB")
		b.ReportMetric(float64(memAfter.TotalAlloc-memBefore.TotalAlloc)/1024/1024, "total_alloc_MiB")

		// Write a heap profile after every iteration so the last (or only) run is always captured.
		f, err := os.Create("mem.prof")
		if err != nil {
			b.Fatalf("could not create mem.prof: %v", err)
		}
		if err := pprof.WriteHeapProfile(f); err != nil {
			f.Close()
			b.Fatalf("could not write heap profile: %v", err)
		}
		f.Close()
	}
}
