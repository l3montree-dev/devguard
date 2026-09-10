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
	"runtime/metrics"
	"testing"
	"time"
)

// BenchmarkNewScanAsset runs DaemonRunner.NewScanAsset against the local
// development database. A testcontainer database is useless here: it is created
// from migrations only, so there would be no dependencies to match.
//
// NewScanAsset creates purl_mapping and commits, so the table is dropped before
// every iteration - untimed, outside the measurement.
//
//	go test -run=^$ -bench=BenchmarkNewScanAsset -benchtime=1x -timeout=30m \
//		-cpuprofile=cpu.prof -memprofile=mem.prof ./tests/
//
//	go tool pprof -http=:8080 cpu.prof
//	go tool pprof -http=:8081 -sample_index=alloc_space mem.prof
func BenchmarkNewScanAsset(b *testing.B) {
	db, pool, cleanup := initDevDatabase()
	b.Cleanup(cleanup)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := pool.Ping(ctx); err != nil {
		b.Fatalf("no development database reachable: %v", err)
	}

	var dependencies int64
	if err := db.Raw(`SELECT count(DISTINCT component_id) FROM sbom_merkle_nodes;`).Scan(&dependencies).Error; err != nil {
		b.Fatalf("could not count dependencies: %v", err)
	}
	if dependencies == 0 {
		b.Fatal("development database has no component dependencies - the scan would measure nothing")
	}

	// Count every statement so N+1 patterns show up instead of hiding inside
	// the wall clock number.
	queries := NewQueryCounter()
	if err := db.Use(queries); err != nil {
		b.Fatalf("failed to install query counter: %v", err)
	}

	app, _ := NewTestAppWithT(b, db, pool, &TestAppOptions{SuppressLogs: true})
	fixture := &TestFixture{T: b, App: app, DB: db, Pool: pool}
	runner := fixture.CreateDaemonRunner()

	sampler := startHeapSampler(20 * time.Millisecond)
	runtime.GC()
	memBefore := getMemStats()
	poolBefore := pool.Stat()
	queries.Reset()

	b.ReportAllocs()
	b.ResetTimer()

	iterations := 0
	for b.Loop() {
		b.StopTimer()
		if _, err := pool.Exec(context.Background(), `DROP TABLE IF EXISTS purl_mapping`); err != nil {
			b.Fatalf("could not drop purl_mapping: %v", err)
		}
		b.StartTimer()

		if err := runner.NewScanAsset(); err != nil {
			b.Fatalf("NewScanAsset failed: %v", err)
		}
		iterations++
	}

	b.StopTimer()

	peakHeap := sampler.stop()
	memAfter := getMemStats()
	poolAfter := pool.Stat()

	b.ReportMetric(float64(peakHeap)/1024/1024, "peak_heap_MB")
	b.ReportMetric(float64(memAfter.TotalAllocBytes-memBefore.TotalAllocBytes)/1024/1024/float64(iterations), "total_alloc_MB/op")
	b.ReportMetric(float64(dependencies), "dependencies")
	b.ReportMetric(float64(queries.Calls())/float64(iterations), "db_calls/op")
	b.ReportMetric(float64(queries.Duration().Milliseconds())/float64(iterations), "db_ms/op")

	var mappedRows int64
	if err := db.Raw(`SELECT count(*) FROM purl_mapping`).Scan(&mappedRows).Error; err != nil {
		b.Fatalf("could not count purl_mapping rows: %v", err)
	}
	b.Logf("%d iteration(s) over %d dependencies produced %d purl_mapping rows", iterations, dependencies, mappedRows)
	for _, line := range queries.Report(10, iterations) {
		b.Logf("%s", line)
	}
	b.Logf("Pool: %d acquires, %s waiting",
		poolAfter.AcquireCount()-poolBefore.AcquireCount(),
		(poolAfter.AcquireDuration() - poolBefore.AcquireDuration()).Round(time.Millisecond),
	)
}

// startHeapSampler tracks the peak live heap. The -memprofile heap dump is
// written after the final GC, so it says nothing about how much was alive at
// once. runtime/metrics is used instead of ReadMemStats because it does not
// stop the world per sample.
func startHeapSampler(interval time.Duration) *heapSampler {
	sampler := &heapSampler{done: make(chan struct{}), peak: make(chan uint64, 1)}

	go func() {
		samples := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		var peak uint64
		for {
			select {
			case <-sampler.done:
				sampler.peak <- peak
				return
			case <-ticker.C:
				metrics.Read(samples)
				if heapBytes := samples[0].Value.Uint64(); heapBytes > peak {
					peak = heapBytes
				}
			}
		}
	}()

	return sampler
}

type heapSampler struct {
	done chan struct{}
	peak chan uint64
}

func (sampler *heapSampler) stop() uint64 {
	close(sampler.done)
	return <-sampler.peak
}
