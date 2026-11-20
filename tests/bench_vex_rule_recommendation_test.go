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
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"runtime/metrics"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/l3montree-dev/devguard/events/listeners"
	"github.com/l3montree-dev/devguard/shared"
)

// BenchmarkVEXRuleRecommendationDaemonDevDB benchmarks a full run of
// RunVEXRuleRecommendationDaemon against your locally configured development
// database, the same way BenchmarkScanLargeSBOMDevDB benchmarks scanning: it
// connects with the POSTGRES_* env vars (defaulting to localhost:5432) and
// operates on whatever orgs/assets/vulns/rules already exist there, instead
// of spinning up a throwaway testcontainer.
//
// Besides timings it reports the peak memory of the Go process and of the
// postgres docker container (POSTGRES_CONTAINER, default
// devguard-postgresql-1) while the daemon runs - the numbers relevant for OOMs.
//
// Run with: go test -run=^$ -bench=BenchmarkVEXRuleRecommendationDaemonDevDB -benchtime=1x ./tests/...
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

	benchmarkVEXRuleRecommendationDaemonRun(b, runner, queryCounter)
}

// BenchmarkVEXRuleRecommendationDaemonScaling shows how the daemon scales with
// the number of rows sharing a signature - the shape a large project with many
// branches and artifacts produces. For every duplication factor N it copies
// each asset version (with its dependency vulns, artifacts and artifact links)
// N-1 times and runs the daemon once, so the number of distinct signatures
// stays the same and only the duplicates grow. Compare per-factor time and
// peak memory: memory should stay flat, time should grow at most linearly.
//
// It writes synthetic data and must not run against the dev database, so it
// connects to BENCH_POSTGRES_DB (default devguard_bench). Create it as a copy
// of the dev database first:
//
//	createdb -T devguard devguard_bench
//	# or, while something is connected to devguard:
//	createdb devguard_bench && pg_dump devguard | psql devguard_bench
//
// The copies are kept between runs and only adjusted to the requested factor,
// so re-running is cheap. Factors come from BENCH_DUP_FACTORS (default 1,2,4,8).
//
// Run with: go test -run=^$ -bench=BenchmarkVEXRuleRecommendationDaemonScaling -benchtime=1x -timeout=0 ./tests/
func BenchmarkVEXRuleRecommendationDaemonScaling(b *testing.B) {
	dbName := getEnvOrDefault("BENCH_POSTGRES_DB", "devguard_bench")
	if dbName == "devguard" {
		b.Fatal("refusing to write synthetic data into the dev database - point BENCH_POSTGRES_DB at a copy")
	}
	// .env is loaded without overriding, so this wins over its POSTGRES_DB
	b.Setenv("POSTGRES_DB", dbName)

	var factors []int
	for f := range strings.SplitSeq(getEnvOrDefault("BENCH_DUP_FACTORS", "1,2,4,8"), ",") {
		factor, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil || factor < 1 {
			b.Fatalf("invalid BENCH_DUP_FACTORS entry %q", f)
		}
		factors = append(factors, factor)
	}

	db, pool, cleanup := initDevDatabase()
	defer cleanup()

	queryCounter := NewQueryCounter()
	if err := db.Use(queryCounter); err != nil {
		b.Fatalf("failed to install query counter: %v", err)
	}

	app, _ := NewTestAppWithT(b, db, pool, &TestAppOptions{
		SuppressLogs: true,
	})
	fixture := &TestFixture{T: b, App: app, DB: db, Pool: pool}
	runner := fixture.CreateDaemonRunner()

	for _, factor := range factors {
		start := time.Now()
		if err := ensureSyntheticDuplicates(db, factor); err != nil {
			b.Fatalf("failed to generate duplication factor %d: %v", factor, err)
		}
		// Every factor starts from the same state as a first-ever run: no
		// recommendations and no lastRun, so all vulns and rules are evaluated.
		if err := db.Exec(`DELETE FROM vex_rule_recommendations`).Error; err != nil {
			b.Fatal(err)
		}
		if err := db.Exec(`DELETE FROM config WHERE key = 'vexrules.recommendations.lastRun'`).Error; err != nil {
			b.Fatal(err)
		}

		var shape struct {
			OpenRows   int64
			Signatures int64
		}
		if err := db.Raw(`SELECT count(*) AS open_rows, count(DISTINCT signature) AS signatures FROM dependency_vulns WHERE state = 'open'`).Scan(&shape).Error; err != nil {
			b.Fatal(err)
		}

		b.Run(fmt.Sprintf("dup=%d", factor), func(b *testing.B) {
			b.Logf("Data: %d open vulns, %d signatures (prepared in %s)", shape.OpenRows, shape.Signatures, time.Since(start).Round(time.Second))
			b.ReportMetric(float64(shape.OpenRows)/float64(shape.Signatures), "open_rows/signature")
			benchmarkVEXRuleRecommendationDaemonRun(b, runner, queryCounter)
		})
	}
}

// synthDupSuffix marks synthetic copies: asset version names end in
// "-synthdup-<k>" and every copied id is md5(original id || suffix), so the
// copies are reproducible and the originals are everything without the marker.
const synthDupSuffix = "-synthdup-"

// ensureSyntheticDuplicates makes the database hold exactly factor-1 copies
// of every asset version that has dependency vulns.
func ensureSyntheticDuplicates(db shared.DB, factor int) error {
	var existing int
	if err := db.Raw(`SELECT coalesce(max(substring(name from ?)::int), 0) FROM asset_versions`, synthDupSuffix+`(\d+)$`).Scan(&existing).Error; err != nil {
		return err
	}

	for k := existing; k >= factor; k-- {
		// cascades to the copied artifacts, vulns and links
		if err := db.Exec(`DELETE FROM asset_versions WHERE name LIKE '%' || ?::text`, synthDupSuffix+strconv.Itoa(k)).Error; err != nil {
			return err
		}
	}

	for k := existing + 1; k < factor; k++ {
		suffix := synthDupSuffix + strconv.Itoa(k)
		err := db.Transaction(func(tx shared.DB) error {
			statements := []string{
				`INSERT INTO asset_versions (created_at, updated_at, name, asset_id, default_branch, slug, type, id)
				SELECT now(), now(), av.name || @suffix, av.asset_id, false, av.slug || @suffix, av.type, md5(av.id::text || @suffix)::uuid
				FROM asset_versions av
				WHERE av.name NOT LIKE '%' || @marker || '%'
					AND EXISTS (SELECT 1 FROM dependency_vulns dv WHERE dv.asset_version_id = av.id)`,

				`INSERT INTO artifacts (artifact_name, asset_id, created_at, id, asset_version_id)
				SELECT a.artifact_name, a.asset_id, a.created_at, md5(a.id::text || @suffix)::uuid, md5(a.asset_version_id::text || @suffix)::uuid
				FROM artifacts a
				JOIN asset_versions av ON av.id = a.asset_version_id
				WHERE av.name NOT LIKE '%' || @marker || '%'
					AND EXISTS (SELECT 1 FROM dependency_vulns dv WHERE dv.asset_version_id = av.id)`,

				// tickets are left out - the daemon doesn't look at them
				`INSERT INTO dependency_vulns (asset_version_name, asset_id, state, manual_ticket_creation, created_at, updated_at, cve_id,
					component_purl, component_fixed_version, risk_assessment, risk_recalculated_at, vulnerability_path,
					direct_dependency_fixed_version, id, signature, asset_signature, last_state_change, asset_version_id)
				SELECT av.name || @suffix, dv.asset_id, dv.state, dv.manual_ticket_creation, dv.created_at, dv.updated_at, dv.cve_id,
					dv.component_purl, dv.component_fixed_version, dv.risk_assessment, dv.risk_recalculated_at, dv.vulnerability_path,
					dv.direct_dependency_fixed_version, md5(dv.id::text || @suffix)::uuid, dv.signature, dv.asset_signature, dv.last_state_change,
					md5(dv.asset_version_id::text || @suffix)::uuid
				FROM dependency_vulns dv
				JOIN asset_versions av ON av.id = dv.asset_version_id
				WHERE av.name NOT LIKE '%' || @marker || '%'`,

				`INSERT INTO artifact_dependency_vulns (dependency_vuln_id, artifact_id)
				SELECT md5(adv.dependency_vuln_id::text || @suffix)::uuid, md5(adv.artifact_id::text || @suffix)::uuid
				FROM artifact_dependency_vulns adv
				JOIN dependency_vulns dv ON dv.id = adv.dependency_vuln_id
				JOIN artifacts a ON a.id = adv.artifact_id AND a.asset_version_id = dv.asset_version_id
				JOIN asset_versions av ON av.id = dv.asset_version_id
				WHERE av.name NOT LIKE '%' || @marker || '%'`,
			}
			for _, statement := range statements {
				if err := tx.Exec(statement, sql.Named("suffix", suffix), sql.Named("marker", synthDupSuffix)).Error; err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("copy %d: %w", k, err)
		}
	}

	if existing != factor-1 {
		// the planner has to see the new row counts, or the measured plans
		// would not be the ones production gets - and index-only scans need the
		// visibility map, which autovacuum would maintain in production
		return db.Exec(`VACUUM ANALYZE asset_versions, artifacts, dependency_vulns, artifact_dependency_vulns`).Error
	}
	return nil
}

// benchmarkVEXRuleRecommendationDaemonRun runs the daemon in b.Loop and
// reports duration, DB pressure and peak memory of the Go process and the
// postgres container.
func benchmarkVEXRuleRecommendationDaemonRun(b *testing.B, runner *listeners.DaemonRunner, queryCounter *QueryCounter) {
	ctx := context.Background()

	// Force GC and get baseline memory
	runtime.GC()
	beforeMem := getMemStats()
	queryCounter.Reset()

	pgContainer := getEnvOrDefault("POSTGRES_CONTAINER", "devguard-postgresql-1")
	stopPGSampler, err := samplePostgresContainerMemPeak(ctx, pgContainer)
	if err != nil {
		b.Logf("WARNING: not measuring postgres memory (container %q): %v", pgContainer, err)
	}
	stopGoSampler := sampleGoMemPeak(10 * time.Millisecond)

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

	goPeak := stopGoSampler()
	b.ReportMetric(mb(goPeak.HeapObjects), "go_peak_heap_MB")
	b.ReportMetric(mb(goPeak.Total), "go_peak_runtime_MB")
	b.ReportMetric(mb(processMaxRSS()), "go_max_rss_MB")
	b.Logf("Peak Go process memory:")
	b.Logf("  Heap (live + not yet collected): %.2f MB", mb(goPeak.HeapObjects))
	b.Logf("  Total mapped by Go runtime:      %.2f MB", mb(goPeak.Total))
	b.Logf("  Max RSS (whole process lifetime): %.2f MB", mb(processMaxRSS()))

	if stopPGSampler != nil {
		pgPeak, err := stopPGSampler()
		if err != nil {
			b.Logf("WARNING: postgres memory sampler failed: %v", err)
		}
		b.ReportMetric(mb(pgPeak.AnonPlusShmem), "pg_peak_MB")
		b.ReportMetric(mb(pgPeak.Anon-pgPeak.BaselineAnon), "pg_peak_anon_delta_MB")
		b.Logf("Peak postgres container memory (%d samples):", pgPeak.Samples)
		b.Logf("  anon + shmem:  %.2f MB (baseline %.2f MB)", mb(pgPeak.AnonPlusShmem), mb(pgPeak.BaselineAnon+pgPeak.BaselineShmem))
		b.Logf("  anon (backend-private, work_mem etc.): %.2f MB (baseline %.2f MB)", mb(pgPeak.Anon), mb(pgPeak.BaselineAnon))
		b.Logf("  shmem (shared_buffers):                %.2f MB (baseline %.2f MB)", mb(pgPeak.Shmem), mb(pgPeak.BaselineShmem))
	}

	// Capture memory after benchmark
	runtime.GC()
	afterMem := getMemStats()

	// Report memory metrics
	reportMemoryDiff(b, beforeMem, afterMem)

	// Report DB pressure per run - these are the numbers to watch when
	// optimizing the daemon.
	b.ReportMetric(float64(queryCounter.Calls())/float64(iterations), "db_calls/op")
	b.ReportMetric(float64(queryCounter.Duration().Milliseconds())/float64(iterations), "db_ms/op")
	for _, stat := range queryCounter.TopStats(0) {
		// the paged soft-match query that took 22-24s per page in production
		if strings.Contains(stat.SQL, "DISTINCT ON (signature)") && strings.Contains(stat.SQL, "NOT EXISTS") {
			b.ReportMetric(float64(stat.Duration.Milliseconds())/float64(stat.Calls), "softmatch_ms/page")
		}
	}

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

func mb(bytes uint64) float64 {
	return float64(bytes) / 1024 / 1024
}

// processMaxRSS is the OS-reported peak RSS of this process since it started,
// so it includes test app setup and is an upper bound for the daemon run.
func processMaxRSS() uint64 {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return 0
	}
	// darwin reports bytes, linux kilobytes
	if runtime.GOOS == "darwin" {
		return uint64(usage.Maxrss)
	}
	return uint64(usage.Maxrss) * 1024
}

type goMemPeak struct {
	HeapObjects uint64
	Total       uint64
}

// sampleGoMemPeak polls the runtime until the returned stop func is called.
// Peaks have to be sampled during the run: a GC before reading the numbers
// afterwards would hide exactly the transient spikes that cause OOMs.
// runtime/metrics is used instead of ReadMemStats since it doesn't stop the world.
func sampleGoMemPeak(interval time.Duration) func() goMemPeak {
	samples := []metrics.Sample{
		{Name: "/memory/classes/heap/objects:bytes"},
		{Name: "/memory/classes/total:bytes"},
	}
	var peak goMemPeak
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			metrics.Read(samples)
			peak.HeapObjects = max(peak.HeapObjects, samples[0].Value.Uint64())
			peak.Total = max(peak.Total, samples[1].Value.Uint64())
			select {
			case <-stop:
				return
			case <-ticker.C:
			}
		}
	}()
	return func() goMemPeak {
		close(stop)
		<-done
		return peak
	}
}

type pgMemPeak struct {
	Samples       int
	BaselineAnon  uint64
	BaselineShmem uint64
	Anon          uint64
	Shmem         uint64
	AnonPlusShmem uint64
}

// samplePostgresContainerMemPeak streams the cgroup memory.stat of the
// postgres container. PG16 has no way to inspect the memory of other backends
// from SQL, and the daemon's work happens on its own transaction's backend.
// anon is backend-private memory (work_mem, hash tables, ...), shmem is
// shared_buffers; page cache (file) is left out as the kernel can reclaim it.
func samplePostgresContainerMemPeak(ctx context.Context, container string) (func() (pgMemPeak, error), error) {
	ctx, cancel := context.WithCancel(ctx)
	// cat fails once the client is gone, which ends the loop inside the
	// container - killing `docker exec` alone would leave it running.
	cmd := exec.CommandContext(ctx, "docker", "exec", container, "sh", "-c",
		"while cat /sys/fs/cgroup/memory.stat && echo ---; do sleep 0.05; done")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, err
	}

	var peak pgMemPeak
	var scanErr error
	firstSample := make(chan struct{})
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		scanner := bufio.NewScanner(stdout)
		var anon, shmem uint64
		for scanner.Scan() {
			key, value, _ := strings.Cut(scanner.Text(), " ")
			switch key {
			case "anon":
				anon, _ = strconv.ParseUint(value, 10, 64)
			case "shmem":
				shmem, _ = strconv.ParseUint(value, 10, 64)
			case "---":
				if peak.Samples == 0 {
					peak.BaselineAnon, peak.BaselineShmem = anon, shmem
					close(firstSample)
				}
				peak.Samples++
				peak.Anon = max(peak.Anon, anon)
				peak.Shmem = max(peak.Shmem, shmem)
				peak.AnonPlusShmem = max(peak.AnonPlusShmem, anon+shmem)
			}
		}
		scanErr = scanner.Err()
	}()

	select {
	case <-firstSample:
	case <-exited:
		cancel()
		_ = cmd.Wait()
		return nil, errors.New("docker exec exited before producing a sample")
	case <-time.After(10 * time.Second):
		cancel()
		_ = cmd.Wait()
		return nil, errors.New("timed out waiting for first sample")
	}

	return func() (pgMemPeak, error) {
		cancel()
		<-exited
		_ = cmd.Wait()
		return peak, scanErr
	}, nil
}
