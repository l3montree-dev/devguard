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
	"cmp"
	"context"
	"fmt"
	"maps"
	"math"
	"math/rand/v2"
	"net/http"
	"os"
	"runtime"
	"runtime/metrics"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/daemons"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/fx"
)

// BenchmarkNewScanAsset runs DaemonRunner.NewScanAsset against the local
// development database. A testcontainer database is useless here: it is created
// from migrations only, so there would be no dependencies to match.
//
// The runner is in dry run mode, so every iteration diffs against the same
// stored vulns.
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

	app, _ := NewTestAppWithT(b, db, pool, &TestAppOptions{SuppressLogs: true, DryRunIntegrations: true})
	fixture := &TestFixture{T: b, App: app, DB: db, Pool: pool}
	runner := fixture.CreateDaemonRunner()
	// without it the first iteration commits the found vulns and every later one finds nothing new
	runner.SetDebugOptions(daemons.DebugOptions{DryRun: true})

	sampler := startHeapSampler(20 * time.Millisecond)
	runtime.GC()
	memBefore := getMemStats()
	poolBefore := pool.Stat()
	queries.Reset()

	b.ReportAllocs()
	b.ResetTimer()

	iterations := 0
	for b.Loop() {
		runner.SetDebugOptions(daemons.DebugOptions{DryRun: false})

		if err := runner.NewScanAsset(context.Background()); err != nil {
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

	b.Logf("%d iteration(s) over %d dependencies", iterations, dependencies)
	for _, line := range queries.Report(10, iterations) {
		b.Logf("%s", line)
	}
	b.Logf("Pool: %d acquires, %s waiting",
		poolAfter.AcquireCount()-poolBefore.AcquireCount(),
		(poolAfter.AcquireDuration() - poolBefore.AcquireDuration()).Round(time.Millisecond),
	)
}

// BenchmarkAssetPipeline runs the per asset pipeline stages, everything but the
// scan, over a sample of the local development database's assets and
// extrapolates the duration of a full run from it.
//
// Assets are bucketed by their dependency vuln count on a log10 scale, every
// sampled asset stands in for bucket size / sampled assets of its bucket. Writes
// are rolled back and nothing leaves the process: the third party integrations
// are replaced by an offline stand in and every outbound http request is refused,
// so their network time is not part of the estimate.
//
//	DEVGUARD_BENCH_ASSETS_PER_BUCKET=5 DEVGUARD_BENCH_SEED=1 DEVGUARD_BENCH_STAGES=CollectStats,SyncUpstream \
//		go test -run=^$ -bench=BenchmarkAssetPipeline -benchtime=1x -timeout=60m ./tests/
func BenchmarkAssetPipeline(b *testing.B) {
	db, pool, cleanup := initDevDatabase()
	b.Cleanup(cleanup)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := pool.Ping(ctx); err != nil {
		b.Fatalf("no development database reachable: %v", err)
	}

	perBucket, err := strconv.Atoi(getEnvOrDefault("DEVGUARD_BENCH_ASSETS_PER_BUCKET", "5"))
	if err != nil || perBucket <= 0 {
		b.Fatalf("DEVGUARD_BENCH_ASSETS_PER_BUCKET must be a positive number: %v", err)
	}
	seed, err := strconv.ParseUint(getEnvOrDefault("DEVGUARD_BENCH_SEED", "1"), 10, 64)
	if err != nil {
		b.Fatalf("DEVGUARD_BENCH_SEED must be a positive number: %v", err)
	}
	var stages []string
	if value := os.Getenv("DEVGUARD_BENCH_STAGES"); value != "" {
		stages = strings.Split(value, ",")
	}

	sample, buckets, err := sampleAssetsByVulnCount(db, perBucket, rand.New(rand.NewPCG(seed, seed)))
	if err != nil {
		b.Fatalf("could not sample assets: %v", err)
	}
	if len(sample) == 0 {
		b.Fatal("development database has no assets - the pipeline would measure nothing")
	}
	sampleIDs := make([]uuid.UUID, len(sample))
	for i := range sample {
		sampleIDs[i] = sample[i].id
	}

	recorder := pipelineSpanRecorder()
	queries := NewQueryCounter()
	if err := db.Use(queries); err != nil {
		b.Fatalf("failed to install query counter: %v", err)
	}

	// installed before the app is built, services copy the egress client when they are constructed
	outbound := blockOutboundRequests(b)
	offline := &offlineIntegrationAggregate{}
	app, _ := NewTestAppWithT(b, db, pool, &TestAppOptions{SuppressLogs: true, ExtraOptions: []fx.Option{
		fx.Decorate(func() shared.IntegrationAggregate { return offline }),
		// extra options switch off the default component service mock
		fx.Decorate(func(cs shared.ComponentService) shared.ComponentService { return createMockedComponentService(b, cs) }),
	}})
	fixture := &TestFixture{T: b, App: app, DB: db, Pool: pool}
	runner := fixture.CreateDaemonRunner()
	// without it every iteration would see the writes of the previous one
	runner.SetDebugOptions(daemons.DebugOptions{DryRun: true, LimitToStages: stages})

	sampler := startHeapSampler(20 * time.Millisecond)
	runtime.GC()
	memBefore := getMemStats()
	poolBefore := pool.Stat()
	queries.Reset()
	recorder.Reset()

	b.ReportAllocs()
	b.ResetTimer()

	iterations := 0
	var sampleWall time.Duration
	var failed map[uuid.UUID]error
	for b.Loop() {
		start := time.Now()
		failed = runner.RunDaemonPipelineForAssets(context.Background(), sampleIDs)
		sampleWall += time.Since(start)
		iterations++
	}

	b.StopTimer()

	peakHeap := sampler.stop()
	memAfter := getMemStats()
	poolAfter := pool.Stat()

	// stage spans measure the work of a stage, the waiting between stages is not part of them
	stageTimes := stageTimesPerAsset(recorder)
	sampleStages := make(map[string]time.Duration)
	estimatedStages := make(map[string]time.Duration)
	bucketTimes := make([]time.Duration, len(buckets))
	for _, asset := range sample {
		for stage, total := range stageTimes[asset.id] {
			perIteration := total / time.Duration(iterations)
			sampleStages[stage] += perIteration
			estimatedStages[stage] += time.Duration(float64(perIteration) * asset.weight)
			bucketTimes[asset.bucket] += perIteration
		}
	}

	stageNames := slices.SortedFunc(maps.Keys(estimatedStages), func(x, y string) int {
		return cmp.Compare(estimatedStages[y], estimatedStages[x])
	})
	if len(stageNames) == 0 {
		b.Fatal("no stage spans were recorded")
	}
	var sampleSequential, estimatedSequential time.Duration
	for _, stage := range stageNames {
		sampleSequential += sampleStages[stage]
		estimatedSequential += estimatedStages[stage]
	}
	sampleBusiest := slices.Max(slices.Collect(maps.Values(sampleStages)))
	estimatedBusiest := estimatedStages[stageNames[0]]
	averageWall := sampleWall / time.Duration(iterations)
	// the stages overlap across assets, a full run is expected to overlap as well as the sample did
	estimatedFullRun := min(max(time.Duration(float64(estimatedBusiest)*float64(averageWall)/float64(sampleBusiest)), estimatedBusiest), estimatedSequential)

	b.ReportMetric(estimatedFullRun.Seconds(), "est_full_run_s")
	b.ReportMetric(estimatedBusiest.Seconds(), "est_full_run_min_s")
	b.ReportMetric(estimatedSequential.Seconds(), "est_full_run_max_s")
	b.ReportMetric(float64(len(sample)), "sample_assets")
	b.ReportMetric(float64(peakHeap)/1024/1024, "peak_heap_MB")
	b.ReportMetric(float64(memAfter.TotalAllocBytes-memBefore.TotalAllocBytes)/1024/1024/float64(iterations), "total_alloc_MB/op")
	b.ReportMetric(float64(queries.Calls())/float64(iterations), "db_calls/op")
	b.ReportMetric(float64(queries.Duration().Milliseconds())/float64(iterations), "db_ms/op")

	// benchmarks cut their b.Log output after 10 lines, the report is longer
	report := func(format string, args ...any) { fmt.Printf(format+"\n", args...) }
	report("%d iteration(s) over %d sampled assets, %d failed in the last iteration", iterations, len(sample), len(failed))
	for assetID, err := range failed {
		report("  failed asset %s: %v", assetID, err)
	}
	report("Buckets:")
	for i, bucket := range buckets {
		if bucket.sampled == 0 {
			continue
		}
		report("  %-18s %6d assets, %3d sampled, %s per asset", bucket.label, bucket.assets, bucket.sampled, (bucketTimes[i] / time.Duration(bucket.sampled)).Round(time.Millisecond))
	}
	report("Stages (sample -> extrapolated):")
	for _, stage := range stageNames {
		report("  %-34s %12s -> %s", stage, sampleStages[stage].Round(time.Millisecond), estimatedStages[stage].Round(time.Second))
	}
	report("Sample run: %s wall, busiest stage %s, stages back to back %s",
		averageWall.Round(time.Millisecond), sampleBusiest.Round(time.Millisecond), sampleSequential.Round(time.Millisecond))
	report("Full run estimate: %s (%s with perfect stage overlap, %s with stages back to back)",
		estimatedFullRun.Round(time.Second), estimatedBusiest.Round(time.Second), estimatedSequential.Round(time.Second))
	for _, line := range queries.Report(10, iterations) {
		report("%s", line)
	}
	report("Pool: %d acquires, %s waiting",
		poolAfter.AcquireCount()-poolBefore.AcquireCount(),
		(poolAfter.AcquireDuration() - poolBefore.AcquireDuration()).Round(time.Millisecond),
	)
	report("Stopped external calls over all iterations: %d issues created, %d issues updated, %d labels created, %d ticket state comparisons, %d events",
		offline.issuesCreated.Load(), offline.issuesUpdated.Load(), offline.labelsCreated.Load(), offline.ticketComparisons.Load(), offline.events.Load())
	for host, count := range outbound.blockedByHost() {
		report("  refused %d http request(s) to %s", count, host)
	}
}

// blockOutboundRequests refuses every request of the shared egress transports and the default transport until the benchmark ends
func blockOutboundRequests(b *testing.B) *blockingTransport {
	transport := &blockingTransport{blocked: make(map[string]int)}
	egressTransport, egressClientTransport, defaultTransport := utils.EgressTransport, utils.EgressClient.Transport, http.DefaultTransport
	utils.EgressTransport, utils.EgressClient.Transport, http.DefaultTransport = transport, transport, transport
	b.Cleanup(func() {
		utils.EgressTransport, utils.EgressClient.Transport, http.DefaultTransport = egressTransport, egressClientTransport, defaultTransport
	})
	return transport
}

type blockingTransport struct {
	mu      sync.Mutex
	blocked map[string]int
}

func (transport *blockingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		req.Body.Close()
	}
	transport.mu.Lock()
	transport.blocked[req.URL.Host]++
	transport.mu.Unlock()
	return nil, fmt.Errorf("outbound request to %s refused by the benchmark", req.URL.Host)
}

func (transport *blockingTransport) blockedByHost() map[string]int {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return maps.Clone(transport.blocked)
}

// offlineIntegrationAggregate replaces every third party integration and forwards nothing, unlike the dry run integration it does not read from them either
type offlineIntegrationAggregate struct {
	issuesCreated     atomic.Int64
	issuesUpdated     atomic.Int64
	labelsCreated     atomic.Int64
	ticketComparisons atomic.Int64
	events            atomic.Int64
}

var _ shared.IntegrationAggregate = &offlineIntegrationAggregate{}

func (offline *offlineIntegrationAggregate) WantsToHandleWebhook(ctx shared.Context) bool {
	return false
}

func (offline *offlineIntegrationAggregate) HandleWebhook(ctx shared.Context) error {
	return nil
}

func (offline *offlineIntegrationAggregate) ListOrgs(ctx shared.Context) ([]models.Org, error) {
	return nil, nil
}

func (offline *offlineIntegrationAggregate) ListGroups(ctx context.Context, userID string, providerID string) ([]models.Project, []shared.Role, error) {
	return nil, nil, nil
}

func (offline *offlineIntegrationAggregate) ListProjects(ctx context.Context, userID string, providerID string, groupID string) ([]models.Asset, []shared.Role, error) {
	return nil, nil, nil
}

func (offline *offlineIntegrationAggregate) ListRepositories(ctx shared.Context) ([]dtos.GitRepository, error) {
	return nil, nil
}

func (offline *offlineIntegrationAggregate) HandleEvent(ctx context.Context, event any, userAgent *string) error {
	offline.events.Add(1)
	return nil
}

func (offline *offlineIntegrationAggregate) CreateIssue(ctx context.Context, asset models.Asset, assetVersionName string, vuln models.Vuln, projectSlug string, orgSlug string, justification string, userID string, userAgent *string) error {
	offline.issuesCreated.Add(1)
	return nil
}

func (offline *offlineIntegrationAggregate) UpdateIssue(ctx context.Context, asset models.Asset, assetVersionSlug string, vuln models.Vuln, userAgent *string) error {
	offline.issuesUpdated.Add(1)
	return nil
}

func (offline *offlineIntegrationAggregate) CreateLabels(ctx context.Context, asset models.Asset) error {
	offline.labelsCreated.Add(1)
	return nil
}

func (offline *offlineIntegrationAggregate) CompareIssueStatesAndResolveDifferences(ctx context.Context, asset models.Asset, vulnsWithTickets []models.DependencyVuln) error {
	offline.ticketComparisons.Add(1)
	return nil
}

func (offline *offlineIntegrationAggregate) GetExcessTicketIDs(ctx context.Context, asset models.Asset, vulnsWithTickets []models.DependencyVuln) ([]string, error) {
	return nil, nil
}

func (offline *offlineIntegrationAggregate) GetID() shared.IntegrationID {
	return shared.AggregateID
}

// callers must not reach a real integration through the aggregate either
func (offline *offlineIntegrationAggregate) GetIntegration(id shared.IntegrationID) shared.ThirdPartyIntegration {
	return offline
}

func (offline *offlineIntegrationAggregate) GetUsers(org models.Org) []dtos.UserDTO {
	return nil
}

type sampledAsset struct {
	id     uuid.UUID
	bucket int
	// the number of assets of the bucket this asset stands in for
	weight float64
}

type vulnCountBucket struct {
	label   string
	assets  int
	sampled int
}

// sampleAssetsByVulnCount buckets the assets by the number of digits of their dependency vuln count and draws up to perBucket assets from each
func sampleAssetsByVulnCount(db shared.DB, perBucket int, rng *rand.Rand) ([]sampledAsset, []vulnCountBucket, error) {
	var population []struct {
		ID    uuid.UUID
		Vulns int64
	}
	// ordered, so the same seed draws the same sample
	err := db.Raw(`
		SELECT a.id, count(dv.id) AS vulns
		FROM assets a
		LEFT JOIN dependency_vulns dv ON dv.asset_id = a.id
		GROUP BY a.id
		ORDER BY a.id;`).Scan(&population).Error
	if err != nil {
		return nil, nil, err
	}

	byBucket := make([][]uuid.UUID, 1)
	for _, asset := range population {
		bucket := 0
		if asset.Vulns > 0 {
			bucket = len(strconv.FormatInt(asset.Vulns, 10))
		}
		for len(byBucket) <= bucket {
			byBucket = append(byBucket, nil)
		}
		byBucket[bucket] = append(byBucket[bucket], asset.ID)
	}

	sample := make([]sampledAsset, 0, len(byBucket)*perBucket)
	buckets := make([]vulnCountBucket, len(byBucket))
	for bucket, ids := range byBucket {
		rng.Shuffle(len(ids), func(i, j int) { ids[i], ids[j] = ids[j], ids[i] })
		picked := ids[:min(perBucket, len(ids))]
		buckets[bucket] = vulnCountBucket{label: vulnBucketLabel(bucket), assets: len(ids), sampled: len(picked)}
		for _, id := range picked {
			sample = append(sample, sampledAsset{id: id, bucket: bucket, weight: float64(len(ids)) / float64(len(picked))})
		}
	}
	// a full run does not process the assets ordered by size either
	rng.Shuffle(len(sample), func(i, j int) { sample[i], sample[j] = sample[j], sample[i] })
	return sample, buckets, nil
}

func vulnBucketLabel(bucket int) string {
	if bucket == 0 {
		return "0 vulns"
	}
	lower := int64(math.Pow10(bucket - 1))
	return fmt.Sprintf("%d-%d vulns", lower, lower*10-1)
}

// the daemon tracer only delegates to the first global tracer provider, so it is set once per process
var pipelineSpanRecorder = sync.OnceValue(func() *tracetest.SpanRecorder {
	recorder := tracetest.NewSpanRecorder()
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder)))
	return recorder
})

// stageTimesPerAsset sums the durations of the stage spans per asset, stages are the children of the pipeline.asset root spans
func stageTimesPerAsset(recorder *tracetest.SpanRecorder) map[uuid.UUID]map[string]time.Duration {
	// roots of failed assets are not always ended, their start carries the asset id already
	roots := make(map[trace.SpanID]uuid.UUID)
	for _, span := range recorder.Started() {
		if span.Name() != "pipeline.asset" {
			continue
		}
		for _, kv := range span.Attributes() {
			if kv.Key != "asset.id" {
				continue
			}
			if assetID, err := uuid.Parse(kv.Value.AsString()); err == nil {
				roots[span.SpanContext().SpanID()] = assetID
			}
		}
	}

	times := make(map[uuid.UUID]map[string]time.Duration, len(roots))
	for _, span := range recorder.Ended() {
		assetID, ok := roots[span.Parent().SpanID()]
		if !ok {
			continue
		}
		if times[assetID] == nil {
			times[assetID] = make(map[string]time.Duration)
		}
		times[assetID][span.Name()] += span.EndTime().Sub(span.StartTime())
	}
	return times
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
