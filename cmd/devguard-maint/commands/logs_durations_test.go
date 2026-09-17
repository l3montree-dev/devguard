package commands

import (
	"testing"
	"time"
)

func TestParseRequest(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		wantOk     bool
		wantMethod string
		wantStatus int
		wantDur    time.Duration
		wantRoute  string
	}{
		{
			name:       "bare url",
			raw:        "8:34AM INF middlewares/logging_middleware.go:34 handled request method=GET url=/api/v1/info/ status=200 duration=2.017011ms",
			wantOk:     true,
			wantMethod: "GET",
			wantStatus: 200,
			wantDur:    2017011 * time.Nanosecond,
			wantRoute:  "/api/v1/info/",
		},
		{
			name:       "quoted url with query string",
			raw:        `8:34AM INF middlewares/logging_middleware.go:34 handled request method=GET url="/api/v1/organizations/%40opencode/projects/p1/assets/base/refs/main/stats/risk-history/?start=2026-06-16&end=2026-09-16" status=200 duration=22.155386656s`,
			wantOk:     true,
			wantMethod: "GET",
			wantStatus: 200,
			wantDur:    22155386656 * time.Nanosecond,
			wantRoute:  "/api/v1/organizations/{org}/projects/{project}/assets/{asset}/refs/{ref}/stats/risk-history/",
		},
		{
			name:       "microsecond duration",
			raw:        "7:40AM INF middlewares/logging_middleware.go:34 handled request method=POST url=/api/v1/webhook/ status=200 duration=478.611µs",
			wantOk:     true,
			wantMethod: "POST",
			wantStatus: 200,
			wantDur:    478611 * time.Nanosecond,
			wantRoute:  "/api/v1/webhook/",
		},
		{
			name:   "not a request entry",
			raw:    "8:34AM INF daemons/daemon_asset_pipeline.go:669 synced upstream for asset version assetVersionName=wget",
			wantOk: false,
		},
		{
			name:   "request marker without a duration",
			raw:    "8:34AM INF middlewares/logging_middleware.go:34 handled request method=GET url=/api/v1/info/ status=200",
			wantOk: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, ok := apiFormat.parse(tt.raw)
			if !ok {
				t.Fatalf("api format did not parse the line")
			}
			r, ok := parseRequest(e)
			if ok != tt.wantOk {
				t.Fatalf("parseRequest ok=%v, want %v", ok, tt.wantOk)
			}
			if !ok {
				return
			}
			if r.method != tt.wantMethod {
				t.Errorf("method=%q, want %q", r.method, tt.wantMethod)
			}
			if r.status != tt.wantStatus {
				t.Errorf("status=%d, want %d", r.status, tt.wantStatus)
			}
			if r.dur != tt.wantDur {
				t.Errorf("duration=%v, want %v", r.dur, tt.wantDur)
			}
			if r.route != tt.wantRoute {
				t.Errorf("route=%q, want %q", r.route, tt.wantRoute)
			}
		})
	}
}

func TestNormalizeRoute(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		// absolute urls lose scheme and host
		{
			"http://api.devguard.opencode.de/api/v1/organizations/@opencode/projects/negotiatecop/assets/core/refs/dev/dependency-vulns/?pageSize=100",
			"/api/v1/organizations/{org}/projects/{project}/assets/{asset}/refs/{ref}/dependency-vulns/",
		},
		// percent encoded org resolves to the same route as the bare spelling
		{
			"/api/v1/organizations/%40opencode/projects/p/assets/a/",
			"/api/v1/organizations/{org}/projects/{project}/assets/{asset}/",
		},
		// a named sub-route under an id parent is not mistaken for an id
		{
			"/api/v1/organizations/@o/projects/p/assets/a/vex-rules/recommendations/",
			"/api/v1/organizations/{org}/projects/{project}/assets/{asset}/vex-rules/recommendations/",
		},
		// but a real id under the same parent is collapsed
		{
			"/api/v1/organizations/@o/projects/p/assets/a/vex-rules/6c56a09c-c7ad-4f31-b91d-bc5f71598698/",
			"/api/v1/organizations/{org}/projects/{project}/assets/{asset}/vex-rules/{ruleID}/",
		},
		// ids under routes not enumerated still collapse
		{
			"/api/v1/vulndb/CVE-2024-1234/",
			"/api/v1/vulndb/{cveID}/",
		},
		{"/api/v1/info/", "/api/v1/info/"},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			if got := normalizeRoute(tt.raw); got != tt.want {
				t.Errorf("normalizeRoute(%q)\n got %q\nwant %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestPercentile(t *testing.T) {
	in := []time.Duration{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	tests := []struct {
		p    int
		want time.Duration
	}{
		{50, 5}, {90, 9}, {95, 10}, {99, 10}, {100, 10},
	}
	for _, tt := range tests {
		if got := percentile(in, tt.p); got != tt.want {
			t.Errorf("percentile(p%d)=%v, want %v", tt.p, got, tt.want)
		}
	}
	if got := percentile(nil, 95); got != 0 {
		t.Errorf("percentile of empty=%v, want 0", got)
	}
}

// The api log carries a wall clock with no date, which time.Parse resolves to
// year 0 - before Go's zero Time. Bucket range tracking must not rely on
// comparisons against the zero value, or the range collapses and gaps vanish.
func TestBuildBucketsFillsGapsInUndatedLog(t *testing.T) {
	at := func(hhmm string) time.Time {
		ts, err := time.Parse("15:04", hhmm)
		if err != nil {
			t.Fatalf("bad test time %q: %v", hhmm, err)
		}
		return ts
	}
	reqs := []requestSample{
		{ts: at("08:24"), dur: time.Second},
		{ts: at("08:28"), dur: time.Second},
	}

	rows := buildBuckets(reqs, bucketMinute)
	if len(rows) != 5 {
		t.Fatalf("got %d rows, want 5 (08:24..08:28 inclusive)", len(rows))
	}
	wantGap := []bool{false, true, true, true, false}
	for i, want := range wantGap {
		if rows[i].gap != want {
			t.Errorf("rows[%d] (%s) gap=%v, want %v", i, rows[i].label, rows[i].gap, want)
		}
	}
}

// A request completing at 08:28 after running three minutes was in flight
// through the buckets that completed nothing, which is what distinguishes a
// stalled process from an idle one.
func TestCountInflightSpansTheWholeRequest(t *testing.T) {
	at := func(hhmm string) time.Time {
		ts, _ := time.Parse("15:04", hhmm)
		return ts
	}
	reqs := []requestSample{{ts: at("08:28"), dur: 3 * time.Minute}}
	rows := buildBuckets(reqs, bucketMinute)

	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	// the single completion bucket is also the whole clamped range here, so
	// check the unclamped helper directly
	inflight := countInflight(reqs, at("08:24"), at("08:28"), time.Minute)
	for _, label := range []string{"08:25", "08:26", "08:27", "08:28"} {
		if got := inflight[at(label)]; got != 1 {
			t.Errorf("inflight at %s = %d, want 1", label, got)
		}
	}
}

func TestMarkSlowTreatsGapAsSlow(t *testing.T) {
	rows := []bucketRow{
		{s: durStats{p95: time.Second}},
		{gap: true},
		{s: durStats{p95: time.Minute}},
	}
	markSlow(rows, 30*time.Second)
	want := []bool{false, true, true}
	for i, w := range want {
		if rows[i].slow != w {
			t.Errorf("rows[%d].slow=%v, want %v", i, rows[i].slow, w)
		}
	}
}
