package commands

import (
	"strings"
	"testing"
	"time"
)

// The prefix is stripped for every format; continuation indentation survives.
func TestStripK8sTimestamp(t *testing.T) {
	line, ts := stripK8sTimestamp("2026-08-11T14:11:48.123456789Z ⨯ Error: boom")
	if line != "⨯ Error: boom" {
		t.Errorf("line=%q, want %q", line, "⨯ Error: boom")
	}
	if ts.IsZero() || ts.UTC().Format("15:04:05") != "14:11:48" {
		t.Errorf("ts=%v, want 14:11:48", ts)
	}

	// indentation after the separating space survives
	line, ts = stripK8sTimestamp("2026-08-11T14:11:48Z     at h (chunk.js:2:296)")
	if line != "    at h (chunk.js:2:296)" {
		t.Errorf("indentation was lost: %q", line)
	}
	if ts.IsZero() {
		t.Error("expected a timestamp")
	}

	if line, ts := stripK8sTimestamp("2:11PM ERR foo.go:1 bar"); line != "2:11PM ERR foo.go:1 bar" || !ts.IsZero() {
		t.Errorf("unprefixed line was altered: %q / %v", line, ts)
	}
}

// A web log collected with --timestamps becomes fully timed, stack frames still
// folded.
func TestK8sTimestampsMakeWebCorrelatable(t *testing.T) {
	content := `2026-08-11T14:11:00Z ⨯ Error: {"message":"Could not fetch group"}
2026-08-11T14:11:00Z     at h (.next/server/chunks/ssr/src_0t4fn29._.js:2:296)
2026-08-11T14:11:00Z   digest: '2028629024'
2026-08-11T14:11:00Z }
2026-08-11T14:11:05Z ✓ Ready in 0ms
`
	p, err := readLog(writeTempLog(t, content), "auto")
	if err != nil {
		t.Fatal(err)
	}
	if p.format.name != webFormat.name {
		t.Fatalf("detected %q, want web", p.format.name)
	}
	if len(p.entries) != 2 {
		for i, e := range p.entries {
			t.Logf("entry %d: %s", i, e.message)
		}
		t.Fatalf("got %d p.entries, want 2", len(p.entries))
	}
	for i, e := range p.entries {
		if e.ts.IsZero() || !e.hasDate {
			t.Errorf("entry %d has no absolute timestamp", i)
		}
	}
	if p.entries[0].source != "digest:2028629024" {
		t.Errorf("digest was not picked up through the timestamp prefix: %q", p.entries[0].source)
	}
	if p.entries[0].ts.UTC().Format("15:04:05") != "14:11:00" {
		t.Errorf("entry 0 ts=%v, want 14:11:00", p.entries[0].ts)
	}
}

func TestParseOffsets(t *testing.T) {
	got, err := parseOffsets([]string{"api=+2h", "3=-90s"})
	if err != nil {
		t.Fatal(err)
	}
	if got["api"] != 2*time.Hour {
		t.Errorf("api offset=%v, want 2h", got["api"])
	}
	if got["3"] != -90*time.Second {
		t.Errorf("3 offset=%v, want -90s", got["3"])
	}
	if _, err := parseOffsets([]string{"api"}); err == nil {
		t.Error("expected an error for a missing =DURATION")
	}
	if _, err := parseOffsets([]string{"api=nonsense"}); err == nil {
		t.Error("expected an error for an unparseable duration")
	}
}

// The api log prints a clock with no date; anchoring places it on the dated logs'
// day.
func TestAnchorSourceSameDay(t *testing.T) {
	s := &logSource{format: apiFormat}
	for _, raw := range []string{
		"1:55PM ERR a.go:1 first",
		"2:11PM ERR a.go:2 middle",
		"2:16PM INF a.go:3 last",
	} {
		e, ok := apiFormat.parse(raw)
		if !ok {
			t.Fatalf("failed to parse %q", raw)
		}
		s.entries = append(s.entries, e)
	}

	anchorSource(s, time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC))

	want := []string{"2026-08-11 13:55", "2026-08-11 14:11", "2026-08-11 14:16"}
	for i, w := range want {
		got := s.entries[i].ts.UTC().Format("2006-01-02 15:04")
		if got != w {
			t.Errorf("entry %d anchored to %s, want %s", i, got, w)
		}
		if !s.entries[i].hasDate {
			t.Errorf("entry %d still has no date", i)
		}
	}
	if s.anchoredTo != "2026-08-11" {
		t.Errorf("anchoredTo=%q, want 2026-08-11", s.anchoredTo)
	}
}

// A log that runs past midnight goes backwards on the clock; the day has to roll
// forward so the p.entries stay in order, and the last entry still lands on the
// reference date.
func TestAnchorSourceRollsOverMidnight(t *testing.T) {
	s := &logSource{format: apiFormat}
	for _, raw := range []string{
		"11:58PM INF a.go:1 before midnight",
		"12:01AM INF a.go:2 after midnight",
		"12:05AM INF a.go:3 later",
	} {
		e, _ := apiFormat.parse(raw)
		s.entries = append(s.entries, e)
	}

	anchorSource(s, time.Date(2026, 8, 11, 0, 0, 0, 0, time.UTC))

	want := []string{"2026-08-10 23:58", "2026-08-11 00:01", "2026-08-11 00:05"}
	for i, w := range want {
		got := s.entries[i].ts.UTC().Format("2006-01-02 15:04")
		if got != w {
			t.Errorf("entry %d anchored to %s, want %s", i, got, w)
		}
	}
	// p.entries must come out strictly ordered
	for i := 1; i < len(s.entries); i++ {
		if s.entries[i].ts.Before(s.entries[i-1].ts) {
			t.Errorf("entry %d goes backwards in time", i)
		}
	}
}

func TestAlignSourcesAnchorsUndatedAgainstDated(t *testing.T) {
	apiPath := writeTempLog(t, "1:55PM ERR a.go:1 boom\n2:11PM ERR a.go:2 boom\n")
	kratosPath := writeTempLog(t,
		"time=2026-08-11T13:50:00Z level=info msg=start\n"+
			"time=2026-08-11T14:20:00Z level=info msg=end\n")

	sources, err := loadSources([]string{apiPath, kratosPath}, "auto", nil)
	if err != nil {
		t.Fatal(err)
	}
	if sources[0].dated {
		t.Fatal("the api source should not be dated before alignment")
	}
	if !sources[0].timed {
		t.Fatal("the api source should be timed")
	}
	if err := alignSources(sources, ""); err != nil {
		t.Fatal(err)
	}
	if !sources[0].dated {
		t.Fatal("the api source should be dated after alignment")
	}
	if got := sources[0].entries[1].ts.UTC().Format("2006-01-02 15:04"); got != "2026-08-11 14:11" {
		t.Errorf("api entry anchored to %s, want 2026-08-11 14:11", got)
	}
}

func TestAlignSourcesHonoursForcedDate(t *testing.T) {
	apiPath := writeTempLog(t, "2:11PM ERR a.go:1 boom\n")
	sources, err := loadSources([]string{apiPath}, "auto", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := alignSources(sources, "2026-01-02"); err != nil {
		t.Fatal(err)
	}
	if got := sources[0].entries[0].ts.UTC().Format("2006-01-02 15:04"); got != "2026-01-02 14:11" {
		t.Errorf("anchored to %s, want 2026-01-02 14:11", got)
	}
	if err := alignSources(sources, "not-a-date"); err == nil {
		t.Error("expected an error for a malformed --date")
	}
}

// Nothing dated: sources stay on a time-of-day timeline.
func TestAlignSourcesLeavesUndatedAloneWhenNothingIsDated(t *testing.T) {
	apiPath := writeTempLog(t, "2:11PM ERR a.go:1 boom\n")
	sources, err := loadSources([]string{apiPath}, "auto", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := alignSources(sources, ""); err != nil {
		t.Fatal(err)
	}
	if sources[0].dated {
		t.Error("no date should have been invented")
	}
}

func TestLoadSourcesAppliesOffsetAndRejectsUnmatchedKey(t *testing.T) {
	path := writeTempLog(t, "time=2026-08-11T14:11:00Z level=info msg=hi\n")

	sources, err := loadSources([]string{path}, "auto", map[string]time.Duration{"kratos": 2 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if got := sources[0].entries[0].ts.UTC().Format("15:04"); got != "16:11" {
		t.Errorf("offset not applied: ts=%s, want 16:11", got)
	}

	if _, err := loadSources([]string{path}, "auto", map[string]time.Duration{"nope": time.Hour}); err == nil {
		t.Error("expected an error when --offset matches no file")
	}
}

// Files sharing a format fall back to file-name labels.
func TestLoadSourcesDisambiguatesLabels(t *testing.T) {
	a := writeTempLogNamed(t, "kratos-a.log", "time=2026-08-11T14:11:00Z level=info msg=hi\n")
	b := writeTempLogNamed(t, "kratos-b.log", "time=2026-08-11T14:12:00Z level=info msg=hi\n")
	sources, err := loadSources([]string{a, b}, "auto", nil)
	if err != nil {
		t.Fatal(err)
	}
	if sources[0].label == sources[1].label {
		t.Errorf("both sources labelled %q", sources[0].label)
	}
	if sources[0].label != "kratos-a" || sources[1].label != "kratos-b" {
		t.Errorf("labels fell back to %q/%q, want the file names", sources[0].label, sources[1].label)
	}
}

func TestParseAround(t *testing.T) {
	ref := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	tests := map[string]string{
		"14:11":                "2026-08-11 14:11:00",
		"14:11:30":             "2026-08-11 14:11:30",
		"2:11PM":               "2026-08-11 14:11:00",
		"2026-08-11 14:11":     "2026-08-11 14:11:00",
		"2026-08-09 09:05:03":  "2026-08-09 09:05:03",
		"2026-08-11T14:11:00Z": "2026-08-11 14:11:00",
	}
	for in, want := range tests {
		got, err := parseAround(in, ref)
		if err != nil {
			t.Errorf("parseAround(%q) failed: %v", in, err)
			continue
		}
		if s := got.UTC().Format("2006-01-02 15:04:05"); s != want {
			t.Errorf("parseAround(%q) = %s, want %s", in, s, want)
		}
	}
	if _, err := parseAround("half past nine", ref); err == nil {
		t.Error("expected an error for unparseable input")
	}
}

func TestCorrelateCell(t *testing.T) {
	if got := correlateCell(nil); got != "·" {
		t.Errorf("empty cell = %q, want ·", got)
	}
	if got := correlateCell(map[string]int{levelInfo: 5}); got != "5" {
		t.Errorf("cell = %q, want 5", got)
	}
	// FTL counts as an error
	if got := correlateCell(map[string]int{levelInfo: 5, levelError: 2}); got != "7/2" {
		t.Errorf("cell = %q, want 7/2", got)
	}
	if got := correlateCell(map[string]int{levelFatal: 1, levelInfo: 1}); got != "2/1" {
		t.Errorf("cell = %q, want 2/1", got)
	}
}

func TestBucketLabel(t *testing.T) {
	ts := time.Date(2026, 8, 11, 14, 11, 48, 0, time.UTC)
	for _, tc := range []struct {
		bucket   bucketSize
		allDated bool
		want     string
	}{
		{bucketMinute, true, "2026-08-11 14:11"},
		{bucketSecond, true, "2026-08-11 14:11:48"},
		{bucketHour, true, "2026-08-11 14"},
		{bucketMinute, false, "14:11"},
	} {
		if got := bucketLabel(ts, tc.bucket, tc.allDated); got != tc.want {
			t.Errorf("bucketLabel(%s, allDated=%v) = %q, want %q", tc.bucket, tc.allDated, got, tc.want)
		}
	}
}

func TestMatchesOffsetKey(t *testing.T) {
	s := &logSource{idx: 2, path: "/logs/devguard-api-deployment.log", format: apiFormat}
	for _, key := range []string{"2", "api", "devguard-api-deployment.log", "devguard-api-deployment"} {
		if !s.matchesOffsetKey(key) {
			t.Errorf("key %q should match", key)
		}
	}
	if s.matchesOffsetKey("kratos") {
		t.Error("key \"kratos\" should not match an api source")
	}
}

func TestIsErrorLevel(t *testing.T) {
	for _, l := range []string{levelError, levelFatal} {
		if !isErrorLevel(l) {
			t.Errorf("%s should count as an error", l)
		}
	}
	for _, l := range []string{levelInfo, levelWarn, levelDebug} {
		if isErrorLevel(l) {
			t.Errorf("%s should not count as an error", l)
		}
	}
}

// End-to-end check through logsCorrelate.
func TestLogsCorrelateMixedFormats(t *testing.T) {
	apiPath := writeTempLog(t, "2:11PM ERR middlewares/server.go:73 code=404, message=could not find project\n")
	kratosPath := writeTempLog(t, "time=2026-08-11T14:11:20Z level=info msg=completed handling request http_request=map[path:/sessions/whoami] http_response=map[status:200]\n")
	pgPath := writeTempLog(t, "2026-08-11 14:11:30.000 UTC [14] LOG:  checkpoint starting: time\n")

	if err := logsCorrelate([]string{apiPath, kratosPath, pgPath}, "auto", correlateOptions{
		bucket: "minute",
		around: "14:11",
		window: "1m",
	}); err != nil {
		t.Fatalf("logsCorrelate failed: %v", err)
	}
}

func TestLogsCorrelateRejectsBadFlags(t *testing.T) {
	p := writeTempLog(t, "time=2026-08-11T14:11:00Z level=info msg=hi\n")
	q := writeTempLog(t, "time=2026-08-11T14:12:00Z level=info msg=hi\n")

	for name, opts := range map[string]correlateOptions{
		"bucket": {bucket: "fortnight"},
		"offset": {bucket: "minute", offsets: []string{"bogus"}},
		"window": {bucket: "minute", around: "14:11", window: "soon"},
		"around": {bucket: "minute", around: "half past nine", window: "1m"},
	} {
		if err := logsCorrelate([]string{p, q}, "auto", opts); err == nil {
			t.Errorf("expected an error for a bad --%s", name)
		} else if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(name)) &&
			name != "around" && name != "offset" {
			t.Errorf("error for --%s should mention it: %v", name, err)
		}
	}
}
