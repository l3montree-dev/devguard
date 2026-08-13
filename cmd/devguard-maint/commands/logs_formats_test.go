package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTempLog(t *testing.T, content string) string {
	return writeTempLogNamed(t, "test.log", content)
}

func writeTempLogNamed(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestKratosParse(t *testing.T) {
	tests := []struct {
		name        string
		raw         string
		wantLevel   string
		wantMessage string
		wantSource  string
	}{
		{
			name:        "request with path",
			raw:         "time=2026-08-11T14:11:48Z level=info msg=started handling request http_request=map[headers:map[accept:*/*] host:127.0.0.1 method:GET path:/sessions/whoami query:<nil>]",
			wantLevel:   levelInfo,
			wantMessage: "started handling request",
			wantSource:  "/sessions/whoami",
		},
		{
			// status is folded in so 200 and 401 on one path stay distinct
			name:        "response carries status",
			raw:         "time=2026-08-11T14:11:48Z level=info msg=completed handling request http_request=map[method:GET path:/sessions/whoami] http_response=map[size:16 status:200 text_status:OK]",
			wantLevel:   levelInfo,
			wantMessage: "completed handling request status=200",
			wantSource:  "/sessions/whoami",
		},
		{
			// a bare msg= runs until the next logfmt key, not the next space
			name:        "unquoted msg stops at next key",
			raw:         "time=2026-08-11T13:42:08Z level=warning msg=A configuration for a non-existing hook was found and will be ignored. audience=application for= hook=two_step_registration",
			wantLevel:   levelWarn,
			wantMessage: "A configuration for a non-existing hook was found and will be ignored.",
			wantSource:  "",
		},
		{
			name:        "error level",
			raw:         "time=2026-08-11T14:11:48Z level=error msg=something broke",
			wantLevel:   levelError,
			wantMessage: "something broke",
			wantSource:  "",
		},
		{
			name:        "nil path is not a source",
			raw:         "time=2026-08-11T14:11:48Z level=info msg=hi http_request=map[path:<nil>]",
			wantLevel:   levelInfo,
			wantMessage: "hi",
			wantSource:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, ok := kratosFormat.parse(tt.raw)
			if !ok {
				t.Fatalf("parse failed for %q", tt.raw)
			}
			if e.level != tt.wantLevel {
				t.Errorf("level=%q, want %q", e.level, tt.wantLevel)
			}
			if e.message != tt.wantMessage {
				t.Errorf("message=%q, want %q", e.message, tt.wantMessage)
			}
			if e.source != tt.wantSource {
				t.Errorf("source=%q, want %q", e.source, tt.wantSource)
			}
			if e.ts.IsZero() || !e.hasDate {
				t.Errorf("expected an absolute timestamp, got ts=%v hasDate=%v", e.ts, e.hasDate)
			}
		})
	}
}

func TestKratosRejectsOtherFormats(t *testing.T) {
	if _, ok := kratosFormat.parse("2:11PM ERR middlewares/server.go:73 code=404"); ok {
		t.Error("kratos parser accepted a zerolog line")
	}
}

// A single postgres event spans a severity line plus DETAIL/HINT annotations.
// Counting those as separate p.entries inflates every total threefold, which is
// the whole reason the format declares a continuation func.
func TestPostgresFoldsAnnotations(t *testing.T) {
	content := `2026-08-11 14:40:49.332 UTC [108184] WARNING:  database "devguard" has a collation version mismatch
2026-08-11 14:40:49.332 UTC [108184] DETAIL:  The database was created using collation version 2.40, but the operating system provides version 2.42.
2026-08-11 14:40:49.332 UTC [108184] HINT:  Rebuild all objects in this database that use the default collation.
2026-08-11 14:41:00.000 UTC [14] LOG:  checkpoint starting: time
2026-08-11 09:55:16.174 UTC [104419] ERROR:  canceling statement due to user request
2026-08-11 09:55:16.174 UTC [104419] STATEMENT:  SELECT 1
	FROM wrapped_statement_body
`
	p, err := readLog(writeTempLog(t, content), "auto")
	if err != nil {
		t.Fatal(err)
	}
	if p.format.name != postgresFormat.name {
		t.Fatalf("detected %q, want postgres", p.format.name)
	}
	if len(p.entries) != 3 {
		for i, e := range p.entries {
			t.Logf("entry %d: level=%s msg=%s", i, e.level, e.message)
		}
		t.Fatalf("got %d p.entries, want 3 (WARNING, LOG, ERROR)", len(p.entries))
	}

	if p.entries[0].level != levelWarn {
		t.Errorf("entry 0 level=%q, want %q", p.entries[0].level, levelWarn)
	}
	// the annotations must still be reachable on the entry they belong to
	if !strings.Contains(p.entries[0].raw, "DETAIL:") || !strings.Contains(p.entries[0].raw, "HINT:") {
		t.Error("DETAIL/HINT were dropped instead of attached to the warning")
	}
	if p.entries[0].source != "108184" {
		t.Errorf("entry 0 source=%q, want the backend pid 108184", p.entries[0].source)
	}
	if p.entries[1].level != levelInfo {
		t.Errorf("entry 1 level=%q, want %q (LOG maps to INF)", p.entries[1].level, levelInfo)
	}
	if p.entries[2].level != levelError {
		t.Errorf("entry 2 level=%q, want %q", p.entries[2].level, levelError)
	}
	// the indented statement body is a continuation
	if !strings.Contains(p.entries[2].raw, "wrapped_statement_body") {
		t.Error("wrapped STATEMENT body was dropped")
	}
	if !p.entries[0].hasDate {
		t.Error("postgres p.entries should carry an absolute date")
	}
}

func TestPostgresLevelMapping(t *testing.T) {
	for severity, want := range map[string]string{
		"FATAL":   levelFatal,
		"PANIC":   levelFatal,
		"ERROR":   levelError,
		"WARNING": levelWarn,
		"NOTICE":  levelInfo,
		"LOG":     levelInfo,
		"DEBUG1":  levelDebug,
	} {
		line := "2026-08-11 14:40:49.332 UTC [1] " + severity + ":  some message"
		e, ok := postgresFormat.parse(line)
		if !ok {
			t.Errorf("failed to parse severity %s", severity)
			continue
		}
		if e.level != want {
			t.Errorf("severity %s mapped to %q, want %q", severity, e.level, want)
		}
	}
}

func TestPostgresParsesUserAtDatabasePrefix(t *testing.T) {
	// log_line_prefix is often "%m [%p] %q%u@%d " which inserts user@database
	e, ok := postgresFormat.parse("2026-08-11 14:40:49.332 UTC [108184] devguard@devguard ERROR:  boom")
	if !ok {
		t.Fatal("failed to parse a user@database prefixed line")
	}
	if e.level != levelError {
		t.Errorf("level=%q, want %q", e.level, levelError)
	}
	if e.source != "108184" {
		t.Errorf("source=%q, want 108184", e.source)
	}
}

// Next.js prints a marker line plus an indented stack; only the body carries the
// digest.
func TestWebFoldsStackAndUsesDigest(t *testing.T) {
	content := `⨯ Error: {"message":"Could not fetch group","context":{"statusCode":500}}
    at h (.next/server/chunks/ssr/src_0t4fn29._.js:2:296)
    at async j (.next/server/chunks/ssr/src_0t4fn29._.js:2:654) {
  statusCode: 500,
  homeLink: '/@opencode',
  digest: '2028629024'
}
✓ Ready in 0ms
TypeError: fetch failed
    at ignore-listed frames {
  [cause]: Error: connect ECONNREFUSED 10.43.168.36:4433
      at <unknown> (Error: connect ECONNREFUSED 10.43.168.36:4433) {
    errno: -111,
    code: 'ECONNREFUSED',
    port: 4433
  }
}
`
	p, err := readLog(writeTempLog(t, content), "auto")
	if err != nil {
		t.Fatal(err)
	}
	if p.format.name != webFormat.name {
		t.Fatalf("detected %q, want web", p.format.name)
	}
	if len(p.entries) != 3 {
		for i, e := range p.entries {
			t.Logf("entry %d: level=%s source=%s msg=%s", i, e.level, e.source, e.message)
		}
		t.Fatalf("got %d p.entries, want 3", len(p.entries))
	}

	if p.entries[0].level != levelError {
		t.Errorf("entry 0 level=%q, want %q", p.entries[0].level, levelError)
	}
	// the marker glyph is stripped from the message
	if strings.HasPrefix(p.entries[0].message, webErrMarker) {
		t.Errorf("entry 0 message still carries the ⨯ marker: %q", p.entries[0].message)
	}
	if p.entries[0].source != "digest:2028629024" {
		t.Errorf("entry 0 source=%q, want digest:2028629024", p.entries[0].source)
	}
	if p.entries[1].level != levelInfo || p.entries[1].message != "Ready in 0ms" {
		t.Errorf("entry 1 = %q/%q, want INF/\"Ready in 0ms\"", p.entries[1].level, p.entries[1].message)
	}
	// a bare TypeError with no digest falls back to the error code
	if p.entries[2].level != levelError {
		t.Errorf("entry 2 level=%q, want %q", p.entries[2].level, levelError)
	}
	if p.entries[2].source != "ECONNREFUSED" {
		t.Errorf("entry 2 source=%q, want ECONNREFUSED", p.entries[2].source)
	}
	if !p.entries[2].ts.IsZero() {
		t.Error("web p.entries must not claim a timestamp")
	}
}

func TestWebInfersWarning(t *testing.T) {
	e, ok := webFormat.parse("(node:1) ExperimentalWarning: localStorage is not available")
	if !ok {
		t.Fatal("failed to parse a node warning")
	}
	if e.level != levelWarn {
		t.Errorf("level=%q, want %q", e.level, levelWarn)
	}
}

func TestDetectFormat(t *testing.T) {
	samples := map[string][]string{
		apiFormat.name: {
			"2:11PM ERR middlewares/server.go:73 code=404, message=could not find project",
			"2:11PM INF middlewares/logging_middleware.go:34 handled request status=200",
		},
		kratosFormat.name: {
			"time=2026-08-11T14:11:48Z level=info msg=started handling request http_request=map[path:/sessions/whoami]",
			"time=2026-08-11T14:11:49Z level=info msg=completed handling request http_response=map[status:200]",
		},
		postgresFormat.name: {
			`2026-08-11 14:40:49.332 UTC [108184] WARNING:  database "devguard" has a collation version mismatch`,
			"2026-08-11 14:41:00.000 UTC [14] LOG:  checkpoint starting: time",
		},
		webFormat.name: {
			`⨯ Error: {"message":"Could not fetch group"}`,
			"    at h (.next/server/chunks/ssr/src_0t4fn29._.js:2:296)",
		},
	}

	for want, lines := range samples {
		t.Run(want, func(t *testing.T) {
			got, scores := detectFormat(lines)
			if got == nil {
				t.Fatalf("detected nothing, scores=%v", scores)
			}
			if got.name != want {
				t.Errorf("detected %q, want %q (scores=%v)", got.name, want, scores)
			}
			// a confident detection does not also match a rival format
			for name, score := range scores {
				if name != want && score > 0 {
					t.Errorf("format %q also matched %d lines, detection is ambiguous", name, score)
				}
			}
		})
	}
}

func TestDetectFormatFailsOnUnknownContent(t *testing.T) {
	if got, _ := detectFormat([]string{"just some prose", "and more prose"}); got != nil {
		t.Errorf("detected %q for unrecognisable content, want no match", got.name)
	}
	_, err := readLog(writeTempLog(t, "just some prose\n"), "auto")
	if err == nil {
		t.Error("expected an error telling the user to pass --format")
	} else if !strings.Contains(err.Error(), "--format") {
		t.Errorf("error should point at --format, got: %v", err)
	}
}

func TestLookupFormat(t *testing.T) {
	for _, name := range []string{"api", "kratos", "postgres", "web"} {
		if _, err := lookupFormat(name); err != nil {
			t.Errorf("lookupFormat(%q) failed: %v", name, err)
		}
	}
	if _, err := lookupFormat("nope"); err == nil {
		t.Error("expected an error for an unknown format")
	}
}

func TestParseBucket(t *testing.T) {
	for _, in := range []string{"s", "sec", "second"} {
		if b, err := parseBucket(in); err != nil || b != bucketSecond {
			t.Errorf("parseBucket(%q) = %q, %v", in, b, err)
		}
	}
	for _, in := range []string{"m", "min", "minute", "MINUTE"} {
		if b, err := parseBucket(in); err != nil || b != bucketMinute {
			t.Errorf("parseBucket(%q) = %q, %v", in, b, err)
		}
	}
	if _, err := parseBucket("fortnight"); err == nil {
		t.Error("expected an error for an unknown bucket")
	}
}

func TestBucketKey(t *testing.T) {
	dated, _ := kratosFormat.parse("time=2026-08-11T14:11:48Z level=info msg=hi")
	if key, ok := bucketKey(dated, bucketMinute); !ok || key != "2026-08-11 14:11" {
		t.Errorf("dated minute key = %q (ok=%v), want 2026-08-11 14:11", key, ok)
	}
	if key, ok := bucketKey(dated, bucketHour); !ok || key != "2026-08-11 14" {
		t.Errorf("dated hour key = %q (ok=%v), want 2026-08-11 14", key, ok)
	}

	// no date, so time of day only; 2:11PM renders as 14:11
	undated, ok := apiFormat.parse("2:11PM ERR middlewares/server.go:73 boom")
	if !ok {
		t.Fatal("failed to parse an api line")
	}
	if undated.hasDate {
		t.Error("api p.entries must not claim a calendar date")
	}
	if key, ok := bucketKey(undated, bucketMinute); !ok || key != "14:11" {
		t.Errorf("undated minute key = %q (ok=%v), want 14:11", key, ok)
	}

	// web has no timestamps at all
	webEntry, _ := webFormat.parse("⨯ Error: boom")
	if _, ok := bucketKey(webEntry, bucketMinute); ok {
		t.Error("web p.entries have no timestamp and must not produce a bucket")
	}
}

// TRC and PNC differ before and after mapping; FTL alone would pass even with no
// mapping at all.
func TestApiLevelMapping(t *testing.T) {
	for token, want := range map[string]string{
		"TRC": levelDebug,
		"DBG": levelDebug,
		"INF": levelInfo,
		"WRN": levelWarn,
		"ERR": levelError,
		"FTL": levelFatal,
		"PNC": levelFatal,
	} {
		e, ok := apiFormat.parse("2:11PM " + token + " main.go:10 something")
		if !ok {
			t.Errorf("failed to parse level %s", token)
			continue
		}
		if e.level != want {
			t.Errorf("level %s mapped to %q, want %q", token, e.level, want)
		}
	}
}

// A Go panic is written outside zerolog; without continuation handling its lines
// match no format and vanish.
func TestApiKeepsPanicWithPrecedingEntry(t *testing.T) {
	content := `2:11PM INF main.go:1 starting
panic: runtime error: index out of range [3] with length 2

goroutine 1 [running]:
main.main()
	/app/main.go:42 +0x1d
exit status 2
2:12PM INF main.go:2 done
`
	p, err := readLog(writeTempLog(t, content), "api")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.entries) != 2 {
		for i, e := range p.entries {
			t.Logf("entry %d: %s", i, e.raw)
		}
		t.Fatalf("got %d entries, want 2", len(p.entries))
	}
	if p.dropped != 0 {
		t.Errorf("dropped=%d, want 0 - panic lines should attach to the entry above", p.dropped)
	}
	for _, want := range []string{"panic: runtime error", "goroutine 1", "main.main()", "/app/main.go:42"} {
		if !strings.Contains(p.entries[0].raw, want) {
			t.Errorf("panic output lost %q", want)
		}
	}
}

// Lines matching neither parse nor continuation are counted so a partial parse is
// never reported as a complete one.
func TestReadLogCountsDroppedLines(t *testing.T) {
	content := "time=2026-08-11T14:11:00Z level=info msg=hi\nnot a kratos line at all\n"
	p, err := readLog(writeTempLog(t, content), "kratos")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(p.entries))
	}
	if p.dropped != 1 {
		t.Errorf("dropped=%d, want 1", p.dropped)
	}
}

func TestKratosQuotedMessage(t *testing.T) {
	e, ok := kratosFormat.parse(`time=2026-08-11T14:11:00Z level=error msg="something broke badly" component=x`)
	if !ok {
		t.Fatal("failed to parse a quoted msg")
	}
	if e.message != "something broke badly" {
		t.Errorf("message=%q, want it unquoted", e.message)
	}
}

func TestNormalizeMessage(t *testing.T) {
	tests := map[string]string{
		// the case that motivated it: same fault, different address each time
		`dial tcp 10.43.168.36:4433: connect: connection refused`: `dial tcp <addr>: connect: connection refused`,
		`dial tcp 10.0.0.9:4433: connect: connection refused`:     `dial tcp <addr>: connect: connection refused`,
		`assetID=ecd0059e-d506-4b0b-a5c9-2e9dc90792a0`:            `assetID=<uuid>`,
		`id=a36d570145e84c7bb58ac456372b25dd`:                     `id=<hex>`,
		`handled request status=200 duration=120.421479ms`:        `handled request status=<n> duration=<dur>`,
		`finished import timestamp=2026-08-11T12:41:20.050Z`:      `finished import timestamp=<ts>`,
	}
	for in, want := range tests {
		if got := normalizeMessage(in); got != want {
			t.Errorf("normalizeMessage(%q)\n  got  %q\n  want %q", in, got, want)
		}
	}
	// different addresses must collapse to one key
	a := normalizeMessage(`dial tcp 10.43.168.36:4433: connect: connection refused`)
	b := normalizeMessage(`dial tcp 10.0.0.9:4433: connect: connection refused`)
	if a != b {
		t.Errorf("addresses did not collapse: %q vs %q", a, b)
	}
}
