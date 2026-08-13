package commands

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseLine(t *testing.T) {
	tests := []struct {
		raw         string
		wantLevel   string
		wantSource  string
		wantMessage string
		wantOk      bool
	}{
		{
			raw:         "12:54AM DBG daemons/daemon_asset_pipeline.go:230 could not resolve fixed version vulnerabilityID=abc",
			wantLevel:   "DBG",
			wantSource:  "daemons/daemon_asset_pipeline.go:230",
			wantMessage: "could not resolve fixed version vulnerabilityID=abc",
			wantOk:      true,
		},
		{
			raw:         "\x1b[2m12:54AM\x1b[0m DBG \x1b[2mdaemons/foo.go:10\x1b[0m message here",
			wantLevel:   "DBG",
			wantSource:  "daemons/foo.go:10",
			wantMessage: "message here",
			wantOk:      true,
		},
		{
			raw:         "12:59AM ERR middlewares/server.go:74 code=403, message=forbidden",
			wantLevel:   "ERR",
			wantSource:  "middlewares/server.go:74",
			wantMessage: "code=403, message=forbidden",
			wantOk:      true,
		},
		{
			raw:    "not a valid log line",
			wantOk: false,
		},
		{
			raw:    "",
			wantOk: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.raw[:min(len(tt.raw), 40)], func(t *testing.T) {
			e, ok := apiFormat.parse(ansiRe.ReplaceAllString(tt.raw, ""))
			if ok != tt.wantOk {
				t.Fatalf("parseLine ok=%v, want %v", ok, tt.wantOk)
			}
			if !ok {
				return
			}
			if e.level != tt.wantLevel {
				t.Errorf("level=%q, want %q", e.level, tt.wantLevel)
			}
			if e.source != tt.wantSource {
				t.Errorf("source=%q, want %q", e.source, tt.wantSource)
			}
			if e.message != tt.wantMessage {
				t.Errorf("message=%q, want %q", e.message, tt.wantMessage)
			}
		})
	}
}

func TestReadLogEntries(t *testing.T) {
	content := `12:54AM DBG daemons/foo.go:1 debug message
12:55AM WRN daemons/foo.go:2 warning message key=val
12:56AM ERR daemons/foo.go:3 error message
not a valid line
12:57AM INF daemons/foo.go:4 info message
`
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	p, err := readLog(path, apiFormat.name)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.entries) != 4 {
		t.Errorf("got %d entries, want 4", len(p.entries))
	}
	// the unparseable line is counted, not silently discarded
	if p.dropped != 1 {
		t.Errorf("dropped=%d, want 1", p.dropped)
	}
	levels := map[string]int{}
	for _, e := range p.entries {
		levels[e.level]++
	}
	if levels["DBG"] != 1 || levels["WRN"] != 1 || levels["ERR"] != 1 || levels["INF"] != 1 {
		t.Errorf("unexpected level counts: %v", levels)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
