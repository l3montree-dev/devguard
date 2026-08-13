package commands

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// kubectl logs --timestamps prefix. Only the single separating space is
// consumed, so continuation indentation survives.
var k8sTimestampRe = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})) (.*)$`)

func stripK8sTimestamp(clean string) (string, time.Time) {
	m := k8sTimestampRe.FindStringSubmatch(clean)
	if m == nil {
		return clean, time.Time{}
	}
	ts, err := time.Parse(time.RFC3339Nano, m[1])
	if err != nil {
		return clean, time.Time{}
	}
	return m[2], ts
}

// Canonical levels; every format maps its own severity tokens onto these.
const (
	levelDebug = "DBG"
	levelInfo  = "INF"
	levelWarn  = "WRN"
	levelError = "ERR"
	levelFatal = "FTL"
)

// most severe first
var canonicalLevels = []string{levelFatal, levelError, levelWarn, levelInfo, levelDebug}

func isErrorLevel(l string) bool { return l == levelError || l == levelFatal }

type logEntry struct {
	time, level, source, message, raw string

	// ts is zero when the format carries no timestamp (web). hasDate is false
	// for formats printing a wall clock with no date (zerolog "2:11PM"), which
	// are bucketable by time of day only.
	ts      time.Time
	hasDate bool
}

// logFormat turns raw lines into entries. Formats are line oriented but may
// claim following lines as continuations, which keeps postgres DETAIL/HINT and
// Next.js stack frames attached to the entry they annotate.
type logFormat struct {
	name string
	help string
	// sourceLabel names what source holds for this format.
	sourceLabel string
	// detect reports whether a line is distinctively this format. Loose
	// matching here skews auto detection.
	detect func(clean string) bool
	parse  func(clean string) (logEntry, bool)
	// continuation reports whether a line belongs to the previous entry.
	continuation func(clean string) bool
	// finalize runs once all continuations are attached, for fields derivable
	// only from the whole block.
	finalize func(e *logEntry)
}

var logFormats = []*logFormat{apiFormat, kratosFormat, postgresFormat, webFormat}

func formatNames() []string {
	names := make([]string, 0, len(logFormats)+1)
	names = append(names, "auto")
	for _, f := range logFormats {
		names = append(names, f.name)
	}
	return names
}

func lookupFormat(name string) (*logFormat, error) {
	for _, f := range logFormats {
		if f.name == name {
			return f, nil
		}
	}
	return nil, fmt.Errorf("unknown format %q (want one of %s)", name, strings.Join(formatNames(), ", "))
}

func indented(clean string) bool {
	return clean != "" && (clean[0] == ' ' || clean[0] == '\t')
}

// ---------------------------------------------------------------------------
// api - zerolog console writer, e.g.
// 2:11PM ERR middlewares/server.go:73 code=404, message=could not find project
// ---------------------------------------------------------------------------

var apiLineRe = regexp.MustCompile(`^(\S+)\s+(TRC|DBG|INF|WRN|ERR|FTL|PNC)\s+(\S+)\s+(.*)$`)

// the console writer's TimeFormat is configurable; these are the layouts seen
// in deployment logs
var apiTimeLayouts = []string{"3:04PM", "3:04:05PM", "15:04:05", "15:04"}

var apiLevelMap = map[string]string{
	"TRC": levelDebug,
	"DBG": levelDebug,
	"INF": levelInfo,
	"WRN": levelWarn,
	"ERR": levelError,
	"FTL": levelFatal,
	"PNC": levelFatal,
}

// a Go stack frame such as main.main() or gorm.io/gorm.(*DB).Find(...) - has no
// spaces before the parenthesis, so it cannot match a zerolog line
var goStackFrameRe = regexp.MustCompile(`^[\w./\-*()\[\]]+\(.*\)$`)

var apiFormat = &logFormat{
	name:        "api",
	help:        "devguard-api / scanner (zerolog console writer)",
	sourceLabel: "Sources",
	detect: func(clean string) bool {
		return apiLineRe.MatchString(strings.TrimSpace(clean))
	},
	parse: func(clean string) (logEntry, bool) {
		m := apiLineRe.FindStringSubmatch(strings.TrimSpace(clean))
		if m == nil {
			return logEntry{}, false
		}
		e := logEntry{time: m[1], level: apiLevelMap[m[2]], source: m[3], message: m[4]}
		if e.level == "" {
			e.level = m[2]
		}
		for _, layout := range apiTimeLayouts {
			if ts, err := time.Parse(layout, m[1]); err == nil {
				e.ts = ts
				break
			}
		}
		return e, true
	},
	// a panic writes its message and stack outside zerolog; without this they
	// would match no format and be dropped
	continuation: func(clean string) bool {
		if indented(clean) {
			return true
		}
		t := strings.TrimSpace(clean)
		switch {
		case strings.HasPrefix(t, "panic:"),
			strings.HasPrefix(t, "goroutine "),
			strings.HasPrefix(t, "[signal "),
			strings.HasPrefix(t, "created by "),
			strings.HasPrefix(t, "exit status "):
			return true
		}
		return goStackFrameRe.MatchString(t)
	},
}

// ---------------------------------------------------------------------------
// kratos - logfmt, e.g.
// time=2026-08-11T14:11:48Z level=info msg=started handling request http_request=map[...]
// ---------------------------------------------------------------------------

var (
	kratosTimeRe  = regexp.MustCompile(`\btime=(\S+)`)
	kratosLevelRe = regexp.MustCompile(`\blevel=(\S+)`)
	// msg= may be quoted or bare; a bare one contains spaces and runs until the
	// next logfmt key
	kratosQuotedMsgRe = regexp.MustCompile(`\bmsg="((?:[^"\\]|\\.)*)"`)
	kratosBareMsgRe   = regexp.MustCompile(`\bmsg=(.*?)(?:\s+[a-z_][a-z0-9_]*=|$)`)
	// path: sits inside a map[...] rendering, so ] is excluded or a trailing
	// path captures the bracket
	kratosPathRe   = regexp.MustCompile(`\bpath:([^\s\]]+)`)
	kratosStatusRe = regexp.MustCompile(`\bstatus:(\d+)`)
)

var kratosLevelMap = map[string]string{
	"trace":   levelDebug,
	"debug":   levelDebug,
	"info":    levelInfo,
	"warn":    levelWarn,
	"warning": levelWarn,
	"error":   levelError,
	"fatal":   levelFatal,
	"panic":   levelFatal,
}

var kratosFormat = &logFormat{
	name:        "kratos",
	help:        "ory kratos (logfmt: time=... level=... msg=...)",
	sourceLabel: "Request Paths",
	detect: func(clean string) bool {
		t := strings.TrimSpace(clean)
		return strings.HasPrefix(t, "time=") && strings.Contains(t, " level=")
	},
	parse: func(clean string) (logEntry, bool) {
		t := strings.TrimSpace(clean)
		tm := kratosTimeRe.FindStringSubmatch(t)
		lm := kratosLevelRe.FindStringSubmatch(t)
		if tm == nil || lm == nil {
			return logEntry{}, false
		}
		e := logEntry{time: tm[1], level: levelInfo}
		if lvl, ok := kratosLevelMap[strings.ToLower(lm[1])]; ok {
			e.level = lvl
		}
		if mm := kratosQuotedMsgRe.FindStringSubmatch(t); mm != nil {
			e.message = mm[1]
		} else if mm := kratosBareMsgRe.FindStringSubmatch(t); mm != nil {
			e.message = strings.TrimSpace(mm[1])
		}
		if pm := kratosPathRe.FindStringSubmatch(t); pm != nil && pm[1] != "<nil>" {
			e.source = pm[1]
		}
		// fold status in so 200 and 401 on the same path stay distinct
		if sm := kratosStatusRe.FindStringSubmatch(t); sm != nil {
			e.message = strings.TrimSpace(e.message + " status=" + sm[1])
		}
		if ts, err := time.Parse(time.RFC3339, tm[1]); err == nil {
			e.ts = ts
			e.hasDate = true
		}
		return e, true
	},
	continuation: indented,
}

// ---------------------------------------------------------------------------
// postgres, e.g.
// 2026-08-11 14:11:23.456 UTC [95874] WARNING:  database "devguard" has a ...
// followed by subordinate DETAIL:/HINT:/STATEMENT:/CONTEXT: lines.
// ---------------------------------------------------------------------------

var postgresLineRe = regexp.MustCompile(
	`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:\.\d+)? ` + // timestamp
		`([A-Z]{2,5}(?:[+-]\d+)?) ` + // timezone
		`\[(\d+)\]` + // backend pid
		`(?: \[[^\]]*\])?` + // optional extra bracketed prefix
		`(?:\s+\S+@\S+)?` + // optional user@database
		`\s+([A-Z][A-Z0-9]*):\s*(.*)$`, // severity and message
)

var postgresLevelMap = map[string]string{
	"DEBUG": levelDebug, "DEBUG1": levelDebug, "DEBUG2": levelDebug,
	"DEBUG3": levelDebug, "DEBUG4": levelDebug, "DEBUG5": levelDebug,
	"INFO": levelInfo, "NOTICE": levelInfo, "LOG": levelInfo,
	"WARNING": levelWarn,
	"ERROR":   levelError,
	"FATAL":   levelFatal, "PANIC": levelFatal,
}

// annotate the preceding severity line; one collation warning emits
// WARNING + DETAIL + HINT
var postgresAnnotations = map[string]bool{
	"DETAIL": true, "HINT": true, "STATEMENT": true, "CONTEXT": true, "QUERY": true,
}

func postgresSeverity(clean string) (string, bool) {
	m := postgresLineRe.FindStringSubmatch(strings.TrimRight(clean, "\r\n"))
	if m == nil {
		return "", false
	}
	return m[4], true
}

var postgresFormat = &logFormat{
	name:        "postgres",
	help:        "postgresql server log (%m [%p] SEVERITY:), stamp read as logged, assumes log_timezone=UTC",
	sourceLabel: "Backend PIDs",
	detect: func(clean string) bool {
		sev, ok := postgresSeverity(clean)
		if !ok {
			return false
		}
		_, known := postgresLevelMap[sev]
		return known || postgresAnnotations[sev]
	},
	parse: func(clean string) (logEntry, bool) {
		m := postgresLineRe.FindStringSubmatch(strings.TrimRight(clean, "\r\n"))
		if m == nil {
			return logEntry{}, false
		}
		lvl, known := postgresLevelMap[m[4]]
		if !known {
			// an annotation with no owning entry above it (truncated log)
			if !postgresAnnotations[m[4]] {
				return logEntry{}, false
			}
			lvl = levelInfo
		}
		ts := parseNaiveTime(m[1])
		return logEntry{
			time:    m[1],
			level:   lvl,
			source:  m[3], // backend pid
			message: strings.TrimSpace(m[4] + ": " + m[5]),
			ts:      ts,
			hasDate: !ts.IsZero(),
		}, true
	},
	continuation: func(clean string) bool {
		// indented lines are wrapped STATEMENT bodies
		if indented(clean) {
			return true
		}
		sev, ok := postgresSeverity(clean)
		return ok && postgresAnnotations[sev]
	},
}

func parseNaiveTime(s string) time.Time {
	ts, err := time.Parse("2006-01-02 15:04:05", s)
	if err != nil {
		return time.Time{}
	}
	return ts
}

// ---------------------------------------------------------------------------
// web - Next.js server output. No timestamps and no levels, so severity is
// inferred from the leading marker and errors are grouped by Next.js digest.
// ---------------------------------------------------------------------------

var (
	webErrorClassRe = regexp.MustCompile(`^([A-Za-z_$][\w$]*(?:Error|Exception))\b`)
	webDigestRe     = regexp.MustCompile(`\bdigest:\s*'([^']+)'`)
	webCodeRe       = regexp.MustCompile(`\bcode:\s*'([^']+)'`)
)

const (
	webErrMarker = "⨯"
	webOKMarker  = "✓"
)

var webInfoMarkers = []string{webOKMarker, "▲", "○", "◐", "●", "- ", "√"}

var webFormat = &logFormat{
	name:        "web",
	help:        "devguard-web (Next.js server output, no timestamps)",
	sourceLabel: "Error Digests",
	detect: func(clean string) bool {
		t := strings.TrimSpace(clean)
		switch {
		case strings.HasPrefix(t, webErrMarker),
			strings.HasPrefix(t, "▲ Next.js"),
			strings.HasPrefix(t, "✓ Ready"),
			strings.HasPrefix(t, "(node:"):
			return true
		}
		return strings.Contains(t, ".next/server/chunks") ||
			strings.Contains(t, "ExperimentalWarning") ||
			strings.Contains(t, "at ignore-listed frames")
	},
	parse: func(clean string) (logEntry, bool) {
		t := strings.TrimSpace(clean)
		if t == "" {
			return logEntry{}, false
		}
		e := logEntry{level: levelInfo}
		msg := t
		switch {
		case strings.HasPrefix(t, webErrMarker):
			e.level = levelError
			msg = strings.TrimSpace(strings.TrimPrefix(t, webErrMarker))
		case webErrorClassRe.MatchString(t), strings.HasPrefix(t, "Error:"):
			e.level = levelError
		case strings.Contains(t, "Warning"):
			e.level = levelWarn
		default:
			for _, m := range webInfoMarkers {
				if strings.HasPrefix(t, m) {
					msg = strings.TrimSpace(strings.TrimPrefix(t, m))
					break
				}
			}
		}
		e.message = msg
		// provisional key; finalize upgrades it to the digest
		if cm := webErrorClassRe.FindStringSubmatch(msg); cm != nil {
			e.source = cm[1]
		}
		return e, true
	},
	continuation: func(clean string) bool {
		if indented(clean) {
			return true
		}
		switch strings.TrimSpace(clean) {
		case "}", "};", "})", "]", "],", "}]":
			return true
		}
		return false
	},
	finalize: func(e *logEntry) {
		// the digest is stable per distinct error, unlike messages embedding
		// varying slugs, and sits in the indented block rather than line one
		if m := webDigestRe.FindStringSubmatch(e.raw); m != nil {
			e.source = "digest:" + m[1]
			return
		}
		if m := webCodeRe.FindStringSubmatch(e.raw); m != nil {
			e.source = m[1]
		}
	},
}

// ---------------------------------------------------------------------------
// reading
// ---------------------------------------------------------------------------

// parsedLog is one log file resolved to a format and its entries.
type parsedLog struct {
	path    string
	format  *logFormat
	entries []logEntry
	// dropped counts lines that matched neither parse nor continuation, so a
	// partial parse is never reported as a complete one.
	dropped int
}

// reportDropped warns on stderr when input was not represented in the output.
func (p *parsedLog) reportDropped() {
	if p.dropped > 0 {
		fmt.Fprintf(os.Stderr, "\n(%d lines did not parse as %s and are not shown)\n",
			p.dropped, p.format.name)
	}
}

func readFileLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines, sc.Err()
}

// readLog reads path using the named format, or auto detects when format is
// "auto" or empty.
func readLog(path, format string) (*parsedLog, error) {
	lines, err := readFileLines(path)
	if err != nil {
		return nil, err
	}

	var f *logFormat
	if format == "" || format == "auto" {
		if f, _ = detectFormat(lines); f == nil {
			return nil, fmt.Errorf(
				"could not detect the log format of %s (matched none of %s) - pass --format explicitly",
				path, strings.Join(formatNames()[1:], ", "))
		}
	} else if f, err = lookupFormat(format); err != nil {
		return nil, err
	}

	p := &parsedLog{path: path, format: f}
	for _, raw := range lines {
		clean := ansiRe.ReplaceAllString(raw, "")
		clean, k8sTS := stripK8sTimestamp(clean)
		if strings.TrimSpace(clean) == "" {
			continue
		}
		clean = strings.TrimRight(clean, "\r\n")

		if f.continuation != nil && len(p.entries) > 0 && f.continuation(clean) {
			p.entries[len(p.entries)-1].raw += "\n" + clean
			continue
		}
		e, ok := f.parse(clean)
		if !ok {
			p.dropped++
			continue
		}
		e.raw = clean
		// kubectl's timestamp is absolute; the format's own may be undated or absent
		if !k8sTS.IsZero() {
			e.ts = k8sTS
			e.hasDate = true
			if e.time == "" {
				e.time = k8sTS.Format(time.RFC3339)
			}
		}
		if f.finalize != nil && len(p.entries) > 0 {
			f.finalize(&p.entries[len(p.entries)-1])
		}
		p.entries = append(p.entries, e)
	}
	if f.finalize != nil && len(p.entries) > 0 {
		f.finalize(&p.entries[len(p.entries)-1])
	}
	return p, nil
}

// detectFormat scores every format over a sample of lines. Scoring rather than
// first-match keeps a stray Next.js-looking line in an api log from flipping the
// whole file.
func detectFormat(lines []string) (*logFormat, map[string]int) {
	const sample = 400
	scores := map[string]int{}
	seen := 0
	for _, raw := range lines {
		clean := ansiRe.ReplaceAllString(raw, "")
		clean, _ = stripK8sTimestamp(clean)
		if strings.TrimSpace(clean) == "" {
			continue
		}
		for _, f := range logFormats {
			if f.detect(clean) {
				scores[f.name]++
			}
		}
		seen++
		if seen >= sample {
			break
		}
	}
	var best *logFormat
	for _, f := range logFormats {
		if scores[f.name] == 0 {
			continue
		}
		if best == nil || scores[f.name] > scores[best.name] {
			best = f
		}
	}
	return best, scores
}

// ---------------------------------------------------------------------------
// bucketing
// ---------------------------------------------------------------------------

type bucketSize string

const (
	bucketSecond bucketSize = "second"
	bucketMinute bucketSize = "minute"
	bucketHour   bucketSize = "hour"
)

func parseBucket(s string) (bucketSize, error) {
	switch strings.ToLower(s) {
	case "s", "sec", "second":
		return bucketSecond, nil
	case "m", "min", "minute":
		return bucketMinute, nil
	case "h", "hour":
		return bucketHour, nil
	}
	return "", fmt.Errorf("unknown bucket %q (want second, minute or hour)", s)
}

// bucketLabel renders a sortable label. withDate must be consistent across a
// run, or dated and undated keys interleave arbitrarily.
func bucketLabel(ts time.Time, b bucketSize, withDate bool) string {
	timePart := "15:04"
	switch b {
	case bucketSecond:
		timePart = "15:04:05"
	case bucketHour:
		timePart = "15"
	}
	if withDate {
		return ts.Format("2006-01-02 " + timePart)
	}
	return ts.Format(timePart)
}

func bucketKey(e logEntry, b bucketSize) (string, bool) {
	if e.ts.IsZero() {
		return "", false
	}
	return bucketLabel(e.ts, b, e.hasDate), true
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
