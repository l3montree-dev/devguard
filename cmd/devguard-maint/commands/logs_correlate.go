package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// logSource is one file placed onto the shared correlation timeline.
type logSource struct {
	idx     int
	path    string
	label   string
	format  *logFormat
	entries []logEntry
	offset  time.Duration
	dropped int

	// dated means the file carries calendar dates, timed that it carries at
	// least a wall clock. Timed but undated (zerolog "2:11PM") must be anchored
	// to a date before it can be compared with anything else.
	dated bool
	timed bool

	anchoredTo string // set when a date had to be inferred
}

func (s *logSource) firstLast() (logEntry, logEntry, bool) {
	if len(s.entries) == 0 {
		return logEntry{}, logEntry{}, false
	}
	return s.entries[0], s.entries[len(s.entries)-1], true
}

func timeOfDaySeconds(t time.Time) int {
	return t.Hour()*3600 + t.Minute()*60 + t.Second()
}

// anchorSource assigns calendar dates to a timed-but-undated source. Entries
// are walked in file order and the day is rolled forward whenever the clock
// goes backwards, so a log spanning midnight stays monotonic. The base date is
// then chosen so the final entry lands on lastDate.
func anchorSource(s *logSource, lastDate time.Time) {
	dayOf := make([]int, len(s.entries))
	day, prev := 0, -1
	for i := range s.entries {
		e := &s.entries[i]
		if e.ts.IsZero() || e.hasDate {
			dayOf[i] = day
			continue
		}
		tod := timeOfDaySeconds(e.ts)
		if prev >= 0 && tod < prev {
			day++
		}
		prev = tod
		dayOf[i] = day
	}
	base := lastDate.AddDate(0, 0, -day)
	for i := range s.entries {
		e := &s.entries[i]
		if e.ts.IsZero() || e.hasDate {
			continue
		}
		d := base.AddDate(0, 0, dayOf[i])
		e.ts = time.Date(d.Year(), d.Month(), d.Day(),
			e.ts.Hour(), e.ts.Minute(), e.ts.Second(), 0, time.UTC)
		e.hasDate = true
	}
	s.dated = true
	s.anchoredTo = base.Format("2006-01-02")
}

// parseOffsets reads repeated --offset KEY=DURATION pairs. KEY matches a source
// by 1-based index, format name or file basename.
func parseOffsets(raw []string) (map[string]time.Duration, error) {
	out := map[string]time.Duration{}
	for _, spec := range raw {
		key, val, ok := strings.Cut(spec, "=")
		if !ok {
			return nil, fmt.Errorf("bad --offset %q, want KEY=DURATION (e.g. api=+2h)", spec)
		}
		d, err := time.ParseDuration(val)
		if err != nil {
			return nil, fmt.Errorf("bad --offset duration in %q: %w", spec, err)
		}
		out[key] = d
	}
	return out, nil
}

func (s *logSource) matchesOffsetKey(key string) bool {
	if key == strconv.Itoa(s.idx) || key == s.format.name {
		return true
	}
	base := filepath.Base(s.path)
	return key == base || key == strings.TrimSuffix(base, filepath.Ext(base))
}

func loadSources(paths []string, format string, offsets map[string]time.Duration) ([]*logSource, error) {
	sources := make([]*logSource, 0, len(paths))
	formatCounts := map[string]int{}

	for i, path := range paths {
		p, err := readLog(path, format)
		if err != nil {
			return nil, err
		}
		s := &logSource{idx: i + 1, path: path, format: p.format, entries: p.entries, dropped: p.dropped}
		for _, e := range p.entries {
			if !e.ts.IsZero() {
				s.timed = true
				if e.hasDate {
					s.dated = true
				}
			}
		}
		formatCounts[p.format.name]++
		sources = append(sources, s)
	}

	// the format name reads best as a column label, but collides when several
	// files share a format
	for _, s := range sources {
		if formatCounts[s.format.name] > 1 {
			base := filepath.Base(s.path)
			s.label = strings.TrimSuffix(base, filepath.Ext(base))
		} else {
			s.label = s.format.name
		}
	}

	for key, d := range offsets {
		matched := false
		for _, s := range sources {
			if !s.matchesOffsetKey(key) {
				continue
			}
			matched = true
			s.offset = d
			for i := range s.entries {
				if !s.entries[i].ts.IsZero() {
					s.entries[i].ts = s.entries[i].ts.Add(d)
				}
			}
		}
		if !matched {
			return nil, fmt.Errorf("--offset %s= matched no input file", key)
		}
	}
	return sources, nil
}

// alignSources anchors every timed-but-undated source against the latest date
// seen in the dated ones, so all entries share one timeline.
func alignSources(sources []*logSource, forcedDate string) error {
	var lastDated time.Time
	for _, s := range sources {
		if !s.dated {
			continue
		}
		for _, e := range s.entries {
			if e.hasDate && e.ts.After(lastDated) {
				lastDated = e.ts
			}
		}
	}

	base := lastDated
	switch {
	case forcedDate != "":
		d, err := time.Parse("2006-01-02", forcedDate)
		if err != nil {
			return fmt.Errorf("bad --date %q, want YYYY-MM-DD: %w", forcedDate, err)
		}
		base = d
	case base.IsZero():
		// nothing dated: leave undated sources on a time-of-day timeline
		return nil
	}
	dateOnly := time.Date(base.Year(), base.Month(), base.Day(), 0, 0, 0, 0, time.UTC)

	for _, s := range sources {
		if s.timed && !s.dated {
			anchorSource(s, dateOnly)
		}
	}
	return nil
}

type correlateOptions struct {
	bucket     string
	level      string
	onlyErrors bool
	around     string
	window     string
	date       string
	offsets    []string
}

func logsCorrelate(paths []string, format string, opts correlateOptions) error {
	b, err := parseBucket(opts.bucket)
	if err != nil {
		return err
	}
	offsets, err := parseOffsets(opts.offsets)
	if err != nil {
		return err
	}
	sources, err := loadSources(paths, format, offsets)
	if err != nil {
		return err
	}
	if err := alignSources(sources, opts.date); err != nil {
		return err
	}

	// alignSources dates every timed source once anything is dated, so any
	// implies all here; keys stay homogeneous and therefore sortable
	anyDated := false
	for _, s := range sources {
		if s.dated {
			anyDated = true
			break
		}
	}
	level := strings.ToUpper(opts.level)

	printCorrelateHeader(sources, b, anyDated)

	// bucket -> source index -> level -> count
	buckets := map[string]map[int]map[string]int{}
	for _, s := range sources {
		for _, e := range s.entries {
			if e.ts.IsZero() {
				continue
			}
			if level != "" && e.level != level {
				continue
			}
			key := bucketLabel(e.ts, b, anyDated)
			if buckets[key] == nil {
				buckets[key] = map[int]map[string]int{}
			}
			if buckets[key][s.idx] == nil {
				buckets[key][s.idx] = map[string]int{}
			}
			buckets[key][s.idx][e.level]++
		}
	}

	if len(buckets) > 0 {
		printCorrelateMatrix(sources, buckets, opts.onlyErrors)
	} else {
		fmt.Println("\n(no timestamped entries to correlate)")
	}

	if opts.around != "" {
		if err := printCorrelateWindow(sources, opts, anyDated); err != nil {
			return err
		}
	}
	printUntimedSources(sources)
	for _, s := range sources {
		if s.dropped > 0 {
			fmt.Fprintf(os.Stderr, "(%s: %d lines did not parse as %s and are not shown)\n",
				filepath.Base(s.path), s.dropped, s.format.name)
		}
	}
	return nil
}

func printCorrelateHeader(sources []*logSource, b bucketSize, allDated bool) {
	fmt.Printf("=== Correlating %d logs (bucket=%s) ===\n\n", len(sources), b)
	for _, s := range sources {
		first, last, ok := s.firstLast()
		rng := "(no entries)"
		if ok {
			switch {
			case !s.timed:
				rng = "no timestamps - cannot be aligned"
			case s.anchoredTo != "":
				rng = fmt.Sprintf("%s -> %s (no date in log, anchored to %s)",
					first.ts.Format("15:04:05"), last.ts.Format("15:04:05"), s.anchoredTo)
			default:
				rng = fmt.Sprintf("%s -> %s",
					first.ts.Format("2006-01-02 15:04:05"), last.ts.Format("2006-01-02 15:04:05"))
			}
		}
		fmt.Printf("  [%d] %-10s %-34s %6d entries  %s",
			s.idx, s.label, filepath.Base(s.path), len(s.entries), rng)
		if s.offset != 0 {
			fmt.Printf("  (shifted %s)", s.offset)
		}
		fmt.Println()
	}

	anchored := false
	for _, s := range sources {
		if s.anchoredTo != "" {
			anchored = true
		}
	}
	if anchored {
		fmt.Println("\n  Note: logs without a date were anchored onto the dated logs' timeline.")
		fmt.Println("        Alignment assumes every log is in the same zone. If one is not,")
		fmt.Println("        correct it with --offset (e.g. --offset api=+2h).")
	}
	if !allDated {
		fmt.Println("\n  Note: no log carried a calendar date - buckets are time of day only.")
	}
}

func printCorrelateMatrix(sources []*logSource, buckets map[string]map[int]map[string]int, onlyErrors bool) {
	keys := sortedKeys(buckets)

	colw := make(map[int]int, len(sources))
	for _, s := range sources {
		w := len(s.label)
		if w < 9 {
			w = 9
		}
		colw[s.idx] = w
	}

	keyw := 16
	for _, k := range keys {
		if len(k) > keyw {
			keyw = len(k)
		}
	}

	rule := keyw + 2
	fmt.Printf("\n%-*s ", keyw+2, "  BUCKET")
	for _, s := range sources {
		if !s.timed {
			continue
		}
		fmt.Printf("%-*s ", colw[s.idx]+1, s.label)
		rule += colw[s.idx] + 2
	}
	fmt.Printf("\n%s\n", strings.Repeat("-", rule))

	shown := 0
	for _, k := range keys {
		row := buckets[k]
		anyErr := false
		for _, counts := range row {
			for lvl, n := range counts {
				if n > 0 && isErrorLevel(lvl) {
					anyErr = true
				}
			}
		}
		if onlyErrors && !anyErr {
			continue
		}
		marker := " "
		if anyErr {
			marker = "!"
		}
		fmt.Printf("%s %-*s ", marker, keyw, k)
		for _, s := range sources {
			if !s.timed {
				continue
			}
			fmt.Printf("%-*s ", colw[s.idx]+1, correlateCell(row[s.idx]))
		}
		fmt.Println()
		shown++
	}
	if shown == 0 {
		fmt.Println("  (no bucket contained an error)")
	}
	fmt.Printf("\n  cell = total/errors, · = nothing logged, ! marks a bucket with ERR or FTL\n")
}

func correlateCell(counts map[string]int) string {
	if len(counts) == 0 {
		return "·"
	}
	total, errs := 0, 0
	for lvl, n := range counts {
		total += n
		if isErrorLevel(lvl) {
			errs += n
		}
	}
	if errs > 0 {
		return fmt.Sprintf("%d/%d", total, errs)
	}
	return strconv.Itoa(total)
}

// parseAround accepts a full instant or a bare wall clock, filling in the date
// from the aligned timeline when it is omitted.
func parseAround(s string, ref time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02 15:04"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	for _, layout := range []string{"15:04:05", "15:04", "3:04PM", "3:04:05PM"} {
		if t, err := time.Parse(layout, s); err == nil {
			if ref.IsZero() {
				return t, nil
			}
			return time.Date(ref.Year(), ref.Month(), ref.Day(),
				t.Hour(), t.Minute(), t.Second(), 0, time.UTC), nil
		}
	}
	return time.Time{}, fmt.Errorf("could not parse --around %q (try 14:11, 14:11:30 or 2026-08-11 14:11)", s)
}

type windowEntry struct {
	src   *logSource
	entry logEntry
}

func printCorrelateWindow(sources []*logSource, opts correlateOptions, allDated bool) error {
	window := 1 * time.Minute
	if opts.window != "" {
		d, err := time.ParseDuration(opts.window)
		if err != nil {
			return fmt.Errorf("bad --window %q: %w", opts.window, err)
		}
		window = d
	}

	// reference instant for filling in a missing date
	var ref time.Time
	for _, s := range sources {
		for _, e := range s.entries {
			if !e.ts.IsZero() {
				ref = e.ts
				break
			}
		}
		if !ref.IsZero() {
			break
		}
	}

	center, err := parseAround(opts.around, ref)
	if err != nil {
		return err
	}
	from, to := center.Add(-window), center.Add(window)
	level := strings.ToUpper(opts.level)

	var merged []windowEntry
	for _, s := range sources {
		for _, e := range s.entries {
			if e.ts.IsZero() || e.ts.Before(from) || e.ts.After(to) {
				continue
			}
			if level != "" && e.level != level {
				continue
			}
			merged = append(merged, windowEntry{src: s, entry: e})
		}
	}
	sort.SliceStable(merged, func(i, j int) bool {
		return merged[i].entry.ts.Before(merged[j].entry.ts)
	})

	layout := "15:04:05"
	if allDated {
		layout = "2006-01-02 15:04:05"
	}
	fmt.Printf("\n=== Window %s -> %s (±%s around %s) ===\n\n",
		from.Format(layout), to.Format(layout), window, center.Format(layout))
	if len(merged) == 0 {
		fmt.Println("  (nothing logged in this window)")
		return nil
	}
	for _, m := range merged {
		prefix := fmt.Sprintf("%s  %-10s %-3s  ",
			m.entry.ts.Format(layout), "["+m.src.label+"]", m.entry.level)
		printEntryLines(prefix, m.entry.raw)
	}
	fmt.Printf("\n(%d entries in window)\n", len(merged))
	return nil
}

// printEntryLines prints all lines of an entry, continuations indented under
// the first.
func printEntryLines(prefix, raw string) {
	lines := strings.Split(raw, "\n")
	fmt.Println(prefix + lines[0])
	if len(lines) == 1 {
		return
	}
	indent := strings.Repeat(" ", len(prefix))
	for _, l := range lines[1:] {
		fmt.Println(indent + strings.TrimRight(l, "\r"))
	}
}

// printUntimedSources reports files with no timestamps, which cannot be placed
// on the timeline.
func printUntimedSources(sources []*logSource) {
	for _, s := range sources {
		if s.timed || len(s.entries) == 0 {
			continue
		}
		var errs []logEntry
		for _, e := range s.entries {
			if isErrorLevel(e.level) {
				errs = append(errs, e)
			}
		}
		fmt.Printf("\n=== %s (%s): not on the timeline ===\n", filepath.Base(s.path), s.label)
		fmt.Printf("  This log carries no timestamps, so its %d entries (%d errors) cannot be\n",
			len(s.entries), len(errs))
		fmt.Printf("  aligned. Re-collect it with timestamps to correlate it properly:\n")
		fmt.Printf("      kubectl logs --timestamps deploy/<name> > %s\n", filepath.Base(s.path))
		if len(errs) == 0 {
			continue
		}
		fmt.Printf("\n  Errors in file order:\n")
		for _, e := range errs {
			printEntryLines(fmt.Sprintf("      %-3s ", e.level), e.raw)
		}
	}
}
