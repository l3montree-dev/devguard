package commands

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

var normalizeRules = []struct {
	re   *regexp.Regexp
	with string
}{
	{regexp.MustCompile(`\d{4}-\d{2}-\d{2}T[\d:.]+Z?`), "<ts>"},
	{regexp.MustCompile(`\d{4}-\d{2}-\d{2}`), "<date>"},
	{regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`), "<uuid>"},
	{regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b`), "<addr>"},
	{regexp.MustCompile(`\b[0-9a-f]{16,}\b`), "<hex>"},
	{regexp.MustCompile(`\b(?:\d+(?:\.\d+)?(?:ns|µs|us|ms|h|m|s))+\b`), "<dur>"},
	{regexp.MustCompile(`\b\d+\b`), "<n>"},
}

func normalizeMessage(s string) string {
	for _, r := range normalizeRules {
		s = r.re.ReplaceAllString(s, r.with)
	}
	return s
}

type countedKey struct {
	key   string
	count int
}

func topN(m map[string]int, n int, title string) {
	ss := make([]countedKey, 0, len(m))
	for k, v := range m {
		ss = append(ss, countedKey{k, v})
	}
	sort.Slice(ss, func(i, j int) bool {
		if ss[i].count != ss[j].count {
			return ss[i].count > ss[j].count
		}
		return ss[i].key < ss[j].key
	})
	fmt.Printf("\n=== %s ===\n", title)
	if len(ss) == 0 {
		fmt.Println("  (none)")
		return
	}
	for i, s := range ss {
		if i >= n {
			fmt.Printf("  ... and %d more\n", len(ss)-n)
			break
		}
		fmt.Printf("  %5d  %s\n", s.count, s.key)
	}
}

func logsSummary(path, format string, normalize bool, top int) error {
	p, err := readLog(path, format)
	if err != nil {
		return err
	}
	levels := map[string]int{}
	sources := map[string]int{}
	messages := map[string]int{}
	for _, e := range p.entries {
		levels[e.level]++
		if e.source != "" {
			sources[e.source]++
		}
		msg := e.message
		if normalize {
			msg = normalizeMessage(msg)
		}
		messages[msg]++
	}

	fmt.Printf("File:    %s\nFormat:  %s (%s)\nEntries: %d\n",
		path, p.format.name, p.format.help, len(p.entries))
	if len(p.entries) > 0 {
		first, last := p.entries[0], p.entries[len(p.entries)-1]
		if first.time != "" || last.time != "" {
			fmt.Printf("Range:   %s -> %s\n", first.time, last.time)
		}
		switch {
		case first.ts.IsZero():
			fmt.Println("Note:    this format carries no timestamps")
		case !first.hasDate:
			fmt.Println("Note:    timestamps carry no date and no timezone")
		}
	}

	fmt.Println("\n=== By Level ===")
	for _, lvl := range canonicalLevels {
		if n := levels[lvl]; n > 0 {
			fmt.Printf("  %-4s  %d\n", lvl, n)
		}
	}
	topN(sources, top, fmt.Sprintf("Top %d %s", top, p.format.sourceLabel))
	title := fmt.Sprintf("Top %d Messages", top)
	if normalize {
		title += " (normalized)"
	}
	topN(messages, top, title)
	p.reportDropped()
	return nil
}

func printMatching(entries []logEntry, keep func(logEntry) bool, limit int) int {
	count := 0
	for _, e := range entries {
		if !keep(e) {
			continue
		}
		fmt.Println(e.raw)
		count++
		if limit > 0 && count >= limit {
			break
		}
	}
	return count
}

func logsFilter(path, format, level, source, contains string, limit int) error {
	p, err := readLog(path, format)
	if err != nil {
		return err
	}
	level = strings.ToUpper(level)
	n := printMatching(p.entries, func(e logEntry) bool {
		if level != "" && e.level != level {
			return false
		}
		if source != "" && !strings.Contains(e.source, source) {
			return false
		}
		return contains == "" || strings.Contains(e.raw, contains)
	}, limit)
	fmt.Fprintf(os.Stderr, "\n(%d entries matched)\n", n)
	p.reportDropped()
	return nil
}

func logsErrors(path, format string, limit int) error {
	p, err := readLog(path, format)
	if err != nil {
		return err
	}
	// FTL counts as an error: postgres FATAL/PANIC, zerolog FTL/PNC
	n := printMatching(p.entries, func(e logEntry) bool {
		return isErrorLevel(e.level)
	}, limit)
	fmt.Fprintf(os.Stderr, "\n(%d entries matched)\n", n)
	p.reportDropped()
	return nil
}

func logsTimeline(path, format, bucket, level string) error {
	b, err := parseBucket(bucket)
	if err != nil {
		return err
	}
	p, err := readLog(path, format)
	if err != nil {
		return err
	}
	level = strings.ToUpper(level)

	buckets := map[string]map[string]int{}
	undated, skipped := false, 0
	for _, e := range p.entries {
		if level != "" && e.level != level {
			continue
		}
		key, ok := bucketKey(e, b)
		if !ok {
			skipped++
			continue
		}
		if !e.hasDate {
			undated = true
		}
		if buckets[key] == nil {
			buckets[key] = map[string]int{}
		}
		buckets[key][e.level]++
	}

	if len(buckets) == 0 {
		if skipped > 0 {
			return fmt.Errorf("the %s format carries no timestamps, so %d entries cannot be placed on a timeline",
				p.format.name, skipped)
		}
		fmt.Println("(no entries matched)")
		return nil
	}

	keys := sortedKeys(buckets)
	totals := make(map[string]int, len(keys))
	peak := 0
	for k, counts := range buckets {
		for _, n := range counts {
			totals[k] += n
		}
		if totals[k] > peak {
			peak = totals[k]
		}
	}

	fmt.Printf("File:   %s\nFormat: %s\nBucket: %s\n", path, p.format.name, b)
	if undated {
		fmt.Println("Note:   time of day only - no date and no timezone in this log;")
		fmt.Println("        a range crossing midnight therefore sorts by clock, not order")
	}
	fmt.Printf("\n%-19s %6s  %5s %5s %5s %5s %5s\n", "BUCKET", "TOTAL", "FTL", "ERR", "WRN", "INF", "DBG")
	for _, k := range keys {
		c := buckets[k]
		fmt.Printf("%-19s %6d  %5s %5s %5s %5s %5s  %s\n",
			k, totals[k],
			dashIfZero(c[levelFatal]), dashIfZero(c[levelError]), dashIfZero(c[levelWarn]),
			dashIfZero(c[levelInfo]), dashIfZero(c[levelDebug]),
			bar(totals[k], peak))
	}
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "\n(%d entries had no parseable timestamp)\n", skipped)
	}
	p.reportDropped()
	return nil
}

func dashIfZero(n int) string {
	if n == 0 {
		return "."
	}
	return fmt.Sprint(n)
}

func bar(n, peak int) string {
	const width = 30
	if peak <= 0 || n <= 0 {
		return ""
	}
	filled := n * width / peak
	if filled == 0 {
		filled = 1
	}
	return strings.Repeat("█", filled)
}

func logsFormats(path string) error {
	fmt.Println("=== Supported formats ===")
	for _, f := range logFormats {
		fmt.Printf("  %-9s %s\n", f.name, f.help)
	}

	lines, err := readFileLines(path)
	if err != nil {
		// the format list is still useful without the file
		fmt.Fprintf(os.Stderr, "\n(could not read %s: %v)\n", path, err)
		return nil
	}
	best, scores := detectFormat(lines)
	fmt.Printf("\n=== Detection for %s ===\n", path)
	for _, f := range logFormats {
		marker := " "
		if best != nil && f.name == best.name {
			marker = "*"
		}
		fmt.Printf("  %s %-9s %d matching lines in sample\n", marker, f.name, scores[f.name])
	}
	if best == nil {
		fmt.Println("\n  no format matched - pass --format explicitly")
	} else {
		fmt.Printf("\n  detected: %s\n", best.name)
	}
	return nil
}
