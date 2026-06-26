package commands

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)
var lineRe = regexp.MustCompile(`^(\S+)\s+(DBG|INF|WRN|ERR)\s+(\S+)\s+(.*)$`)

type logEntry struct {
	time, level, source, message, raw string
}

func parseLine(raw string) (logEntry, bool) {
	clean := ansiRe.ReplaceAllString(raw, "")
	m := lineRe.FindStringSubmatch(strings.TrimSpace(clean))
	if m == nil {
		return logEntry{}, false
	}
	return logEntry{time: m[1], level: m[2], source: m[3], message: m[4], raw: clean}, true
}

func readLogEntries(path string) ([]logEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var entries []logEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		if e, ok := parseLine(sc.Text()); ok {
			entries = append(entries, e)
		}
	}
	return entries, sc.Err()
}

var LogsCmd = &cobra.Command{
	Use:   "logs",
	Short: "Analyze log files",
}

func init() {
	var logFile string
	LogsCmd.PersistentFlags().StringVarP(&logFile, "file", "f", "devguard.log", "log file to analyze")

	summary := &cobra.Command{
		Use:   "summary",
		Short: "Print level counts, top sources, and top messages",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return logsSummary(logFile)
		},
	}

	var filterLevel, filterSource, filterContains string
	var filterLimit int
	filter := &cobra.Command{
		Use:   "filter",
		Short: "Filter log lines by level, source, or substring",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return logsFilter(logFile, filterLevel, filterSource, filterContains, filterLimit)
		},
	}
	filter.Flags().StringVarP(&filterLevel, "level", "l", "", "level: DBG, INF, WRN, ERR")
	filter.Flags().StringVarP(&filterSource, "source", "s", "", "source file substring")
	filter.Flags().StringVarP(&filterContains, "contains", "c", "", "substring the line must contain")
	filter.Flags().IntVarP(&filterLimit, "limit", "n", 0, "max lines (0 = all)")

	var errLimit int
	errors := &cobra.Command{
		Use:   "errors",
		Short: "Print all ERR lines",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return logsFilter(logFile, "ERR", "", "", errLimit)
		},
	}
	errors.Flags().IntVarP(&errLimit, "limit", "n", 0, "max lines (0 = all)")

	LogsCmd.AddCommand(summary, filter, errors)
}

func logsSummary(path string) error {
	entries, err := readLogEntries(path)
	if err != nil {
		return err
	}
	levels := map[string]int{}
	sources := map[string]int{}
	messages := map[string]int{}
	for _, e := range entries {
		levels[e.level]++
		sources[e.source]++
		msg := e.message
		if len(msg) > 80 {
			msg = msg[:80]
		}
		messages[msg]++
	}
	fmt.Printf("Total lines: %d\n\n", len(entries))
	fmt.Println("=== By Level ===")
	for _, lvl := range []string{"ERR", "WRN", "INF", "DBG"} {
		if n := levels[lvl]; n > 0 {
			fmt.Printf("  %-4s  %d\n", lvl, n)
		}
	}
	type kv struct {
		k string
		v int
	}
	top := func(m map[string]int, n int, title string) {
		var ss []kv
		for k, v := range m {
			ss = append(ss, kv{k, v})
		}
		sort.Slice(ss, func(i, j int) bool { return ss[i].v > ss[j].v })
		fmt.Printf("\n=== %s ===\n", title)
		for i, s := range ss {
			if i >= n {
				break
			}
			fmt.Printf("  %5d  %s\n", s.v, s.k)
		}
	}
	top(sources, 15, "Top 15 Sources")
	top(messages, 15, "Top 15 Messages")
	return nil
}

func logsFilter(path, level, source, contains string, limit int) error {
	entries, err := readLogEntries(path)
	if err != nil {
		return err
	}
	count := 0
	for _, e := range entries {
		if level != "" && e.level != strings.ToUpper(level) {
			continue
		}
		if source != "" && !strings.Contains(e.source, source) {
			continue
		}
		if contains != "" && !strings.Contains(e.raw, contains) {
			continue
		}
		fmt.Println(e.raw)
		count++
		if limit > 0 && count >= limit {
			break
		}
	}
	fmt.Fprintf(os.Stderr, "\n(%d lines matched)\n", count)
	return nil
}
