package commands

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// parsing "handled request" entries
// ---------------------------------------------------------------------------

// The api logging middleware emits one entry per request:
//
//	handled request method=GET url=/api/v1/info/ status=200 duration=2.017011ms
//
// zerolog quotes a value containing characters it considers special, so url
// arrives bare or quoted depending on whether it carried a query string.
var (
	reqMethodRe   = regexp.MustCompile(`\bmethod=(\S+)`)
	reqStatusRe   = regexp.MustCompile(`\bstatus=(\d+)`)
	reqDurationRe = regexp.MustCompile(`\bduration=(\S+)`)
	reqURLRe      = regexp.MustCompile(`\burl=("(?:[^"\\]|\\.)*"|\S+)`)
)

const requestMarker = "handled request"

type requestSample struct {
	ts      time.Time
	hasDate bool
	method  string
	route   string // normalized, for grouping
	rawURL  string
	status  int
	dur     time.Duration
}

// parseRequest reads a middleware request entry. Anything missing a duration is
// not a request entry, which is what separates requests from the rest of the log.
func parseRequest(e logEntry) (requestSample, bool) {
	if !strings.Contains(e.message, requestMarker) {
		return requestSample{}, false
	}
	dm := reqDurationRe.FindStringSubmatch(e.message)
	if dm == nil {
		return requestSample{}, false
	}
	d, err := time.ParseDuration(dm[1])
	if err != nil {
		return requestSample{}, false
	}
	r := requestSample{ts: e.ts, hasDate: e.hasDate, dur: d}
	if m := reqMethodRe.FindStringSubmatch(e.message); m != nil {
		r.method = m[1]
	}
	if m := reqStatusRe.FindStringSubmatch(e.message); m != nil {
		r.status, _ = strconv.Atoi(m[1])
	}
	if m := reqURLRe.FindStringSubmatch(e.message); m != nil {
		raw := m[1]
		if unquoted, err := strconv.Unquote(raw); err == nil {
			raw = unquoted
		}
		r.rawURL = raw
		r.route = normalizeRoute(raw)
	}
	return r, true
}

// ---------------------------------------------------------------------------
// route normalization
// ---------------------------------------------------------------------------

// Segments whose successor is a human readable slug rather than an id, taken
// from the :param route definitions in router/. These never look like ids, so
// they can only be collapsed positionally.
var slugParents = map[string]string{
	"organizations":    "{org}",
	"projects":         "{project}",
	"assets":           "{asset}",
	"refs":             "{ref}",
	"artifacts":        "{artifact}",
	"dependency-proxy": "{secret}",
}

// Segments whose successor is an id, but which are also plain collection
// endpoints ("/vex-rules/?page=1") or have named sub-routes
// ("/vex-rules/recommendations/"). The successor is only collapsed when it
// actually looks like an id.
var idParents = map[string]string{
	"dependency-vulns":      "{vulnID}",
	"first-party-vulns":     "{vulnID}",
	"license-risks":         "{riskID}",
	"vex-rules":             "{ruleID}",
	"compliance-postures":   "{controlID}",
	"compliance-components": "{componentID}",
	"vulndb":                "{cveID}",
	"events":                "{eventID}",
	"members":               "{userID}",
	"pats":                  "{tokenID}",
	"in-toto":               "{supplyChainID}",
	"invitation":            "{id}",
	"public":                "{assetID}",
}

var (
	uuidSegmentRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	hexSegmentRe  = regexp.MustCompile(`^[0-9a-f]{16,}$`)
	numSegmentRe  = regexp.MustCompile(`^\d+$`)
	cveSegmentRe  = regexp.MustCompile(`^(?i:CVE|GHSA|OSV)-[\w-]+$`)
)

func looksLikeID(seg string) bool {
	return uuidSegmentRe.MatchString(seg) || hexSegmentRe.MatchString(seg) ||
		numSegmentRe.MatchString(seg) || cveSegmentRe.MatchString(seg)
}

// normalizeRoute reduces a request URL to the route that served it, so the same
// endpoint hit against different orgs and assets groups into one row. The query
// string is dropped; pagination and date ranges would otherwise split a route
// into hundreds of one-hit entries.
func normalizeRoute(raw string) string {
	path := raw
	if u, err := url.Parse(raw); err == nil && u.Path != "" {
		path = u.Path // also drops scheme://host on the absolute urls
	}
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	if decoded, err := url.PathUnescape(path); err == nil {
		path = decoded
	}

	segs := strings.Split(path, "/")
	for i, seg := range segs {
		if seg == "" || i == 0 {
			continue
		}
		parent := segs[i-1]
		if ph, ok := slugParents[parent]; ok {
			segs[i] = ph
			continue
		}
		if ph, ok := idParents[parent]; ok && looksLikeID(seg) {
			segs[i] = ph
			continue
		}
		// catch ids under routes not enumerated above, and @org spellings that
		// reached the log without percent encoding
		switch {
		case looksLikeID(seg) && !isPlaceholder(parent):
			segs[i] = "{id}"
		case strings.HasPrefix(seg, "@"):
			segs[i] = "{org}"
		}
	}
	out := strings.Join(segs, "/")
	if out == "" {
		return "/"
	}
	return out
}

func isPlaceholder(seg string) bool {
	return strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}")
}

// ---------------------------------------------------------------------------
// statistics
// ---------------------------------------------------------------------------

// durStats summarises a set of durations. Percentiles use the nearest rank
// method, so every reported value is a duration that really occurred.
type durStats struct {
	n                  int
	total              time.Duration
	p50, p90, p95, p99 time.Duration
	max                time.Duration
}

// statsOf sorts sorted in place.
func statsOf(sorted []time.Duration) durStats {
	if len(sorted) == 0 {
		return durStats{}
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	s := durStats{n: len(sorted), max: sorted[len(sorted)-1]}
	for _, d := range sorted {
		s.total += d
	}
	s.p50, s.p90 = percentile(sorted, 50), percentile(sorted, 90)
	s.p95, s.p99 = percentile(sorted, 95), percentile(sorted, 99)
	return s
}

func percentile(sorted []time.Duration, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	rank := (p*len(sorted) + 99) / 100 // ceil(p/100 * n)
	if rank < 1 {
		rank = 1
	}
	if rank > len(sorted) {
		rank = len(sorted)
	}
	return sorted[rank-1]
}

// fmtDur keeps columns narrow and comparable; the raw Go rendering of a
// duration varies in width by three characters between units.
func fmtDur(d time.Duration) string {
	switch {
	case d == 0:
		return "-"
	case d < time.Millisecond:
		return fmt.Sprintf("%.1fµs", float64(d)/float64(time.Microsecond))
	case d < time.Second:
		return fmt.Sprintf("%.0fms", float64(d)/float64(time.Millisecond))
	case d < time.Minute:
		return fmt.Sprintf("%.2fs", d.Seconds())
	default:
		return fmt.Sprintf("%.1fm", d.Minutes())
	}
}

// ---------------------------------------------------------------------------
// durations command
// ---------------------------------------------------------------------------

type durationsOptions struct {
	bucket     string
	top        int
	slow       string
	lead       int
	minLatency string
	route      string
	noPrecurse bool
}

func logsDurations(path, format string, o durationsOptions) error {
	b, err := parseBucket(o.bucket)
	if err != nil {
		return err
	}
	p, err := readLog(path, format)
	if err != nil {
		return err
	}

	var minLatency time.Duration
	if o.minLatency != "" {
		if minLatency, err = time.ParseDuration(o.minLatency); err != nil {
			return fmt.Errorf("--min-latency: %w", err)
		}
	}
	var slowThreshold time.Duration
	if o.slow != "" {
		if slowThreshold, err = time.ParseDuration(o.slow); err != nil {
			return fmt.Errorf("--slow: %w", err)
		}
	}

	// split the log into timed requests and everything else; the remainder is
	// what the precursor analysis searches
	var reqs []requestSample
	var events []logEntry
	for _, e := range p.entries {
		r, ok := parseRequest(e)
		if !ok {
			events = append(events, e)
			continue
		}
		if minLatency > 0 && r.dur < minLatency {
			continue
		}
		if o.route != "" && !strings.Contains(r.rawURL, o.route) && !strings.Contains(r.route, o.route) {
			continue
		}
		reqs = append(reqs, r)
	}

	fmt.Printf("File:     %s\nFormat:   %s\nRequests: %d of %d entries\n",
		path, p.format.name, len(reqs), len(p.entries))
	if len(reqs) == 0 {
		fmt.Println("\n(no \"handled request\" entries with a duration= field were found)")
		p.reportDropped()
		return nil
	}
	if !reqs[0].hasDate {
		fmt.Println("Note:     timestamps carry no date and no timezone")
	}

	all := make([]time.Duration, len(reqs))
	for i, r := range reqs {
		all[i] = r.dur
	}
	overall := statsOf(all)
	fmt.Printf("\n=== Overall latency ===\n")
	fmt.Printf("  count %d   p50 %s   p90 %s   p95 %s   p99 %s   max %s\n",
		overall.n, fmtDur(overall.p50), fmtDur(overall.p90), fmtDur(overall.p95),
		fmtDur(overall.p99), fmtDur(overall.max))
	fmt.Printf("  total time spent serving requests: %s\n", fmtDur(overall.total))

	rows := buildBuckets(reqs, b)
	if slowThreshold == 0 {
		slowThreshold = autoSlowThreshold(rows)
	}
	markSlow(rows, slowThreshold)
	plotBuckets(rows, b, slowThreshold)
	stalls(rows, b)
	topRoutes(reqs, o.top)
	slowestRequests(reqs, o.top)
	if !o.noPrecurse {
		precursors(rows, events, b, o.lead, o.top)
	}

	p.reportDropped()
	return nil
}

// bucketRow is one point on the timeline. A row with no requests is a gap: the
// api completed nothing in that whole bucket, which on a busy instance means it
// was stalled rather than idle, so gaps are kept rather than skipped.
type bucketRow struct {
	t     time.Time
	label string
	durs  []time.Duration
	s     durStats
	gap   bool
	slow  bool
	// inflight is how many requests were still running during this bucket,
	// reconstructed from each entry's completion time minus its duration. It is
	// the load the process actually carried, which the completion count alone
	// hides: a bucket completing 8 requests may have had 200 in flight.
	inflight int
}

func bucketDuration(b bucketSize) time.Duration {
	switch b {
	case bucketSecond:
		return time.Second
	case bucketHour:
		return time.Hour
	default:
		return time.Minute
	}
}

// maxFilledBuckets caps gap filling, so a log spanning days does not expand into
// millions of second buckets.
const maxFilledBuckets = 20000

func buildBuckets(reqs []requestSample, b bucketSize) []bucketRow {
	step := bucketDuration(b)
	byTime := map[time.Time][]time.Duration{}
	var first, last time.Time
	// an undated api timestamp parses to year 0, which is before Go's zero
	// Time, so the range cannot be tracked by comparing against the zero value
	seen := false
	hasDate := false
	for _, r := range reqs {
		if r.ts.IsZero() {
			continue
		}
		t := r.ts.Truncate(step)
		byTime[t] = append(byTime[t], r.dur)
		if !seen || t.Before(first) {
			first = t
		}
		if !seen || t.After(last) {
			last = t
		}
		seen = true
		hasDate = hasDate || r.hasDate
	}
	if len(byTime) == 0 {
		return nil
	}

	// walk the whole range so empty buckets become rows rather than vanishing
	span := int(last.Sub(first)/step) + 1
	var rows []bucketRow
	if span <= maxFilledBuckets {
		inflight := countInflight(reqs, first, last, step)
		for t := first; !t.After(last); t = t.Add(step) {
			durs := byTime[t]
			rows = append(rows, bucketRow{
				t:        t,
				label:    bucketLabel(t, b, hasDate),
				durs:     durs,
				s:        statsOf(append([]time.Duration(nil), durs...)),
				gap:      len(durs) == 0,
				inflight: inflight[t],
			})
		}
		return rows
	}
	times := make([]time.Time, 0, len(byTime))
	for t := range byTime {
		times = append(times, t)
	}
	sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
	for _, t := range times {
		durs := byTime[t]
		rows = append(rows, bucketRow{
			t:     t,
			label: bucketLabel(t, b, hasDate),
			durs:  durs,
			s:     statsOf(append([]time.Duration(nil), durs...)),
		})
	}
	return rows
}

// countInflight spreads each request over every bucket between its start and
// its completion. A request that began before the log window is counted only
// from the window start, so early buckets read low.
func countInflight(reqs []requestSample, first, last time.Time, step time.Duration) map[time.Time]int {
	inflight := map[time.Time]int{}
	for _, r := range reqs {
		if r.ts.IsZero() {
			continue
		}
		end := r.ts.Truncate(step)
		start := r.ts.Add(-r.dur).Truncate(step)
		if start.Before(first) {
			start = first
		}
		if end.After(last) {
			end = last
		}
		for t := start; !t.After(end); t = t.Add(step) {
			inflight[t]++
		}
	}
	return inflight
}

// autoSlowThreshold picks the p95 of the worst tenth of buckets, so "slow"
// scales with the log rather than with an arbitrary constant. Gaps are excluded:
// they have no p95 and would drag the threshold to zero.
func autoSlowThreshold(rows []bucketRow) time.Duration {
	p95s := make([]time.Duration, 0, len(rows))
	for _, r := range rows {
		if !r.gap {
			p95s = append(p95s, r.s.p95)
		}
	}
	if len(p95s) == 0 {
		return 0
	}
	sort.Slice(p95s, func(i, j int) bool { return p95s[i] < p95s[j] })
	return percentile(p95s, 90)
}

// markSlow treats a gap as slow: completing no request at all is the extreme of
// the same failure, and folding it in lets an onset be detected at the moment
// the api went quiet rather than when it came back.
func markSlow(rows []bucketRow, slow time.Duration) {
	for i := range rows {
		rows[i].slow = rows[i].gap || rows[i].s.p95 >= slow
	}
}

func plotBuckets(rows []bucketRow, b bucketSize, slow time.Duration) {
	fmt.Printf("\n=== Latency over time (%s buckets, bar = p95, slow >= %s) ===\n", b, fmtDur(slow))
	var peak time.Duration
	for _, r := range rows {
		if r.s.p95 > peak {
			peak = r.s.p95
		}
	}
	fmt.Printf("\n%-19s %5s %8s %8s %8s %8s  %s\n",
		"BUCKET", "REQS", "INFLIGHT", "P50", "P95", "MAX", "P95")
	for _, r := range rows {
		if r.gap {
			fmt.Printf("%-19s %5d %8d %8s %8s %8s %s %s\n",
				r.label, 0, r.inflight, "-", "-", "-", "!", "(no request completed)")
			continue
		}
		marker := " "
		if r.slow {
			marker = "!"
		}
		fmt.Printf("%-19s %5d %8d %8s %8s %8s %s %s\n",
			r.label, r.s.n, r.inflight, fmtDur(r.s.p50), fmtDur(r.s.p95), fmtDur(r.s.max),
			marker, durBar(r.s.p95, peak))
	}
}

// stalls reports contiguous runs of gap buckets. On an instance serving traffic
// every minute these are the hard outages, and they are easy to miss in the plot
// because nothing is plotted for them.
func stalls(rows []bucketRow, b bucketSize) {
	step := bucketDuration(b)
	type run struct{ from, to time.Time }
	var runs []run
	for i := 0; i < len(rows); i++ {
		if !rows[i].gap {
			continue
		}
		j := i
		for j+1 < len(rows) && rows[j+1].gap {
			j++
		}
		runs = append(runs, run{rows[i].t, rows[j].t.Add(step)})
		i = j
	}
	fmt.Printf("\n=== Stalls (windows where no request completed) ===\n\n")
	if len(runs) == 0 {
		fmt.Println("  none: every bucket in range completed at least one request")
		return
	}
	for _, r := range runs {
		fmt.Printf("  %s -> %s  (%s)\n",
			r.from.Format("15:04:05"), r.to.Format("15:04:05"), fmtDur(r.to.Sub(r.from)))
	}
}

func durBar(d, peak time.Duration) string {
	const width = 40
	if peak <= 0 || d <= 0 {
		return ""
	}
	filled := int(int64(d) * width / int64(peak))
	if filled == 0 {
		filled = 1
	}
	return strings.Repeat("█", filled)
}

// topRoutes ranks by total time rather than by p95: a route that is merely slow
// matters less than one that is slow and hit constantly.
func topRoutes(reqs []requestSample, top int) {
	byRoute := map[string][]time.Duration{}
	for _, r := range reqs {
		key := r.method + " " + r.route
		byRoute[key] = append(byRoute[key], r.dur)
	}
	type row struct {
		route string
		s     durStats
	}
	rows := make([]row, 0, len(byRoute))
	for k, ds := range byRoute {
		rows = append(rows, row{k, statsOf(ds)})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].s.total > rows[j].s.total })

	fmt.Printf("\n=== Top %d routes by total time spent ===\n\n", top)
	fmt.Printf("%9s %6s %8s %8s %8s  %s\n", "TOTAL", "REQS", "P50", "P95", "MAX", "ROUTE")
	for i, r := range rows {
		if i >= top {
			fmt.Printf("  ... and %d more routes\n", len(rows)-top)
			break
		}
		fmt.Printf("%9s %6d %8s %8s %8s  %s\n",
			fmtDur(r.s.total), r.s.n, fmtDur(r.s.p50), fmtDur(r.s.p95), fmtDur(r.s.max), r.route)
	}
}

func slowestRequests(reqs []requestSample, top int) {
	sorted := append([]requestSample(nil), reqs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].dur > sorted[j].dur })
	fmt.Printf("\n=== %d slowest individual requests ===\n\n", top)
	for i, r := range sorted {
		if i >= top {
			break
		}
		u := r.rawURL
		if len(u) > 110 {
			u = u[:107] + "..."
		}
		fmt.Printf("%9s  %s  %s %d  %s\n", fmtDur(r.dur), r.ts.Format("15:04"), r.method, r.status, u)
	}
}

// ---------------------------------------------------------------------------
// precursor analysis
// ---------------------------------------------------------------------------

// precursors looks for event kinds that are over represented in the buckets
// immediately before latency rises, which is the cheapest available stand-in
// for a cause when the log carries no request ids to trace with.
//
// An onset is a slow bucket whose predecessor was not slow; steady state
// slowness produces no onset, so a log that is uniformly slow reports nothing
// rather than reporting everything.
func precursors(rows []bucketRow, events []logEntry, b bucketSize, lead, top int) {
	var onsets []int
	for i, r := range rows {
		if !r.slow {
			continue
		}
		if i == 0 || !rows[i-1].slow {
			onsets = append(onsets, i)
		}
	}

	fmt.Printf("\n=== What precedes a latency onset (%d lead %s buckets) ===\n", lead, b)
	if len(onsets) == 0 {
		fmt.Println("\n  no onset found: latency never crosses the threshold, or never recovers")
		return
	}

	// the union of lead windows, so an event is never counted twice when two
	// onsets sit close together
	window := map[string]bool{}
	for _, i := range onsets {
		for j := i - lead; j < i; j++ {
			if j >= 0 {
				window[rows[j].label] = true
			}
		}
	}

	// index events by bucket
	kindTotal := map[string]int{}
	kindInWindow := map[string]int{}
	bucketsSeen := map[string]bool{}
	for _, e := range events {
		if e.ts.IsZero() {
			continue
		}
		k := bucketLabel(e.ts, b, e.hasDate)
		bucketsSeen[k] = true
		kind := eventKind(e)
		kindTotal[kind]++
		if window[k] {
			kindInWindow[kind]++
		}
	}
	for _, r := range rows {
		bucketsSeen[r.label] = true
	}

	totalBuckets := len(bucketsSeen)
	windowBuckets := len(window)
	if totalBuckets == 0 || windowBuckets == 0 {
		fmt.Println("\n  not enough timestamped events to compare")
		return
	}
	share := float64(windowBuckets) / float64(totalBuckets)

	type kindRow struct {
		kind     string
		inWindow int
		total    int
		lift     float64
	}
	var ranked []kindRow
	for kind, n := range kindInWindow {
		// a handful of occurrences produces a huge ratio by chance
		if n < 3 {
			continue
		}
		expected := float64(kindTotal[kind]) * share
		if expected <= 0 {
			continue
		}
		ranked = append(ranked, kindRow{kind, n, kindTotal[kind], float64(n) / expected})
	}
	sort.Slice(ranked, func(i, j int) bool { return ranked[i].lift > ranked[j].lift })

	onsetLabels := make([]string, 0, len(onsets))
	for _, i := range onsets {
		onsetLabels = append(onsetLabels, rows[i].label)
	}
	fmt.Printf("\n  onsets (%d): %s\n", len(onsets), strings.Join(onsetLabels, ", "))
	fmt.Printf("  lead window covers %d of %d buckets (%.0f%%)\n\n",
		windowBuckets, totalBuckets, share*100)
	if len(ranked) == 0 {
		fmt.Println("  no event kind occurred often enough in the lead windows to rank")
		return
	}
	fmt.Printf("%6s %7s %7s  %s\n", "LIFT", "LEAD", "TOTAL", "EVENT KIND")
	for i, r := range ranked {
		if i >= top {
			break
		}
		kind := r.kind
		if len(kind) > 100 {
			kind = kind[:97] + "..."
		}
		fmt.Printf("%5.1fx %7d %7d  %s\n", r.lift, r.inWindow, r.total, kind)
	}
	fmt.Println("\n  lift is occurrences per lead bucket over occurrences per bucket overall.")
	fmt.Println("  it ranks coincidence, not cause: a kind that only ever fires during load")
	fmt.Println("  scores high whether it is the trigger or another symptom.")
}

// eventKind labels a non request entry for grouping: the source keeps entries
// from different call sites apart even when normalization collapses their text.
func eventKind(e logEntry) string {
	msg := normalizeMessage(e.message)
	if len(msg) > 90 {
		msg = msg[:90]
	}
	if e.source == "" {
		return e.level + " " + msg
	}
	return e.level + " " + e.source + " " + msg
}
