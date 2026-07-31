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
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gorm.io/gorm"
)

// QueryStat aggregates all executions of a single normalized statement.
type QueryStat struct {
	SQL      string
	Calls    int64
	Duration time.Duration
	Rows     int64
}

// QueryCounter is a GORM plugin that counts every statement issued through a
// *gorm.DB, so benchmarks can report queries/op and spot N+1 patterns.
//
// It is intended for tests/benchmarks only: it keeps one entry per distinct
// normalized statement in memory.
type QueryCounter struct {
	calls    atomic.Int64
	duration atomic.Int64 // nanoseconds
	rows     atomic.Int64

	mu    sync.Mutex
	stats map[string]*QueryStat
}

const queryCounterStartKey = "bench:query_start"

// placeholder lists such as "$1,$2,$3,..." differ per call but are the same
// statement shape - collapse them so the report stays readable.
var placeholderListPattern = regexp.MustCompile(`\$\d+(\s*,\s*\$\d+)+`)

func NewQueryCounter() *QueryCounter {
	return &QueryCounter{stats: make(map[string]*QueryStat)}
}

func (q *QueryCounter) Name() string { return "devguard:query_counter" }

// Initialize registers the counting callbacks on every GORM processor.
func (q *QueryCounter) Initialize(db *gorm.DB) error {
	// GORM's processor type is unexported, so each processor is registered
	// through its own closure instead of a shared helper.
	register := []func() error{
		func() error { return db.Callback().Create().Before("*").Register("bench:count_before_create", q.before) },
		func() error { return db.Callback().Create().After("*").Register("bench:count_after_create", q.after) },
		func() error { return db.Callback().Query().Before("*").Register("bench:count_before_query", q.before) },
		func() error { return db.Callback().Query().After("*").Register("bench:count_after_query", q.after) },
		func() error { return db.Callback().Update().Before("*").Register("bench:count_before_update", q.before) },
		func() error { return db.Callback().Update().After("*").Register("bench:count_after_update", q.after) },
		func() error { return db.Callback().Delete().Before("*").Register("bench:count_before_delete", q.before) },
		func() error { return db.Callback().Delete().After("*").Register("bench:count_after_delete", q.after) },
		func() error { return db.Callback().Row().Before("*").Register("bench:count_before_row", q.before) },
		func() error { return db.Callback().Row().After("*").Register("bench:count_after_row", q.after) },
		func() error { return db.Callback().Raw().Before("*").Register("bench:count_before_raw", q.before) },
		func() error { return db.Callback().Raw().After("*").Register("bench:count_after_raw", q.after) },
	}

	for _, fn := range register {
		if err := fn(); err != nil {
			return err
		}
	}
	return nil
}

func (q *QueryCounter) before(db *gorm.DB) {
	db.InstanceSet(queryCounterStartKey, time.Now())
}

func (q *QueryCounter) after(db *gorm.DB) {
	var elapsed time.Duration
	if start, ok := db.InstanceGet(queryCounterStartKey); ok {
		if t, ok := start.(time.Time); ok {
			elapsed = time.Since(t)
		}
	}

	q.calls.Add(1)
	q.duration.Add(int64(elapsed))
	q.rows.Add(db.RowsAffected)

	sql := normalizeSQL(db.Statement.SQL.String())
	if sql == "" {
		return
	}

	q.mu.Lock()
	defer q.mu.Unlock()
	stat, ok := q.stats[sql]
	if !ok {
		stat = &QueryStat{SQL: sql}
		q.stats[sql] = stat
	}
	stat.Calls++
	stat.Duration += elapsed
	stat.Rows += db.RowsAffected
}

func normalizeSQL(sql string) string {
	sql = strings.Join(strings.Fields(sql), " ")
	return placeholderListPattern.ReplaceAllString(sql, "$$?,...")
}

// Reset clears all collected data. Call it right before the measured section.
func (q *QueryCounter) Reset() {
	q.calls.Store(0)
	q.duration.Store(0)
	q.rows.Store(0)

	q.mu.Lock()
	defer q.mu.Unlock()
	q.stats = make(map[string]*QueryStat)
}

func (q *QueryCounter) Calls() int64            { return q.calls.Load() }
func (q *QueryCounter) Duration() time.Duration { return time.Duration(q.duration.Load()) }
func (q *QueryCounter) Rows() int64             { return q.rows.Load() }

// TopStats returns the n statements with the most calls, descending.
func (q *QueryCounter) TopStats(n int) []QueryStat {
	q.mu.Lock()
	stats := make([]QueryStat, 0, len(q.stats))
	for _, stat := range q.stats {
		stats = append(stats, *stat)
	}
	q.mu.Unlock()

	sort.Slice(stats, func(i, j int) bool {
		if stats[i].Calls != stats[j].Calls {
			return stats[i].Calls > stats[j].Calls
		}
		return stats[i].Duration > stats[j].Duration
	})

	if n > 0 && len(stats) > n {
		stats = stats[:n]
	}
	return stats
}

// Report renders a compact, line-oriented summary. iterations scales the
// per-call numbers down to "per benchmark iteration".
func (q *QueryCounter) Report(topN, iterations int) []string {
	if iterations <= 0 {
		iterations = 1
	}

	lines := []string{
		fmt.Sprintf("DB calls: %d total (%.1f per op), %s total (%s per op), rows affected: %d",
			q.Calls(),
			float64(q.Calls())/float64(iterations),
			q.Duration().Round(time.Millisecond),
			(q.Duration() / time.Duration(iterations)).Round(time.Millisecond),
			q.Rows(),
		),
	}

	for _, stat := range q.TopStats(topN) {
		lines = append(lines, fmt.Sprintf("  %6d calls %10s %s",
			stat.Calls,
			stat.Duration.Round(time.Millisecond),
			truncate(stat.SQL, 160),
		))
	}
	return lines
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
