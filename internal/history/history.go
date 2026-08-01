// Package history persists analysis reports across serve-mode runs and
// provides the data for trends and run-over-run diffs.
package history

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/cluster-guardian/cluster-guardian/internal/report"
)

// Entry is one run in the history index.
type Entry struct {
	Time    time.Time      `json:"time"`
	Summary report.Summary `json:"summary"`
}

// Store keeps the most recent runs. With a directory it persists each report
// as a JSON file (surviving restarts); without one it is memory-only, which
// still gives trends for the lifetime of the process.
type Store struct {
	mu         sync.Mutex
	dir        string
	limit      int
	entries    []Entry
	files      []string // parallel to entries; "" when not on disk
	prev, last *report.Report
}

// New opens a store, loading any reports previously persisted in dir.
// An empty dir means memory-only.
func New(dir string, limit int) (*Store, error) {
	if limit < 2 {
		limit = 2 // a diff needs two runs
	}
	s := &Store{dir: dir, limit: limit}
	if dir == "" {
		return s, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("creating history dir: %w", err)
	}
	names, err := filepath.Glob(filepath.Join(dir, "report-*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(names) // timestamped names sort chronologically
	for _, name := range names {
		data, err := os.ReadFile(name)
		if err != nil {
			continue
		}
		var r report.Report
		if err := json.Unmarshal(data, &r); err != nil {
			continue // unreadable history entries are skipped, not fatal
		}
		s.push(&r, name)
	}
	return s, nil
}

// Append records a fresh report. Persistence is best-effort: a failed write
// keeps the run in memory.
func (s *Store) Append(r *report.Report) {
	s.mu.Lock()
	defer s.mu.Unlock()
	file := ""
	if s.dir != "" {
		file = filepath.Join(s.dir, "report-"+r.GeneratedAt.UTC().Format("20060102T150405.000")+"Z.json")
		if data, err := json.Marshal(r); err == nil {
			if err := os.WriteFile(file, data, 0o600); err != nil {
				file = ""
			}
		}
	}
	s.push(r, file)
}

// push appends an entry and prunes beyond the limit. Caller holds the lock
// (or is the constructor).
func (s *Store) push(r *report.Report, file string) {
	s.entries = append(s.entries, Entry{Time: r.GeneratedAt, Summary: r.Summary})
	s.files = append(s.files, file)
	s.prev, s.last = s.last, r
	for len(s.entries) > s.limit {
		if s.files[0] != "" {
			_ = os.Remove(s.files[0])
		}
		s.entries = s.entries[1:]
		s.files = s.files[1:]
	}
}

// Entries returns the history index, oldest first.
func (s *Store) Entries() []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Entry(nil), s.entries...)
}

// LastDiff returns the diff between the two most recent runs, or nil when
// fewer than two runs are known.
func (s *Store) LastDiff() *report.DiffResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.prev == nil || s.last == nil {
		return nil
	}
	d := report.Diff(s.prev, s.last)
	return &d
}
