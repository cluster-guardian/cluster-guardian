package fleet

import (
	"context"
	"log"
	"path/filepath"
	"sync"
	"time"

	"github.com/AndrewKarpaty/cluster-guardian/internal/analyzer"
	"github.com/AndrewKarpaty/cluster-guardian/internal/history"
	"github.com/AndrewKarpaty/cluster-guardian/internal/notify"
	"github.com/AndrewKarpaty/cluster-guardian/internal/report"
)

// Status is what the fleet API exposes per cluster — never credentials.
type Status struct {
	Name     string    `json:"name"`
	Server   string    `json:"server"`
	LastScan time.Time `json:"lastScan"`
	// LastScanSeconds is how long the most recent scan took.
	LastScanSeconds float64 `json:"lastScanSeconds,omitempty"`
	// Scans and ScanErrors count attempts and failures since process start.
	Scans      int             `json:"scans"`
	ScanErrors int             `json:"scanErrors"`
	Error      string          `json:"error,omitempty"`
	Summary    *report.Summary `json:"summary,omitempty"`
}

type clusterState struct {
	cluster      Cluster
	report       *report.Report
	history      *history.Store
	lastScan     time.Time
	lastDuration time.Duration
	lastErr      error
	scans        int
	scanErrors   int
}

// Manager owns the scan schedule and per-cluster state.
type Manager struct {
	lister       ClusterLister
	opts         analyzer.Options
	interval     time.Duration
	timeout      time.Duration
	historyDir   string
	historyLimit int
	notifier     *notify.Notifier
	// scan produces a report for one cluster; injectable for tests.
	scan func(ctx context.Context, c Cluster) (*report.Report, error)

	mu     sync.Mutex
	states map[string]*clusterState
	order  []string
}

// NewManager builds a manager scanning lister's clusters every interval.
// historyDir "" keeps per-cluster history in memory only.
func NewManager(lister ClusterLister, opts analyzer.Options, interval time.Duration, historyDir string, historyLimit int) *Manager {
	m := &Manager{
		lister:       lister,
		opts:         opts,
		interval:     interval,
		timeout:      2 * time.Minute,
		historyDir:   historyDir,
		historyLimit: historyLimit,
		states:       map[string]*clusterState{},
	}
	m.scan = func(ctx context.Context, c Cluster) (*report.Report, error) {
		client, err := c.Build()
		if err != nil {
			return nil, err
		}
		o := m.opts
		if o.ClusterName == "" {
			o.ClusterName = c.Name
		}
		return analyzer.Run(ctx, client, o)
	}
	return m
}

// EnableNotifications posts each cluster's new findings to n after scans.
func (m *Manager) EnableNotifications(n *notify.Notifier) { m.notifier = n }

// SetScanForTest replaces the per-cluster scan function so tests can inject
// synthetic reports.
func (m *Manager) SetScanForTest(scan func(context.Context, Cluster) (*report.Report, error)) {
	m.scan = scan
}

// Run scans immediately, then on every interval tick until ctx is done.
func (m *Manager) Run(ctx context.Context) {
	m.ScanAll(ctx)
	t := time.NewTicker(m.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.ScanAll(ctx)
		}
	}
}

// ScanAll refreshes the registry and scans every cluster with bounded
// concurrency and a per-cluster timeout, so one unreachable cluster never
// stalls the fleet.
func (m *Manager) ScanAll(ctx context.Context) {
	clusters, err := m.lister.Clusters(ctx)
	if err != nil {
		log.Printf("fleet: refreshing cluster registry: %v", err)
	}

	m.mu.Lock()
	m.order = m.order[:0]
	for _, c := range clusters {
		m.order = append(m.order, c.Name)
		if _, ok := m.states[c.Name]; !ok {
			dir := ""
			if m.historyDir != "" {
				dir = filepath.Join(m.historyDir, SanitizeName(c.Name))
			}
			hist, herr := history.New(dir, m.historyLimit)
			if herr != nil {
				log.Printf("fleet: history for %s: %v; falling back to memory", c.Name, herr)
				hist, _ = history.New("", m.historyLimit)
			}
			m.states[c.Name] = &clusterState{history: hist}
		}
		m.states[c.Name].cluster = c
	}
	m.mu.Unlock()

	sem := make(chan struct{}, 3)
	var wg sync.WaitGroup
	for _, c := range clusters {
		wg.Add(1)
		go func(c Cluster) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			cctx, cancel := context.WithTimeout(ctx, m.timeout)
			defer cancel()
			start := time.Now()
			r, scanErr := m.scan(cctx, c)

			m.mu.Lock()
			defer m.mu.Unlock()
			st := m.states[c.Name]
			st.lastScan, st.lastErr = time.Now(), scanErr
			st.lastDuration = time.Since(start)
			st.scans++
			if scanErr != nil {
				st.scanErrors++
				log.Printf("fleet: scanning %s: %v", c.Name, scanErr)
				return
			}
			st.report = r
			st.history.Append(r)
			if m.notifier != nil {
				if d := st.history.LastDiff(); d != nil && len(d.New) > 0 {
					// Post outside the lock: a slow webhook must not block
					// dashboard reads.
					go m.postNotification(c.Name, d.New)
				}
			}
		}(c)
	}
	wg.Wait()
}

func (m *Manager) postNotification(cluster string, findings []report.LocatedFinding) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := m.notifier.Notify(ctx, cluster, findings); err != nil {
		log.Printf("fleet: notify for %s: %v", cluster, err)
	}
}

// Statuses lists every known cluster in registry order.
func (m *Manager) Statuses() []Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Status, 0, len(m.order))
	for _, name := range m.order {
		st := m.states[name]
		s := Status{
			Name:            name,
			Server:          st.cluster.Server,
			LastScan:        st.lastScan,
			LastScanSeconds: st.lastDuration.Seconds(),
			Scans:           st.scans,
			ScanErrors:      st.scanErrors,
		}
		if st.lastErr != nil {
			s.Error = st.lastErr.Error()
		}
		if st.report != nil {
			sum := st.report.Summary
			s.Summary = &sum
		}
		out = append(out, s)
	}
	return out
}

// Report returns the latest report for a cluster, or nil if unknown or not
// yet scanned successfully.
func (m *Manager) Report(name string) *report.Report {
	m.mu.Lock()
	defer m.mu.Unlock()
	if st, ok := m.states[name]; ok {
		return st.report
	}
	return nil
}

// History returns the history index for a cluster.
func (m *Manager) History(name string) []history.Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	if st, ok := m.states[name]; ok {
		return st.history.Entries()
	}
	return nil
}

// Diff returns the run-over-run diff for a cluster, or nil.
func (m *Manager) Diff(name string) *report.DiffResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	if st, ok := m.states[name]; ok {
		return st.history.LastDiff()
	}
	return nil
}
