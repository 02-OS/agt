package telemetry

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

var toolBuckets = []float64{0.01, 0.05, 0.1, 0.5, 1, 5, 30}

type transitionKey struct {
	from string
	to   string
}

type toolHist struct {
	buckets []uint64
	sum     float64
	count   uint64
}

// RunStats captures store-level run counts and accumulated spend for /metrics.
type RunStats struct {
	Active          int64
	ByState         map[string]int64
	TotalCostMicros int64
}

// Metrics records in-process daemon operational counters and histograms.
type Metrics struct {
	mu              sync.Mutex
	transitions     map[transitionKey]uint64
	tools           map[string]*toolHist
	sandboxCleanups uint64
	costMicros      int64
}

// NewMetrics returns an empty Prometheus metrics registry.
func NewMetrics() *Metrics {
	return &Metrics{
		transitions: map[transitionKey]uint64{},
		tools:       map[string]*toolHist{},
	}
}

func (m *Metrics) RecordTransition(from, to string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.transitions[transitionKey{from: from, to: to}]++
	m.mu.Unlock()
}

func (m *Metrics) ObserveTool(tool string, d time.Duration) {
	if m == nil || tool == "" {
		return
	}
	sec := d.Seconds()
	if sec < 0 {
		sec = 0
	}
	m.mu.Lock()
	h, ok := m.tools[tool]
	if !ok {
		h = &toolHist{buckets: make([]uint64, len(toolBuckets))}
		m.tools[tool] = h
	}
	for i, bound := range toolBuckets {
		if sec <= bound {
			h.buckets[i]++
		}
	}
	h.sum += sec
	h.count++
	m.mu.Unlock()
}

func (m *Metrics) AddSandboxCleanups(n int) {
	if m == nil || n <= 0 {
		return
	}
	m.mu.Lock()
	m.sandboxCleanups += uint64(n)
	m.mu.Unlock()
}

func (m *Metrics) AddCostMicros(micros int64) {
	if m == nil || micros <= 0 {
		return
	}
	m.mu.Lock()
	m.costMicros += micros
	m.mu.Unlock()
}

// Render formats Prometheus text exposition metrics combining DB stats and in-process counters.
func (m *Metrics) Render(stats RunStats) string {
	var b strings.Builder

	b.WriteString("# HELP agt_runs_active Number of active non-terminal runs.\n")
	b.WriteString("# TYPE agt_runs_active gauge\n")
	fmt.Fprintf(&b, "agt_runs_active %d\n", stats.Active)

	b.WriteString("# HELP agt_runs_by_state Current number of runs by state.\n")
	b.WriteString("# TYPE agt_runs_by_state gauge\n")
	if len(stats.ByState) > 0 {
		states := make([]string, 0, len(stats.ByState))
		for s := range stats.ByState {
			states = append(states, s)
		}
		sort.Strings(states)
		for _, s := range states {
			fmt.Fprintf(&b, "agt_runs_by_state{state=%q} %d\n", s, stats.ByState[s])
		}
	}

	var transitions []transitionKey
	var transVals []uint64
	var toolNames []string
	var toolSnapshots []toolHist
	var cleanups uint64
	var memCost int64
	if m != nil {
		m.mu.Lock()
		transitions = make([]transitionKey, 0, len(m.transitions))
		for k := range m.transitions {
			transitions = append(transitions, k)
		}
		sort.Slice(transitions, func(i, j int) bool {
			if transitions[i].from != transitions[j].from {
				return transitions[i].from < transitions[j].from
			}
			return transitions[i].to < transitions[j].to
		})
		transVals = make([]uint64, len(transitions))
		for i, k := range transitions {
			transVals[i] = m.transitions[k]
		}

		toolNames = make([]string, 0, len(m.tools))
		for k := range m.tools {
			toolNames = append(toolNames, k)
		}
		sort.Strings(toolNames)
		toolSnapshots = make([]toolHist, len(toolNames))
		for i, name := range toolNames {
			h := m.tools[name]
			cp := make([]uint64, len(h.buckets))
			copy(cp, h.buckets)
			toolSnapshots[i] = toolHist{buckets: cp, sum: h.sum, count: h.count}
		}
		cleanups = m.sandboxCleanups
		memCost = m.costMicros
		m.mu.Unlock()
	}

	b.WriteString("# HELP agt_state_transitions_total Total run state transitions observed.\n")
	b.WriteString("# TYPE agt_state_transitions_total counter\n")
	for i, k := range transitions {
		fmt.Fprintf(&b, "agt_state_transitions_total{from=%q,to=%q} %d\n", k.from, k.to, transVals[i])
	}

	b.WriteString("# HELP agt_tool_duration_seconds Tool execution latency distribution.\n")
	b.WriteString("# TYPE agt_tool_duration_seconds histogram\n")
	for i, name := range toolNames {
		h := toolSnapshots[i]
		for bi, bound := range toolBuckets {
			fmt.Fprintf(&b, "agt_tool_duration_seconds_bucket{tool=%q,le=\"%g\"} %d\n", name, bound, h.buckets[bi])
		}
		fmt.Fprintf(&b, "agt_tool_duration_seconds_bucket{tool=%q,le=\"+Inf\"} %d\n", name, h.count)
		fmt.Fprintf(&b, "agt_tool_duration_seconds_sum{tool=%q} %.9f\n", name, h.sum)
		fmt.Fprintf(&b, "agt_tool_duration_seconds_count{tool=%q} %d\n", name, h.count)
	}

	b.WriteString("# HELP agt_sandbox_cleanups_total Total sandbox containers cleaned up.\n")
	b.WriteString("# TYPE agt_sandbox_cleanups_total counter\n")
	fmt.Fprintf(&b, "agt_sandbox_cleanups_total %d\n", cleanups)

	totalCost := stats.TotalCostMicros
	if totalCost == 0 && memCost > 0 {
		totalCost = memCost
	}
	b.WriteString("# HELP agt_token_cost_micros_total Accumulated token cost in USD micros.\n")
	b.WriteString("# TYPE agt_token_cost_micros_total counter\n")
	fmt.Fprintf(&b, "agt_token_cost_micros_total %d\n", totalCost)

	return b.String()
}
