package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/csy20/agt/internal/run"
)

// ShouldSweep reports whether a labelled container is safe to remove.
// Live work, including EXECUTING and VERIFYING, is left alone. A missing run
// is abandoned. A lookup error is not a decision: callers skip that container.
func ShouldSweep(state run.State, found bool) bool {
	if !found {
		return true
	}
	switch state {
	case run.Succeeded, run.FailedTerminal, run.Paused, run.PausedBudget, run.Cancelled:
		return true
	default:
		return false
	}
}

// ParseRunLabels reads one docker `--format '{{json .Labels}}'` line or `k=v,...` label string.
func ParseRunLabels(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "null" {
		return "", false
	}
	var labels map[string]string
	switch raw[0] {
	case '{':
		if err := json.Unmarshal([]byte(raw), &labels); err != nil {
			return "", false
		}
	case '"':
		var line string
		if err := json.Unmarshal([]byte(raw), &line); err != nil {
			return "", false
		}
		var ok bool
		labels, ok = parseLabelPairs(line)
		if !ok {
			return "", false
		}
	default:
		var ok bool
		labels, ok = parseLabelPairs(raw)
		if !ok {
			return "", false
		}
	}
	id := strings.TrimSpace(labels["agt-run"])
	if id == "" {
		return "", false
	}
	return id, true
}

func parseLabelPairs(s string) (map[string]string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || !strings.Contains(s, "=") {
		return nil, false
	}
	labels := map[string]string{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return nil, false
		}
		labels[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return labels, len(labels) > 0
}

// Sweep removes containers whose runs are terminal, paused, cancelled, or gone.
// It does not delete the data directory or result artifacts. lookup errors skip
// that container.
func (r *Runner) Sweep(ctx context.Context, lookup func(runID string) (run.State, bool, error)) (int, error) {
	ids, err := labelledRunIDs(ctx, r.namespace())
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, id := range ids {
		state, found, err := lookup(id)
		if err != nil {
			continue
		}
		if !ShouldSweep(state, found) {
			continue
		}
		if err := r.Destroy(ctx, id); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

func labelledRunIDs(ctx context.Context, namespace string) ([]string, error) {
	cmd := dockerCommand(ctx, "ps", "-a",
		"--filter", "label=agt-namespace="+namespace,
		"--filter", "label=agt-run",
		"--format", "{{json .Labels}}")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("docker ps: %w", err)
	}
	var ids []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		id, ok := ParseRunLabels(line)
		if !ok || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	return ids, nil
}
