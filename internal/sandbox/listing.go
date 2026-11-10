package sandbox

import (
	"fmt"
	"strings"
	"time"

	"github.com/csy20/agt/internal/run"
)

// ListedRun is a run the caller already recorded. Building this value does
// not start Docker and does not inspect a container.
type ListedRun struct {
	RunID     string
	SandboxID string
	State     string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Record fills the sandbox id from the same name the runner would use.
// It does not call Docker.
func Record(namespace, runID, state string, created, updated time.Time) (ListedRun, error) {
	if strings.TrimSpace(runID) == "" || strings.ContainsAny(runID, " \t\r\n") {
		return ListedRun{}, fmt.Errorf("run id is empty")
	}
	if !knownState(state) {
		return ListedRun{}, fmt.Errorf("run state is unknown")
	}
	if created.IsZero() || updated.IsZero() || updated.Before(created) {
		return ListedRun{}, fmt.Errorf("run timestamps are invalid")
	}
	return ListedRun{
		RunID:     runID,
		SandboxID: containerName(namespace, runID),
		State:     state,
		CreatedAt: created.UTC(),
		UpdatedAt: updated.UTC(),
	}, nil
}

// FormatRuns prints sandbox id, state, and timestamps. An empty list is
// "no runs" and still does not start Docker.
func FormatRuns(records []ListedRun) (string, error) {
	if len(records) == 0 {
		return "no runs\n", nil
	}
	var b strings.Builder
	for _, rec := range records {
		if rec.RunID == "" || rec.SandboxID == "" || !knownState(rec.State) {
			return "", fmt.Errorf("run record is incomplete")
		}
		if !strings.Contains(rec.SandboxID, sanitizeName(rec.RunID)) {
			return "", fmt.Errorf("sandbox id is not this run")
		}
		if rec.CreatedAt.IsZero() || rec.UpdatedAt.Before(rec.CreatedAt) {
			return "", fmt.Errorf("run timestamps are invalid")
		}
		fmt.Fprintf(&b, "%s  %s  %s  created %s  updated %s\n",
			rec.RunID, rec.SandboxID, rec.State,
			rec.CreatedAt.UTC().Format(time.RFC3339Nano),
			rec.UpdatedAt.UTC().Format(time.RFC3339Nano))
	}
	return b.String(), nil
}

func knownState(state string) bool {
	switch run.State(state) {
	case run.Created, run.Contextualising, run.Planning, run.Executing, run.Observing,
		run.Verifying, run.AwaitingApproval, run.Committing, run.Succeeded, run.Paused,
		run.PausedBudget, run.Cancelled, run.FailedRetryable, run.FailedTerminal:
		return true
	default:
		return false
	}
}
