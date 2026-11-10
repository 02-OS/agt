package sandbox

import (
	"strings"
	"testing"
	"time"
)

func TestRunListingDoesNotStartDocker(t *testing.T) {
	created := time.Date(2026, 11, 10, 13, 0, 0, 0, time.UTC)
	updated := created.Add(time.Minute)
	rec, err := Record("ns", "run_1", "SUCCEEDED", created, updated)
	if err != nil {
		t.Fatal(err)
	}
	if rec.SandboxID != "agt-ns-run_1" {
		t.Fatalf("sandbox id %s", rec.SandboxID)
	}
	text, err := FormatRuns([]ListedRun{rec})
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{"run_1", "agt-ns-run_1", "SUCCEEDED", "2026-11-10T13:00:00Z", "2026-11-10T13:01:00Z"} {
		if !strings.Contains(text, part) {
			t.Fatalf("listing %q missing %s", text, part)
		}
	}
	empty, err := FormatRuns(nil)
	if err != nil || empty != "no runs\n" {
		t.Fatalf("empty %q %v", empty, err)
	}
	if _, err := Record("ns", "run_1", "RUNNING", created, updated); err == nil {
		t.Fatal("unknown state was accepted")
	}
	if _, err := Record("ns", "run_1", "SUCCEEDED", updated, created); err == nil {
		t.Fatal("reversed timestamps were accepted")
	}
	foreign := rec
	foreign.SandboxID = "agt-other-run_9"
	if _, err := FormatRuns([]ListedRun{foreign}); err == nil {
		t.Fatal("foreign sandbox id was accepted")
	}
}
