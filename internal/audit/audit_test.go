package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/csy20/agt/internal/policy"
)

func TestAuditIsAppendOnlyAndPrivate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	decision, err := policy.Decide("write_file", json.RawMessage(`{"path":"counter.go","content":"package p\n","before_sha256":""}`))
	if err != nil {
		t.Fatal(err)
	}
	first := Event{Time: "2026-11-10T13:00:00Z", Kind: "decision", RunID: "run_1", Tool: "write_file", ArgsHash: decision.ArgsHash, Decision: string(decision.Decision)}
	if err := Append(path, first); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
	second := Event{Time: "2026-11-10T13:01:00Z", Kind: "state", RunID: "run_1", SandboxID: "agt-ns-run_1", State: "SUCCEEDED"}
	if err := Append(path, second); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	events, err := Replay(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].ArgsHash != decision.ArgsHash || events[0].Seq != 1 || events[1].Seq != 2 {
		t.Fatalf("%+v", events)
	}
	if events[0].Prev != "genesis" || events[1].Prev == "" || events[1].Prev == events[0].Prev {
		t.Fatalf("chain %+v", events)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("replay rewrote the log")
	}
	lines := strings.Split(strings.TrimSuffix(string(after), "\n"), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], decision.ArgsHash) {
		t.Fatalf("lines %v", lines)
	}

	rewritten := []byte(lines[1] + "\n")
	if err := os.WriteFile(path, rewritten, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Replay(path); err == nil {
		t.Fatal("a rewritten line was accepted")
	}
}

func TestAuditRefusesSymlinkAndLooseMode(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.jsonl")
	if err := os.WriteFile(real, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "audit.jsonl")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := Append(link, Event{Kind: "state"}); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink: %v", err)
	}
	loose := filepath.Join(dir, "loose.jsonl")
	if err := os.WriteFile(loose, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	err := Append(loose, Event{Kind: "state"})
	if runtime.GOOS == "windows" {
		if err != nil {
			t.Fatalf("loose: %v", err)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), "not private") {
		t.Fatalf("loose: %v", err)
	}
}
