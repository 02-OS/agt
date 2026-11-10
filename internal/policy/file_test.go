package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyFileTightensAllowAndCannotLoosen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	body := []byte(`{
		"version": "policy.file.v1",
		"rules": [
			{"tool": "run_test", "decision": "require_approval"},
			{"tool": "write_file", "decision": "deny", "path_prefix": "payments"}
		],
		"limits": {"max_steps": 4, "max_write_bytes": 8},
		"approvals": ["apply_patch"]
	}`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	runTest, err := DecideWithFile("run_test", json.RawMessage(`{}`), &file)
	base, err2 := Decide("run_test", json.RawMessage(`{}`))
	if err != nil || err2 != nil {
		t.Fatal(err, err2)
	}
	if runTest.Decision != RequireApproval || runTest.ArgsHash != base.ArgsHash || runTest.ArgsHash == "" {
		t.Fatalf("run_test %+v base %s", runTest, base.ArgsHash)
	}

	other, err := DecideWithFile("write_file", json.RawMessage(`{"path":"counter.go","content":"ok","before_sha256":""}`), &file)
	if err != nil || other.Decision != Allow {
		t.Fatalf("unrelated write %+v %v", other, err)
	}
	scoped, err := DecideWithFile("write_file", json.RawMessage(`{"path":"payments/processor.py","content":"ok","before_sha256":""}`), &file)
	if err != nil || scoped.Decision != Deny || !strings.Contains(scoped.Reason, "tightened") {
		t.Fatalf("scoped write %+v %v", scoped, err)
	}
	if scoped.ArgsHash != mustDecide(t, "write_file", `{"path":"payments/processor.py","content":"ok","before_sha256":""}`).ArgsHash {
		t.Fatal("tightening changed the args hash")
	}

	wide, err := DecideWithFile("apply_patch", json.RawMessage(`{"path":"counter.go","old":"a","new":"b"}`), &file)
	if err != nil || wide.Decision != RequireApproval || !strings.Contains(wide.Reason, "requires approval") {
		t.Fatalf("approval list %+v %v", wide, err)
	}

	pushed, err := DecideWithFile("git_push", json.RawMessage(`{"remote":"origin","branch":"main","commit":"abc123"}`), &file)
	code := mustDecide(t, "git_push", `{"remote":"origin","branch":"main","commit":"abc123"}`)
	if err != nil || pushed.Decision != Deny || pushed.Reason != code.Reason || pushed.ArgsHash != code.ArgsHash {
		t.Fatalf("push was loosened: %+v code %+v", pushed, code)
	}

	askPatch, err := DecideForFile("ask", "apply_patch", json.RawMessage(`{"path":"counter.go","old":"a","new":"b"}`), &file)
	if err != nil || askPatch.Decision != Deny || !strings.Contains(askPatch.Reason, "read-only") {
		t.Fatalf("ask stayed denied: %+v %v", askPatch, err)
	}

	if file.StepLimit(8) != 4 || file.StepLimit(2) != 2 || file.StepLimit(0) != 0 || file.StepLimit(-1) != 4 {
		t.Fatalf("step limit got %d %d %d %d", file.StepLimit(8), file.StepLimit(2), file.StepLimit(0), file.StepLimit(-1))
	}

	huge := json.RawMessage(`{"path":"note.txt","content":"0123456789","before_sha256":""}`)
	limited, err := DecideWithFile("write_file", huge, &file)
	if err != nil || limited.Decision != Deny || limited.Reason != "policy file write limit" {
		t.Fatalf("write limit %+v %v", limited, err)
	}
	if limited.ArgsHash != mustDecide(t, "write_file", string(huge)).ArgsHash {
		t.Fatal("write limit changed the args hash")
	}
}

func TestPolicyFileRejectsLooseningAndSymlinks(t *testing.T) {
	_, err := ParseFile([]byte(`{"version":"policy.file.v1","rules":[{"tool":"git_push","decision":"allow"}]}`))
	if err == nil || !strings.Contains(err.Error(), "cannot allow") {
		t.Fatalf("allow rule: %v", err)
	}
	_, err = ParseFile([]byte(`{"version":"policy.file.v1","limits":{"max_write_bytes":200001}}`))
	if err == nil || !strings.Contains(err.Error(), "max_write_bytes") {
		t.Fatalf("loose write cap: %v", err)
	}
	_, err = ParseFile([]byte(`{"version":"nope"}`))
	if err == nil || !strings.Contains(err.Error(), "policy version") {
		t.Fatalf("version: %v", err)
	}

	dir := t.TempDir()
	target := filepath.Join(dir, "real.json")
	if err := os.WriteFile(target, []byte(`{"version":"policy.file.v1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "policy.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(link); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlink: %v", err)
	}

	constructed := File{Version: FileVersion, Rules: []Rule{{Tool: "git_push", Decision: string(Allow)}}}
	denied := mustDecide(t, "git_push", `{"remote":"origin","branch":"main","commit":"abc123"}`)
	if got := constructed.Tighten(denied); got.Decision != Deny || got.ArgsHash != denied.ArgsHash || got.Reason != denied.Reason {
		t.Fatalf("constructed allow loosened a denial: %+v", got)
	}
	shell := mustDecide(t, "shell", `{"cmd":"id"}`)
	approved := File{Version: FileVersion, Approvals: []string{"shell"}}
	if got := approved.Tighten(shell); got.Decision != Deny || got.ArgsHash != shell.ArgsHash {
		t.Fatalf("approval list loosened an unknown tool: %+v", got)
	}
}

func TestEmptyPolicyFileChangesNothing(t *testing.T) {
	file, err := ParseFile([]byte(`{"version":"policy.file.v1"}`))
	if err != nil {
		t.Fatal(err)
	}
	raw := json.RawMessage(`{"path":"counter.go","content":"package p\n","before_sha256":""}`)
	got, err := DecideWithFile("write_file", raw, &file)
	want := mustDecide(t, "write_file", string(raw))
	if err != nil || got.Decision != want.Decision || got.ArgsHash != want.ArgsHash || got.Reason != want.Reason {
		t.Fatalf("empty file changed %+v want %+v", got, want)
	}
	if got, err := DecideWithFile("write_file", raw, nil); err != nil || got.ArgsHash != want.ArgsHash {
		t.Fatalf("nil file: %+v %v", got, err)
	}
}

func mustDecide(t *testing.T, tool, raw string) Result {
	t.Helper()
	result, err := Decide(tool, json.RawMessage(raw))
	if err != nil {
		t.Fatal(err)
	}
	return result
}
