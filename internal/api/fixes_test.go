package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/csy20/agt/internal/config"
	"github.com/csy20/agt/internal/patch"
	"github.com/csy20/agt/internal/profile"
	"github.com/csy20/agt/internal/store"
)

func TestHideCommandRedactsSecretsAndKeepsValidJSON(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "sk-live-test-value-999")
	srv := New(nil, config.Config{
		DataDir:     t.TempDir(),
		ModelAPIKey: "agt-model-secret-888",
	}, "tok")

	cmd := store.Command{
		CommandID:  "cmd_1",
		RunID:      "run_1",
		Tool:       "read_file_range",
		Canonical:  json.RawMessage(`{"path":"app.py","api_key":"inline-secret-value","env":"OPENAI_API_KEY=sk-live-test-value-999"}`),
		Result:     json.RawMessage(`{"output":"bearer sk-live-test-value-999 and agt-model-secret-888","token":"tok-secret-123"}`),
		ApprovalID: "ok",
	}
	redacted := srv.hideCommand(cmd)
	for _, secret := range []string{"sk-live-test-value-999", "agt-model-secret-888", "inline-secret-value", "tok-secret-123"} {
		if strings.Contains(string(redacted.Canonical), secret) || strings.Contains(string(redacted.Result), secret) {
			t.Fatalf("secret %q leaked in %s / %s", secret, redacted.Canonical, redacted.Result)
		}
	}
	var obj map[string]any
	if err := json.Unmarshal(redacted.Canonical, &obj); err != nil {
		t.Fatalf("canonical invalid JSON: %v\n%s", err, redacted.Canonical)
	}
	if obj["path"] != "app.py" {
		t.Fatalf("non-secret path changed: %#v", obj)
	}
	if err := json.Unmarshal(redacted.Result, &obj); err != nil {
		t.Fatalf("result invalid JSON: %v\n%s", err, redacted.Result)
	}
}

func TestStreamFlushesHeadersImmediately(t *testing.T) {
	srv := New(nil, config.Config{}, "tok")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/runs/run_1/events?stream=1", nil)
	srv.stream(rec, req, "run_1", 0)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !rec.Flushed {
		t.Fatal("stream did not flush headers immediately")
	}
	if !strings.Contains(rec.Body.String(), ": connected") {
		t.Fatalf("expected SSE prelude, got %q", rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content-type = %q", ct)
	}
}

func TestMetricsEndpointRequiresAuthAndRendersPrometheus(t *testing.T) {
	srv := New(nil, config.Config{DataDir: t.TempDir()}, "secret-bearer")
	srv.Metrics.RecordTransition("PLANNING", "EXECUTING")
	srv.Metrics.ObserveTool("search_code", 15*time.Millisecond)
	srv.Metrics.AddSandboxCleanups(2)

	h := srv.Handler()
	unauth := httptest.NewRecorder()
	h.ServeHTTP(unauth, httptest.NewRequest(http.MethodGet, "http://127.0.0.1/metrics", nil))
	if unauth.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /metrics returned %d, want 401", unauth.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/metrics", nil)
	req.Header.Set("Authorization", "Bearer secret-bearer")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics status = %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"agt_runs_active 0", `agt_state_transitions_total{from="PLANNING",to="EXECUTING"} 1`, "agt_sandbox_cleanups_total 2"} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in /metrics:\n%s", want, body)
		}
	}
}

func TestReleaseApplyLockPreservesIncompleteRollback(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, "apply.lock")

	if err := os.WriteFile(lockPath, []byte("rb\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	releaseApplyLock(lockPath, errors.New("apply failed; rollback incomplete: restore err"))
	if _, err := os.Stat(lockPath); err != nil {
		t.Fatalf("apply.lock removed after incomplete rollback: %v", err)
	}

	releaseApplyLock(lockPath, errors.New("hash mismatch"))
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("apply.lock remained after clean failure: %v", err)
	}
}

func TestPruneExpiredRunsRespectsLocksAndDryRun(t *testing.T) {
	dataDir := t.TempDir()
	runsDir := filepath.Join(dataDir, "runs")
	lockedDir := filepath.Join(runsDir, "run_locked")
	expiredDir := filepath.Join(runsDir, "run_old")
	freshDir := filepath.Join(runsDir, "run_fresh")
	for _, d := range []string{lockedDir, expiredDir, freshDir} {
		if err := os.MkdirAll(filepath.Join(d, "work"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "work", "file.txt"), []byte("payload"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(lockedDir, "apply.lock"), []byte("rb\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldTime := time.Now().Add(-48 * time.Hour)
	for _, d := range []string{lockedDir, filepath.Join(lockedDir, "work"), expiredDir, filepath.Join(expiredDir, "work")} {
		if err := os.Chtimes(d, oldTime, oldTime); err != nil {
			t.Fatal(err)
		}
	}

	dry, err := PruneExpiredRuns(context.Background(), nil, dataDir, 24*time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	if dry.Removed != 1 || len(dry.PrunedRunIDs) != 1 || dry.PrunedRunIDs[0] != "run_old" || dry.BytesFreed <= 0 {
		t.Fatalf("unexpected dry run report: %+v", dry)
	}
	if _, err := os.Stat(expiredDir); err != nil {
		t.Fatalf("dry run deleted %s", expiredDir)
	}

	real, err := PruneExpiredRuns(context.Background(), nil, dataDir, 24*time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	if real.Removed != 1 || real.PrunedRunIDs[0] != "run_old" {
		t.Fatalf("unexpected gc report: %+v", real)
	}
	if _, err := os.Stat(expiredDir); !os.IsNotExist(err) {
		t.Fatalf("expired dir still exists: %v", err)
	}
	if _, err := os.Stat(lockedDir); err != nil {
		t.Fatalf("locked dir was removed: %v", err)
	}
	if _, err := os.Stat(freshDir); err != nil {
		t.Fatalf("fresh dir was removed: %v", err)
	}
}

func TestCodexExcerptsConfigurableAndSecretFree(t *testing.T) {
	work := t.TempDir()
	if err := os.MkdirAll(filepath.Join(work, "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "pkg", "a.py"), []byte("def a(): pass\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "pkg", "bin.dat"), []byte("ab\x00cd"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, ".env"), []byte("KEY=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := codexExcerpts(work)
	if len(got) != 1 || got[0] != "pkg/a.py" {
		t.Fatalf("auto excerpts = %v", got)
	}
	globs, err := resolveCodexExcerpts(work, nil, []string{"pkg/*.py"})
	if err != nil || len(globs) != 1 || globs[0] != "pkg/a.py" {
		t.Fatalf("glob excerpts = %v %v", globs, err)
	}
	if _, err := resolveCodexExcerpts(work, []string{".env"}, nil); err == nil {
		t.Fatal("accepted secret excerpt path")
	}
}

func TestVerifyAgentPatchRoutesPatchToVerifyAndKeepsRepoClean(t *testing.T) {
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, "payments"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repo, "tests"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "payments", "processor.py"), []byte("def charge():\n    return 0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "tests", "test_accept.py"), []byte("assert True\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	edited := t.TempDir()
	if err := os.MkdirAll(filepath.Join(edited, "payments"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(edited, "tests"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(edited, "payments", "processor.py"), []byte("def charge():\n    return 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(edited, "tests", "test_accept.py"), []byte("assert True\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	art, err := patch.Build(repo, edited, patch.Meta{RunID: "ext_1", RepoPath: repo})
	if err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	srv := New(nil, config.Config{DataDir: dataDir, ImagePython: "agt-sandbox:python"}, "tok")
	srv.VerifyExec = func(_ context.Context, workdir, _ string, prof profile.Profile) (string, string, int, error) {
		body, err := os.ReadFile(filepath.Join(workdir, "payments", "processor.py"))
		if err != nil {
			return "", err.Error(), 1, nil
		}
		if strings.Contains(strings.Join(prof.Argv, " "), "test_regress") {
			return "Ran 1 test in 0.001s\nOK\n", "", 0, nil
		}
		if strings.Contains(string(body), "return 1") {
			return "Ran 1 test in 0.001s\nOK\n", "", 0, nil
		}
		return "AssertionError\nFAILED (failures=1)\n", "", 1, nil
	}

	reqBody, _ := json.Marshal(map[string]any{
		"repo_path": repo,
		"task_type": "feature",
		"profile":   map[string]any{"name": "python", "argv": []string{"python", "-m", "unittest"}},
		"contract": map[string]any{
			"version": "verify.v1",
			"checks": []map[string]any{
				{"name": "regress", "role": "regression", "argv": []string{"python", "-m", "unittest", "tests.test_regress"}, "paths": []string{"tests/test_regress.py"}},
				{"name": "accept", "role": "acceptance", "argv": []string{"python", "-m", "unittest", "tests.test_accept"}, "paths": []string{"tests/test_accept.py"}},
			},
		},
		"artifact": art,
	})
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/v1/agents/verify", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Passed  bool   `json:"passed"`
		Outcome string `json:"outcome"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Passed || resp.Outcome != "feature_implemented" {
		t.Fatalf("unexpected verify response: %s", rec.Body.String())
	}
	hostBody, err := os.ReadFile(filepath.Join(repo, "payments", "processor.py"))
	if err != nil || !strings.Contains(string(hostBody), "return 0") {
		t.Fatalf("host repo was mutated: %q %v", hostBody, err)
	}
}
