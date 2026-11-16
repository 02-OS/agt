package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/csy20/agt/internal/audit"
	"github.com/csy20/agt/internal/version"
)

func TestIdleReaderSinglePumpAndTimeout(t *testing.T) {
	pr, pw := io.Pipe()
	r := newIdleReader(pr, 500*time.Millisecond)
	defer r.Close()

	go func() {
		defer pw.Close()
		_, _ = pw.Write([]byte("hello "))
		_, _ = pw.Write([]byte("world\n"))
	}()
	buf := make([]byte, 4)
	var out bytes.Buffer
	for {
		n, err := r.Read(buf)
		if n > 0 {
			out.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("unexpected read err: %v", err)
		}
	}
	if out.String() != "hello world\n" {
		t.Fatalf("got %q, want %q", out.String(), "hello world\n")
	}

	// Idle stream triggers errStreamIdle cleanly without hanging or panicking.
	pr2, pw2 := io.Pipe()
	defer pw2.Close()
	r2 := newIdleReader(pr2, 30*time.Millisecond)
	defer r2.Close()
	if _, err := r2.Read(buf); !errors.Is(err, errStreamIdle) {
		t.Fatalf("expected errStreamIdle, got %v", err)
	}
}

func TestAuditVerifyCommand(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	if err := audit.Append(path, audit.Event{Kind: "state", RunID: "run_a", State: "SUCCEEDED"}); err != nil {
		t.Fatal(err)
	}
	if code := Run([]string{"agt", "audit", "verify", "--file", path, "--json"}); code != 0 {
		t.Fatalf("expected exit 0 on valid audit log, got %d", code)
	}
	if code := Run([]string{"agt", "audit", "verify", "--file", filepath.Join(dir, "missing.jsonl")}); code != 1 {
		t.Fatalf("expected exit 1 on missing file, got %d", code)
	}
}

func TestRollbackAndGCCommands(t *testing.T) {
	t.Setenv("AGT_TOKEN", "test-token-1234567890")
	var lastMethod, lastPath, lastBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(version.ProductHeader, version.Name)
		w.Header().Set(version.VersionHeader, version.Product)
		w.Header().Set(version.ContractHeader, version.Contract)
		w.Header().Set(version.CapabilitiesHeader, version.CapabilityHeaderValue())
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "ok\n")
			return
		}
		body, _ := io.ReadAll(r.Body)
		lastMethod = r.Method
		lastPath = r.URL.Path
		lastBody = string(body)
		switch r.URL.Path {
		case "/v1/runs/run_1/rollbacks":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"run_id":    "run_1",
				"rollbacks": []map[string]any{{"id": "rb_1", "digest": "abc123", "files": []any{}}},
			})
		case "/v1/runs/run_1/rollback":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"rolled_back": 1,
				"rollback_id": "rb_1",
				"digest":      "abc123",
				"repo_path":   "/repo",
			})
		case "/v1/gc":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"pruned_run_ids": []string{"run_old"},
				"removed":        1,
				"skipped":        2,
				"bytes_freed":    4096,
				"dry_run":        true,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	if code := Run([]string{"agt", "rollback", "run_1", "--list", "--server", srv.URL}); code != 0 || lastMethod != http.MethodGet || lastPath != "/v1/runs/run_1/rollbacks" {
		t.Fatalf("rollback list: code=%d %s %s", code, lastMethod, lastPath)
	}
	if code := Run([]string{"agt", "run", "rollback", "run_1", "--id", "rb_1", "--server", srv.URL}); code != 0 || lastPath != "/v1/runs/run_1/rollback" || !strings.Contains(lastBody, `"rb_1"`) {
		t.Fatalf("rollback apply: code=%d %s %s", code, lastPath, lastBody)
	}
	if code := Run([]string{"agt", "gc", "--max-age", "24h", "--dry-run", "--server", srv.URL}); code != 0 || lastPath != "/v1/gc" || !strings.Contains(lastBody, `"dry_run":true`) {
		t.Fatalf("gc: code=%d %s %s", code, lastPath, lastBody)
	}
}
