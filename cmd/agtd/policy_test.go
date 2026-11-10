package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInvalidPolicyFileStopsBeforePostgres(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(path, []byte(`{"version":"policy.file.v1","rules":[{"tool":"write_file","decision":"allow"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGT_LISTEN", "127.0.0.1:1")
	t.Setenv("AGT_POLICY_FILE", path)
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = old })
	code := run()
	_ = w.Close()
	os.Stderr = old
	out, _ := io.ReadAll(r)
	_ = r.Close()
	if code == 0 {
		t.Fatal("startup succeeded")
	}
	if !strings.Contains(string(out), "policy file") {
		t.Fatalf("exit %d log %s", code, out)
	}
}
