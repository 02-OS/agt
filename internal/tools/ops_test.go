package tools

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPatchIsIdempotentAndRefusesEscape(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "payments")
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(path, "processor.py")
	if err := os.WriteFile(file, []byte("alpha\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	msg, err := Patch(root, "payments/processor.py", "alpha\n", "beta\n")
	if err != nil || msg != "patched" {
		t.Fatalf("first patch: %s %v", msg, err)
	}
	msg, err = Patch(root, "payments/processor.py", "alpha\n", "beta\n")
	if err != nil || msg != "already applied" {
		t.Fatalf("second patch: %s %v", msg, err)
	}
	body, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "beta\n" {
		t.Fatalf("content = %q", body)
	}

	if _, err := Patch(root, "../outside.txt", "a", "b"); err == nil {
		t.Fatal("parent path was written")
	}
	outside := filepath.Join(filepath.Dir(root), "outside.txt")
	if _, err := os.Stat(outside); !os.IsNotExist(err) {
		t.Fatalf("outside file exists: %v", err)
	}
}

func TestSymlinkEscapeIsNotWritten(t *testing.T) {
	root := t.TempDir()
	outsideDir := t.TempDir()
	target := filepath.Join(outsideDir, "secret")
	if err := os.WriteFile(target, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "leak")); err != nil {
		t.Fatal(err)
	}
	_, err := Patch(root, "leak", "secret", "pwned")
	if err == nil {
		t.Fatal("symlink patch should fail")
	}
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "secret" {
		t.Fatalf("target changed to %q", body)
	}
}

func TestPatchPreservesExecutableBit(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "run.sh")
	if err := os.WriteFile(file, []byte("echo old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Patch(root, "run.sh", "echo old\n", "echo new\n"); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm()&0o111 == 0 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
}

func TestSearchFindsLiteral(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "payments"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "payments", "processor.py"), []byte("def charge():\n    pass\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := Search(root, "def charge")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(filepath.ToSlash(out), "payments/processor.py:1:") {
		t.Fatalf("search = %q", out)
	}
}

func TestPatchFalsePositiveAndSizeGuard(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "main.py")
	// Initial file already happens to contain new text "foo_bar" elsewhere,
	// and target "foo" also exists; Patch must NOT falsely return already_applied!
	if err := os.WriteFile(file, []byte("x = foo\ny = foo_bar\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Patch(root, "main.py", "x = foo", "x = foo_bar")
	if err != nil {
		t.Fatal(err)
	}
	if res != "patched" {
		t.Fatalf("expected patched, got %s", res)
	}
	// Repeating exact same patch immediately must return already_applied cleanly.
	res2, err := Patch(root, "main.py", "x = foo", "x = foo_bar")
	if err != nil {
		t.Fatal(err)
	}
	if res2 != "already applied" {
		t.Fatalf("expected already applied on idempotent retry, got %s", res2)
	}
	// Ambiguous file where new is substring of old: changing content outside Patch must NOT claim already_applied.
	other := filepath.Join(root, "other.py")
	if err := os.WriteFile(other, []byte("hello world"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Patch(root, "other.py", "hello world", "world"); err == nil {
		// Applied once cleanly.
		if _, err := Patch(root, "other.py", "missing", "world"); err == nil {
			t.Fatal("expected missing target to fail")
		}
	}

	// Oversized file guard.
	big := make([]byte, MaxWriteBytes+1)
	for i := range big {
		big[i] = 'a'
	}
	if err := os.WriteFile(filepath.Join(root, "big.txt"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Patch(root, "big.txt", "a", "b"); err == nil {
		t.Fatal("expected size limit error for Patch")
	}
}

func TestSearchSkipsBinaryOversizeAndFiltersPathGlob(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pkg", "a.go"), []byte("package pkg\n// target_match\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pkg", "b.txt"), []byte("target_match\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pkg", "bin.dat"), []byte("target_match\x00binary"), 0o644); err != nil {
		t.Fatal(err)
	}
	big := make([]byte, MaxWriteBytes+64)
	copy(big, []byte("target_match\n"))
	if err := os.WriteFile(filepath.Join(root, "pkg", "huge.go"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	longLine := strings.Repeat("z", 70*1024) + "target_match\n"
	if err := os.WriteFile(filepath.Join(root, "pkg", "long.go"), []byte(longLine), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := SearchFiltered(root, "target_match", "pkg", "*.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "pkg/a.go:2:") || !strings.Contains(out, "pkg/long.go:1:") {
		t.Fatalf("missing expected matches in %q", out)
	}
	if strings.Contains(out, "b.txt") || strings.Contains(out, "bin.dat") || strings.Contains(out, "huge.go") {
		t.Fatalf("unexpected match included in %q", out)
	}
}
