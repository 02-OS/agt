package workspace

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestMaterializeKeepsConfigModesAndSkipsDependencies(t *testing.T) {
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, ".github", "workflows"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, ".github", "workflows", "ci.yml"), []byte("name: ci\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, ".gitignore"), []byte("bin/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(src, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, ".git", "config"), []byte("secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(src, "node_modules", "leftpad"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "node_modules", "leftpad", "index.js"), []byte("module.exports=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(src, "build", "out"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "build", "out", "app"), []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(src, "script.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(script, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("script.sh", filepath.Join(src, "link.sh")); err == nil {
		// Symlinks are refused. Put the link last so the assertion is the error.
	}

	work, _, err := Materialize(src, t.TempDir(), "run_copy")
	if err == nil {
		t.Fatal("symlink was copied")
	}
	_ = work
}

func TestMaterializeSkipsSecretFiles(t *testing.T) {
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, ".ssh", "id_rsa"), []byte("PRIVATE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, ".env"), []byte("TOKEN=hidden\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, ".env.example"), []byte("TOKEN=example\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(src, ".github"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, ".github", "workflows.yml"), []byte("name: ci\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	work, _, err := Materialize(src, t.TempDir(), "run_secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(work, ".env")); !os.IsNotExist(err) {
		t.Fatalf(".env copied: %v", err)
	}
	if _, err := os.Stat(filepath.Join(work, ".ssh", "id_rsa")); !os.IsNotExist(err) {
		t.Fatalf("key copied: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(work, ".env.example"))
	if err != nil || string(body) != "TOKEN=example\n" {
		t.Fatalf("example %q %v", body, err)
	}
	if _, err := os.Stat(filepath.Join(work, ".github", "workflows.yml")); err != nil {
		t.Fatal(err)
	}
}

func TestMaterializeRejectsOversizedFile(t *testing.T) {
	src := t.TempDir()
	f, err := os.Create(filepath.Join(src, "big.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(MaxCopyFileBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, _, err := Materialize(src, t.TempDir(), "run_big"); err == nil || !strings.Contains(err.Error(), "copy limit") {
		t.Fatalf("err %v", err)
	}
}

func TestMaterializeCopiesDotfilesAndExecutableBits(t *testing.T) {
	src := t.TempDir()
	if err := os.MkdirAll(filepath.Join(src, ".github", "workflows"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, ".github", "workflows", "ci.yml"), []byte("name: ci\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, ".gitignore"), []byte("bin/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(src, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, ".git", "config"), []byte("[core]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(src, "node_modules", "leftpad"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "node_modules", "leftpad", "index.js"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(src, "cmd", "tool"), 0o755); err != nil {
		t.Fatal(err)
	}
	tool := filepath.Join(src, "cmd", "tool", "run.sh")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tool, 0o755); err != nil {
		t.Fatal(err)
	}

	work, base, err := Materialize(src, t.TempDir(), "run_copy")
	if err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{work, base} {
		if _, err := os.Stat(filepath.Join(root, ".github", "workflows", "ci.yml")); err != nil {
			t.Fatalf("config missing in %s: %v", root, err)
		}
		if _, err := os.Stat(filepath.Join(root, ".gitignore")); err != nil {
			t.Fatalf("dotfile missing in %s: %v", root, err)
		}
		if _, err := os.Stat(filepath.Join(root, ".git", "config")); !os.IsNotExist(err) {
			t.Fatalf(".git copied into %s: %v", root, err)
		}
		if _, err := os.Stat(filepath.Join(root, "node_modules", "leftpad", "index.js")); !os.IsNotExist(err) {
			t.Fatalf("node_modules copied into %s: %v", root, err)
		}
		st, err := os.Stat(filepath.Join(root, "cmd", "tool", "run.sh"))
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" && st.Mode().Perm()&0o111 == 0 {
			t.Fatalf("executable bit cleared in %s: %o", root, st.Mode().Perm())
		}
	}
}

func TestMaterializeGitWorktreeWithDirtyOverlayAndExclusions(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	src := t.TempDir()
	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", src}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	runGit("init")
	runGit("config", "user.name", "Test")
	runGit("config", "user.email", "test@example.com")
	if err := os.WriteFile(filepath.Join(src, "app.py"), []byte("v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "to_delete.py"), []byte("bye\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit("add", "app.py", "to_delete.py")
	runGit("commit", "-m", "init")

	// Dirty changes + untracked file + excluded dirs/secrets.
	if err := os.WriteFile(filepath.Join(src, "app.py"), []byte("v2_dirty\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(src, "to_delete.py")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "untracked.py"), []byte("new\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, ".env"), []byte("SECRET=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(src, ".02agent"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, ".02agent", "state.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	work, base, err := MaterializeWithBackend(src, t.TempDir(), "run_wt", BackendGitWorktree)
	if err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{work, base} {
		body, err := os.ReadFile(filepath.Join(root, "app.py"))
		if err != nil || string(body) != "v2_dirty\n" {
			t.Fatalf("%s app.py = %q %v", root, body, err)
		}
		if body, err := os.ReadFile(filepath.Join(root, "untracked.py")); err != nil || string(body) != "new\n" {
			t.Fatalf("%s untracked.py = %q %v", root, body, err)
		}
		if _, err := os.Stat(filepath.Join(root, "to_delete.py")); !os.IsNotExist(err) {
			t.Fatalf("%s deleted file still present", root)
		}
		if _, err := os.Stat(filepath.Join(root, ".env")); !os.IsNotExist(err) {
			t.Fatalf("%s .env copied", root)
		}
		if _, err := os.Stat(filepath.Join(root, ".02agent")); !os.IsNotExist(err) {
			t.Fatalf("%s .02agent copied", root)
		}
		if _, err := os.Stat(filepath.Join(root, ".git")); !os.IsNotExist(err) {
			t.Fatalf("%s .git present", root)
		}
	}
}
