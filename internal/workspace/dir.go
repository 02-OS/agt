package workspace

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/csy20/agt/internal/patch"
	"github.com/csy20/agt/internal/tools"
)

// TestFunc runs the fixed repository test command. Production points it at a
// sandbox; tests may point it at a local interpreter.
type TestFunc func(ctx context.Context, root string) (stdout, stderr string, code int, err error)

// CheckFunc runs one contract argv with the same runner as TestFunc.
// The argv is already validated. This is not a shell.
type CheckFunc func(ctx context.Context, root string, argv []string) (stdout, stderr string, code int, err error)

// Handle is the workspace the orchestrator is allowed to touch.
type Handle interface {
	Search(ctx context.Context, query string) (string, int, error)
	Read(ctx context.Context, path string, start, end int) (string, int, error)
	Diff(ctx context.Context) (string, int, error)
	Patch(ctx context.Context, path, old, new string) (string, int, error)
	Write(ctx context.Context, args tools.WriteArgs) (string, int, error)
	Delete(ctx context.Context, args tools.DeleteArgs) (string, int, error)
	Test(ctx context.Context) (string, int, error)
	Check(ctx context.Context, argv []string) (string, int, error)
	Artifact(meta patch.Meta) (patch.Artifact, error)
	Calls() []string
	Close(ctx context.Context) error
}

// Dir performs file tools on a copied worktree. Test execution is injected so
// model-requested process execution is not the control-plane shell.
type Dir struct {
	Work    string
	Base    string
	TestFn  TestFunc
	CheckFn CheckFunc
	CloseFn func(context.Context) error

	mu    sync.Mutex
	calls []string
}

func NewDir(work, base string, testFn TestFunc) *Dir {
	return &Dir{Work: work, Base: base, TestFn: testFn}
}

func (d *Dir) note(tool string) {
	d.mu.Lock()
	d.calls = append(d.calls, tool)
	d.mu.Unlock()
}

func (d *Dir) Calls() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]string, len(d.calls))
	copy(out, d.calls)
	return out
}

// ScopedSearcher is optionally implemented by workspaces that support path/glob filtering.
type ScopedSearcher interface {
	SearchFiltered(ctx context.Context, query, path, glob string) (string, int, error)
}

func (d *Dir) Search(_ context.Context, query string) (string, int, error) {
	d.note("search_code")
	out, err := tools.Search(d.Work, query)
	if err != nil {
		return err.Error(), 2, nil
	}
	return out, 0, nil
}

func (d *Dir) SearchFiltered(_ context.Context, query, path, glob string) (string, int, error) {
	d.note("search_code")
	out, err := tools.SearchFiltered(d.Work, query, path, glob)
	if err != nil {
		return err.Error(), 2, nil
	}
	return out, 0, nil
}

func (d *Dir) Read(_ context.Context, path string, start, end int) (string, int, error) {
	d.note("read_file_range")
	out, err := tools.ReadRange(d.Work, path, start, end)
	if err != nil {
		return err.Error(), 2, nil
	}
	return out, 0, nil
}

func (d *Dir) Diff(context.Context) (string, int, error) {
	d.note("git_diff")
	out, err := tools.Diff(d.Base, d.Work)
	if err != nil {
		return "", 2, err
	}
	return out, 0, nil
}

func (d *Dir) Patch(_ context.Context, path, old, new string) (string, int, error) {
	d.note("apply_patch")
	out, err := tools.Patch(d.Work, path, old, new)
	if err != nil {
		return err.Error(), 2, nil
	}
	return out, 0, nil
}

func (d *Dir) Write(_ context.Context, args tools.WriteArgs) (string, int, error) {
	d.note("write_file")
	out, err := tools.WriteFile(d.Work, args)
	if err != nil {
		if out == "" {
			out = err.Error()
		}
		return out, 2, nil
	}
	return out, 0, nil
}

func (d *Dir) Delete(_ context.Context, args tools.DeleteArgs) (string, int, error) {
	d.note("delete_file")
	out, err := tools.DeleteFile(d.Work, args)
	if err != nil {
		if out == "" {
			out = err.Error()
		}
		return out, 2, nil
	}
	return out, 0, nil
}

func (d *Dir) Test(ctx context.Context) (string, int, error) {
	d.note("run_test")
	if d.TestFn == nil {
		return "", 0, fmt.Errorf("no test runner configured")
	}
	stdout, stderr, code, err := d.TestFn(ctx, d.Work)
	if err != nil {
		return "", code, err
	}
	return joinOutput(stdout, stderr), code, nil
}

func (d *Dir) Check(ctx context.Context, argv []string) (string, int, error) {
	d.note("check")
	if d.CheckFn == nil {
		return "", 0, fmt.Errorf("no check runner configured")
	}
	if len(argv) == 0 {
		return "", 0, fmt.Errorf("check argv is empty")
	}
	stdout, stderr, code, err := d.CheckFn(ctx, d.Work, argv)
	if err != nil {
		return "", code, err
	}
	return joinOutput(stdout, stderr), code, nil
}

func (d *Dir) Artifact(meta patch.Meta) (patch.Artifact, error) {
	return patch.Build(d.Base, d.Work, meta)
}

func joinOutput(stdout, stderr string) string {
	out := strings.TrimSpace(stdout + "\n" + stderr)
	if out == "" {
		out = "(no output)"
	}
	return out
}

func (d *Dir) Close(ctx context.Context) error {
	if d.CloseFn != nil {
		return d.CloseFn(ctx)
	}
	return nil
}

// MaxCopyFileBytes is the largest regular file Materialize will copy.
// Larger files fail the copy instead of being dropped silently.
const MaxCopyFileBytes = 8 << 20

const (
	BackendCopy        = "copy"
	BackendGitWorktree = "git-worktree"
)

// Materialize copies the working tree, including uncommitted files, into
// dataDir/runs/<id>/{work,base}. It copies repo into base once and clones/reflinks
// base into work. When AGT_WORKSPACE_BACKEND=git-worktree is set on a Git
// repository, it uses a detached git worktree plus dirty-overlay snapshot.
// The source tree is not modified. .git and .02agent are not copied. Symlinks
// are refused. Executable bits are preserved.
func Materialize(repo, dataDir, runID string) (work, base string, err error) {
	backend := strings.TrimSpace(os.Getenv("AGT_WORKSPACE_BACKEND"))
	return MaterializeWithBackend(repo, dataDir, runID, backend)
}

// MaterializeWithBackend materializes a run workspace using the named backend
// ("copy" / "" or "git-worktree").
func MaterializeWithBackend(repo, dataDir, runID, backend string) (work, base string, err error) {
	if err := Overlap(repo, dataDir); err != nil {
		return "", "", err
	}
	root := filepath.Join(dataDir, "runs", runID)
	if err := os.RemoveAll(root); err != nil {
		return "", "", err
	}
	work = filepath.Join(root, "work")
	base = filepath.Join(root, "base")
	switch strings.ToLower(strings.TrimSpace(backend)) {
	case BackendGitWorktree:
		ok, err := materializeGitWorktree(repo, base)
		if err != nil {
			return "", "", err
		}
		if !ok {
			if err := copyTree(repo, base); err != nil {
				return "", "", err
			}
		}
	case "", BackendCopy, "reflink", "auto":
		if err := copyTree(repo, base); err != nil {
			return "", "", err
		}
	default:
		return "", "", fmt.Errorf("unknown workspace backend %q", backend)
	}
	if err := cloneTree(base, work); err != nil {
		return "", "", err
	}
	return work, base, nil
}

func cloneTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return fmt.Errorf("clone escapes source")
		}
		target := filepath.Join(dst, rel)
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to clone symlink %s", rel)
		}
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		return cloneFile(path, target, info.Mode())
	})
}

func cloneFile(src, dst string, mode os.FileMode) error {
	if tryReflink(src, dst, mode) {
		return nil
	}
	return copyFile(src, dst, mode)
}

func materializeGitWorktree(repo, base string) (bool, error) {
	if _, ok := gitDir(repo); !ok {
		return false, nil
	}
	if _, err := exec.LookPath("git"); err != nil {
		return false, nil
	}
	// Check HEAD exists before adding worktree; empty repos fall back to copyTree.
	headCheck := exec.Command("git", "-C", repo, "rev-parse", "--verify", "HEAD")
	if err := headCheck.Run(); err != nil {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(base), 0o755); err != nil {
		return false, err
	}
	addCmd := exec.Command("git", "-C", repo, "worktree", "add", "--detach", "--force", base, "HEAD")
	if out, err := addCmd.CombinedOutput(); err != nil {
		_ = os.RemoveAll(base)
		_ = exec.Command("git", "-C", repo, "worktree", "prune").Run()
		return false, fmt.Errorf("git worktree add: %w: %s", err, bytes.TrimSpace(out))
	}
	defer func() {
		_ = os.RemoveAll(filepath.Join(base, ".git"))
		_ = exec.Command("git", "-C", repo, "worktree", "prune").Run()
	}()
	_ = os.RemoveAll(filepath.Join(base, ".git"))

	if err := scrubTree(base); err != nil {
		return false, err
	}
	if err := overlayDirtyGit(repo, base); err != nil {
		return false, err
	}
	return true, nil
}

func scrubTree(root string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to copy symlink %s", rel)
		}
		if d.IsDir() {
			if tools.SkipDir(d.Name()) || tools.SecretDir(d.Name()) {
				if rerr := os.RemoveAll(path); rerr != nil {
					return rerr
				}
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || tools.SecretFile(d.Name()) {
			return os.Remove(path)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Size() > MaxCopyFileBytes {
			return fmt.Errorf("file %s is %d bytes, over the %d byte copy limit", rel, info.Size(), MaxCopyFileBytes)
		}
		return nil
	})
}

func overlayDirtyGit(repo, base string) error {
	statusCmd := exec.Command("git", "-C", repo, "status", "--porcelain", "-z", "-uall", "--no-renames")
	out, err := statusCmd.Output()
	if err != nil {
		return fmt.Errorf("git status: %w", err)
	}
	for _, rec := range bytes.Split(out, []byte{0}) {
		if len(rec) < 4 {
			continue
		}
		x, y := rec[0], rec[1]
		relSlash := string(rec[3:])
		safe, err := tools.SafeRel(relSlash)
		if err != nil {
			continue
		}
		if skipRelPath(filepath.ToSlash(safe)) {
			continue
		}
		src := filepath.Join(repo, safe)
		dst := filepath.Join(base, safe)
		if x == 'D' || y == 'D' {
			if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
				return err
			}
			continue
		}
		info, err := os.Lstat(src)
		if err != nil {
			if os.IsNotExist(err) {
				_ = os.Remove(dst)
				continue
			}
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to copy symlink %s", safe)
		}
		if info.IsDir() {
			if err := copyTree(src, dst); err != nil {
				return err
			}
			continue
		}
		if !info.Mode().IsRegular() || tools.SecretFile(info.Name()) {
			continue
		}
		if info.Size() > MaxCopyFileBytes {
			return fmt.Errorf("file %s is %d bytes, over the %d byte copy limit", safe, info.Size(), MaxCopyFileBytes)
		}
		if err := copyFile(src, dst, info.Mode()); err != nil {
			return err
		}
	}
	return nil
}

func skipRelPath(slash string) bool {
	for _, part := range strings.Split(slash, "/") {
		if part == "" || part == "." {
			continue
		}
		if tools.SkipDir(part) || tools.SecretDir(part) {
			return true
		}
	}
	return false
}

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return fmt.Errorf("copy escapes source")
		}
		target := filepath.Join(dst, rel)
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to copy symlink %s", rel)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			if rel != "." && (tools.SkipDir(d.Name()) || tools.SecretDir(d.Name())) {
				return filepath.SkipDir
			}
			return os.MkdirAll(target, 0o755)
		}
		if !d.Type().IsRegular() || tools.SecretFile(d.Name()) {
			return nil
		}
		if info.Size() > MaxCopyFileBytes {
			return fmt.Errorf("file %s is %d bytes, over the %d byte copy limit", rel, info.Size(), MaxCopyFileBytes)
		}
		return copyFile(path, target, info.Mode())
	})
}

func copyFile(src, dst string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	perm := mode.Perm()
	if perm == 0 {
		perm = 0o644
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return os.Chmod(dst, perm)
}
