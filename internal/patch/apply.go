package patch

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/csy20/agt/internal/tools"
)

var (
	// ErrDigest means the artifact does not match its digest or contract.
	ErrDigest = errors.New("patch digest does not match")
	// ErrConflict means a touched file no longer matches the snapshot.
	// Apply writes nothing when this is returned from the preflight.
	ErrConflict = errors.New("target does not match the snapshot")
	// ErrEscape means a path leaves the target repository.
	ErrEscape = errors.New("path escapes the repository")
)

// beforeMutate runs after the rollback record is durable and before each
// target write. Tests set it to stop an apply partway through.
var beforeMutate = func(string) error { return nil }

// Apply writes art into repo. It rejects a digest mismatch, a path escape,
// and any touched file whose current bytes or mode differ from the snapshot.
// Untouched files, including unrelated dirty files, are left alone.
// rollbackDir receives copies of the previous bytes and a manifest before
// the first target write. A failure after that point restores the files
// this function already changed.
func Apply(repo string, art Artifact, rollbackDir string) error {
	if err := art.check(); err != nil {
		return err
	}
	repoAbs, err := tools.CanonicalRepo(repo)
	if err != nil {
		return err
	}
	plan, err := preflight(repoAbs, art.Files)
	if err != nil {
		return err
	}
	if len(plan) == 0 {
		return nil
	}
	if err := writeRollback(rollbackDir, repoAbs, art.Digest, plan); err != nil {
		return err
	}
	var done []int
	var createdDirs []string
	for i := range plan {
		if err := beforeMutate(plan[i].full); err != nil {
			return restoreAfter(plan, done, createdDirs, err)
		}
		dirs, err := commitOne(repoAbs, &plan[i])
		createdDirs = append(createdDirs, dirs...)
		if err != nil {
			return restoreAfter(plan, done, createdDirs, err)
		}
		done = append(done, i)
	}
	return nil
}

func (a Artifact) check() error {
	if a.Contract != Contract || a.Strategy != Strategy {
		return fmt.Errorf("%w: contract %s", ErrDigest, a.Contract)
	}
	if Digest(a) != a.Digest || a.Digest == "" {
		return ErrDigest
	}
	seen := map[string]struct{}{}
	for _, f := range a.Files {
		if _, ok := seen[f.Path]; ok {
			return fmt.Errorf("%w: duplicate %s", ErrDigest, f.Path)
		}
		seen[f.Path] = struct{}{}
		if _, err := f.afterBytes(); err != nil {
			return fmt.Errorf("%w: %s", ErrDigest, err.Error())
		}
		switch f.Op {
		case OpAdd:
			if f.BeforeMode != "" || f.BeforeSHA256 != "" || f.AfterMode == "" || f.AfterSHA256 == "" {
				return fmt.Errorf("%w: add %s", ErrDigest, f.Path)
			}
		case OpDelete:
			if f.AfterMode != "" || f.AfterSHA256 != "" || f.ContentBase64 != "" || f.BeforeMode == "" || f.BeforeSHA256 == "" {
				return fmt.Errorf("%w: delete %s", ErrDigest, f.Path)
			}
		case OpModify:
			if f.BeforeMode == "" || f.AfterMode == "" || f.BeforeSHA256 == "" || f.AfterSHA256 == "" {
				return fmt.Errorf("%w: modify %s", ErrDigest, f.Path)
			}
		default:
			return fmt.Errorf("%w: op %s", ErrDigest, f.Op)
		}
	}
	return nil
}

func (f File) afterBytes() ([]byte, error) {
	if f.Op == OpDelete {
		if f.ContentBase64 != "" {
			return nil, fmt.Errorf("delete %s has content", f.Path)
		}
		return nil, nil
	}
	raw, err := base64.StdEncoding.DecodeString(f.ContentBase64)
	if err != nil {
		return nil, fmt.Errorf("content %s: %w", f.Path, err)
	}
	if hashBytes(raw) != f.AfterSHA256 {
		return nil, fmt.Errorf("content hash mismatch for %s", f.Path)
	}
	return raw, nil
}

type planned struct {
	file      File
	rel       string
	full      string
	after     []byte
	mode      os.FileMode
	existed   bool
	prior     []byte
	priorMode os.FileMode
}

func preflight(repo string, files []File) ([]planned, error) {
	plan := make([]planned, 0, len(files))
	for _, f := range files {
		rel, err := tools.SafeRel(f.Path)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrEscape, f.Path)
		}
		full, err := tools.Within(repo, f.Path)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrEscape, f.Path)
		}
		exists, mode, sum, body, err := readRegular(full)
		if err != nil {
			return nil, err
		}
		switch f.Op {
		case OpAdd:
			if exists {
				return nil, fmt.Errorf("%w: %s already exists", ErrConflict, f.Path)
			}
		case OpModify, OpDelete:
			if !exists || sum != f.BeforeSHA256 || mode != f.BeforeMode {
				return nil, fmt.Errorf("%w: %s", ErrConflict, f.Path)
			}
		default:
			return nil, fmt.Errorf("%w: op %s", ErrDigest, f.Op)
		}
		after, err := f.afterBytes()
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrDigest, err.Error())
		}
		var perm os.FileMode
		if f.Op != OpDelete {
			perm, err = parseMode(f.AfterMode)
			if err != nil {
				return nil, fmt.Errorf("%w: %s", ErrDigest, err.Error())
			}
		}
		item := planned{file: f, rel: rel, full: full, after: after, mode: perm, existed: exists}
		if exists {
			item.prior = append([]byte(nil), body...)
			parsed, err := parseMode(mode)
			if err != nil {
				return nil, err
			}
			item.priorMode = parsed
		}
		plan = append(plan, item)
	}
	return plan, nil
}

func readRegular(full string) (exists bool, mode, sum string, body []byte, err error) {
	st, err := os.Lstat(full)
	if os.IsNotExist(err) {
		return false, "", "", nil, nil
	}
	if err != nil {
		return false, "", "", nil, err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
		return false, "", "", nil, fmt.Errorf("%w: %s is not a regular file", ErrEscape, full)
	}
	body, err = os.ReadFile(full)
	if err != nil {
		return false, "", "", nil, err
	}
	return true, formatMode(st.Mode()), hashBytes(body), body, nil
}

func parseMode(s string) (os.FileMode, error) {
	if s == "" || strings.ContainsAny(s, " \t") {
		return 0, fmt.Errorf("mode %q", s)
	}
	n, err := strconv.ParseUint(s, 8, 32)
	if err != nil || n > 0o777 {
		return 0, fmt.Errorf("mode %q", s)
	}
	return os.FileMode(n), nil
}

type rollbackFile struct {
	Path        string `json:"path"`
	Op          string `json:"op"`
	Existed     bool   `json:"existed"`
	Mode        string `json:"mode,omitempty"`
	Blob        string `json:"blob,omitempty"`
	AfterMode   string `json:"after_mode,omitempty"`
	AfterSHA256 string `json:"after_sha256,omitempty"`
}

type rollbackManifest struct {
	Contract string         `json:"contract"`
	Repo     string         `json:"repo"`
	Digest   string         `json:"digest"`
	Files    []rollbackFile `json:"files"`
}

// RollbackInfo describes one saved rollback bundle under runs/<id>/rollback/<ts>.
type RollbackInfo struct {
	ID           string         `json:"id"`
	Contract     string         `json:"contract"`
	Repo         string         `json:"repo_path"`
	Digest       string         `json:"digest"`
	Files        []rollbackFile `json:"files"`
	RolledBack   bool           `json:"rolled_back"`
	RolledBackAt string         `json:"rolled_back_at,omitempty"`
}

func writeRollback(dir, repo, digest string, plan []planned) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	manifest := rollbackManifest{Contract: Contract, Repo: repo, Digest: digest}
	for i, item := range plan {
		rec := rollbackFile{
			Path:        item.file.Path,
			Op:          item.file.Op,
			Existed:     item.existed,
			AfterMode:   item.file.AfterMode,
			AfterSHA256: item.file.AfterSHA256,
		}
		if item.existed {
			name := fmt.Sprintf("blob-%04d", i)
			if err := os.WriteFile(filepath.Join(dir, name), item.prior, 0o600); err != nil {
				return err
			}
			rec.Mode = formatMode(item.priorMode)
			rec.Blob = name
		}
		manifest.Files = append(manifest.Files, rec)
	}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0o600)
}

// InspectRollback reads a rollback bundle's manifest and rolled-back state without modifying files.
func InspectRollback(rollbackDir string) (RollbackInfo, error) {
	st, err := os.Lstat(rollbackDir)
	if err != nil {
		return RollbackInfo{}, err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
		return RollbackInfo{}, fmt.Errorf("%w: rollback path is not a directory", ErrEscape)
	}
	exists, _, _, raw, err := readRegular(filepath.Join(rollbackDir, "manifest.json"))
	if err != nil {
		return RollbackInfo{}, err
	}
	if !exists {
		return RollbackInfo{}, os.ErrNotExist
	}
	var manifest rollbackManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return RollbackInfo{}, fmt.Errorf("%w: invalid rollback manifest: %v", ErrDigest, err)
	}
	if manifest.Contract != Contract {
		return RollbackInfo{}, fmt.Errorf("%w: rollback contract %s", ErrDigest, manifest.Contract)
	}
	info := RollbackInfo{
		ID:       filepath.Base(rollbackDir),
		Contract: manifest.Contract,
		Repo:     manifest.Repo,
		Digest:   manifest.Digest,
		Files:    manifest.Files,
	}
	rbPath := filepath.Join(rollbackDir, "rolled_back.json")
	if rbExists, _, _, rbRaw, rerr := readRegular(rbPath); rerr == nil && rbExists {
		var mark struct {
			RolledBackAt string `json:"rolled_back_at"`
		}
		if json.Unmarshal(rbRaw, &mark) == nil {
			info.RolledBack = true
			info.RolledBackAt = mark.RolledBackAt
		}
	}
	return info, nil
}

// Rollback restores pre-image files from rollbackDir into repo after checking
// that current repository contents still match the applied post-images.
func Rollback(rollbackDir, repo string) error {
	info, err := InspectRollback(rollbackDir)
	if err != nil {
		return err
	}
	if info.RolledBack {
		return fmt.Errorf("%w: rollback %s has already been applied", ErrConflict, info.ID)
	}
	repoAbs, err := tools.CanonicalRepo(repo)
	if err != nil {
		return err
	}
	if info.Repo != "" {
		manifestRepo, merr := tools.CanonicalRepo(info.Repo)
		if merr == nil && manifestRepo != repoAbs {
			return fmt.Errorf("%w: rollback target %s does not match manifest repo %s", ErrConflict, repoAbs, manifestRepo)
		}
	}
	type restorePlan struct {
		rec         rollbackFile
		full        string
		prior       []byte
		priorMode   os.FileMode
		current     []byte
		currentMode os.FileMode
		curExisted  bool
	}
	var plan []restorePlan
	for _, rf := range info.Files {
		if _, err := tools.SafeRel(rf.Path); err != nil {
			return fmt.Errorf("%w: %s", ErrEscape, rf.Path)
		}
		full, err := tools.Within(repoAbs, rf.Path)
		if err != nil {
			return fmt.Errorf("%w: %s", ErrEscape, rf.Path)
		}
		exists, mode, sum, body, err := readRegular(full)
		if err != nil {
			return err
		}
		switch rf.Op {
		case OpDelete:
			if exists {
				return fmt.Errorf("%w: %s was recreated after apply", ErrConflict, rf.Path)
			}
		case OpAdd, OpModify:
			if !exists {
				return fmt.Errorf("%w: %s is missing", ErrConflict, rf.Path)
			}
			if rf.AfterSHA256 != "" && sum != rf.AfterSHA256 {
				return fmt.Errorf("%w: %s changed since apply", ErrConflict, rf.Path)
			}
			if rf.AfterMode != "" && mode != rf.AfterMode {
				return fmt.Errorf("%w: %s mode changed since apply", ErrConflict, rf.Path)
			}
		default:
			return fmt.Errorf("%w: unknown rollback op %s", ErrDigest, rf.Op)
		}
		item := restorePlan{rec: rf, full: full, curExisted: exists}
		if exists {
			item.current = append([]byte(nil), body...)
			parsedCur, err := parseMode(mode)
			if err != nil {
				return err
			}
			item.currentMode = parsedCur
		}
		if rf.Existed {
			if rf.Blob == "" || strings.ContainsAny(rf.Blob, "/\\") || rf.Blob == "." || rf.Blob == ".." {
				return fmt.Errorf("%w: invalid blob name %q", ErrEscape, rf.Blob)
			}
			blobPath := filepath.Join(rollbackDir, rf.Blob)
			bExists, _, _, bBody, err := readRegular(blobPath)
			if err != nil {
				return err
			}
			if !bExists {
				return fmt.Errorf("%w: missing rollback blob %s", ErrDigest, rf.Blob)
			}
			pm, err := parseMode(rf.Mode)
			if err != nil {
				return fmt.Errorf("%w: %s", ErrDigest, err.Error())
			}
			item.prior = bBody
			item.priorMode = pm
		}
		plan = append(plan, item)
	}
	var done []int
	var createdDirs []string
	undo := func(cause error) error {
		var probs []string
		for i := len(done) - 1; i >= 0; i-- {
			it := plan[done[i]]
			if err := restoreOne(planned{
				full:      it.full,
				existed:   it.curExisted,
				prior:     it.current,
				priorMode: it.currentMode,
			}); err != nil {
				probs = append(probs, err.Error())
			}
		}
		for i := len(createdDirs) - 1; i >= 0; i-- {
			_ = os.Remove(createdDirs[i])
		}
		if len(probs) > 0 {
			return fmt.Errorf("rollback stopped: %v; recovery incomplete: %s", cause, strings.Join(probs, "; "))
		}
		return fmt.Errorf("rollback stopped: %v; restored %d file(s)", cause, len(done))
	}
	for i, it := range plan {
		if !it.rec.Existed {
			if err := os.Remove(it.full); err != nil && !os.IsNotExist(err) {
				return undo(err)
			}
			done = append(done, i)
			continue
		}
		dirs, err := ensureDirs(repoAbs, filepath.Dir(it.full))
		createdDirs = append(createdDirs, dirs...)
		if err != nil {
			return undo(err)
		}
		if err := restoreOne(planned{
			full:      it.full,
			existed:   true,
			prior:     it.prior,
			priorMode: it.priorMode,
		}); err != nil {
			return undo(err)
		}
		done = append(done, i)
	}
	mark, _ := json.Marshal(map[string]string{
		"rolled_back_at": time.Now().UTC().Format(time.RFC3339Nano),
		"repo":           repoAbs,
		"digest":         info.Digest,
	})
	_ = os.WriteFile(filepath.Join(rollbackDir, "rolled_back.json"), append(mark, '\n'), 0o600)
	return nil
}

func commitOne(repo string, item *planned) ([]string, error) {
	if item.file.Op == OpDelete {
		if err := os.Remove(item.full); err != nil {
			return nil, err
		}
		return nil, nil
	}
	parent := filepath.Dir(item.full)
	created, err := ensureDirs(repo, parent)
	if err != nil {
		return created, err
	}
	tmp, err := os.CreateTemp(parent, ".agt-apply-*")
	if err != nil {
		return created, err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(item.after); err != nil {
		tmp.Close()
		return created, err
	}
	if err := tmp.Chmod(item.mode); err != nil {
		tmp.Close()
		return created, err
	}
	if err := tmp.Close(); err != nil {
		return created, err
	}
	if err := os.Rename(tmpName, item.full); err != nil {
		return created, err
	}
	ok = true
	return created, nil
}

func ensureDirs(repo, dir string) ([]string, error) {
	rel, err := filepath.Rel(repo, dir)
	if err != nil {
		return nil, err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return nil, fmt.Errorf("%w: %s", ErrEscape, dir)
	}
	var created []string
	cur := repo
	if rel == "." {
		return nil, nil
	}
	for _, part := range strings.Split(rel, string(os.PathSeparator)) {
		if part == "" || part == "." {
			continue
		}
		cur = filepath.Join(cur, part)
		st, err := os.Lstat(cur)
		if os.IsNotExist(err) {
			if err := os.Mkdir(cur, 0o755); err != nil {
				return created, err
			}
			created = append(created, cur)
			continue
		}
		if err != nil {
			return created, err
		}
		if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
			return created, fmt.Errorf("%w: %s is not a directory", ErrEscape, cur)
		}
	}
	return created, nil
}

func restoreAfter(plan []planned, done []int, created []string, cause error) error {
	var problems []string
	for i := len(done) - 1; i >= 0; i-- {
		if err := restoreOne(plan[done[i]]); err != nil {
			problems = append(problems, err.Error())
		}
	}
	for i := len(created) - 1; i >= 0; i-- {
		_ = os.Remove(created[i])
	}
	if len(problems) > 0 {
		return fmt.Errorf("apply stopped: %v; rollback incomplete: %s", cause, strings.Join(problems, "; "))
	}
	return fmt.Errorf("apply stopped: %v; restored %d file(s)", cause, len(done))
}

func restoreOne(item planned) error {
	if !item.existed {
		if err := os.Remove(item.full); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	parent := filepath.Dir(item.full)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(parent, ".agt-rollback-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(item.prior); err != nil {
		tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(item.priorMode); err != nil {
		tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, item.full); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}
