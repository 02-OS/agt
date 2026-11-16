package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/csy20/agt/internal/patch"
	"github.com/csy20/agt/internal/run"
	"github.com/csy20/agt/internal/store"
	"github.com/csy20/agt/internal/tools"
	"github.com/csy20/agt/internal/workspace"
)

func (s *Server) diff(w http.ResponseWriter, r *http.Request) {
	current, art, work, base, ok := s.review(w, r)
	if !ok {
		return
	}
	text, err := tools.Diff(base, work)
	complete := true
	note := ""
	if err != nil {
		if strings.Contains(err.Error(), "exceeds") {
			complete = false
			note = err.Error() + "; export the patch artifact for the complete bytes"
			text = ""
		} else {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"run_id":     current.ID,
		"repo_path":  current.RepoPath,
		"diff":       text,
		"digest":     art.Digest,
		"complete":   complete,
		"note":       note,
		"strategy":   patch.Strategy,
		"revision":   art.Revision,
		"file_count": len(art.Files),
	})
}

func (s *Server) patchArtifact(w http.ResponseWriter, r *http.Request) {
	_, art, _, _, ok := s.review(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, art)
}

func (s *Server) apply(w http.ResponseWriter, r *http.Request) {
	current, err := s.Store.GetRun(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "run not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if current.State != run.Succeeded {
		writeError(w, http.StatusConflict, "apply requires SUCCEEDED")
		return
	}
	var req struct {
		Digest string `json:"digest"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if strings.TrimSpace(req.Digest) == "" {
		writeError(w, http.StatusBadRequest, "digest is required")
		return
	}
	art, _, _, err := s.artifact(current)
	if err != nil {
		writeReviewError(w, err)
		return
	}
	if req.Digest != art.Digest || art.RepoPath != current.RepoPath || art.RunID != current.ID {
		writeError(w, http.StatusConflict, "digest does not match the run artifact")
		return
	}
	if current.VerificationDigest != "" && current.VerificationDigest != art.Digest {
		writeError(w, http.StatusConflict, "verification digest does not match the run artifact")
		return
	}
	if s.Config.DataDir == "" {
		writeError(w, http.StatusInternalServerError, "data directory is not configured")
		return
	}
	lockPath := filepath.Join(s.Config.DataDir, "runs", current.ID, "apply.lock")
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		writeError(w, http.StatusConflict, "an apply for this run is already in progress or was interrupted; remove apply.lock after checking the rollback directory")
		return
	}
	rollback := filepath.Join(s.Config.DataDir, "runs", current.ID, "rollback", time.Now().UTC().Format("20060102T150405.000000000Z"))
	_, _ = lock.WriteString(rollback + "\n")
	_ = lock.Close()
	if err := patch.Apply(current.RepoPath, art, rollback); err != nil {
		releaseApplyLock(lockPath, err)
		writeReviewError(w, err)
		return
	}
	releaseApplyLock(lockPath, nil)
	_, _ = s.Store.AppendEvent(r.Context(), current.ID, "patch.applied", "user", "local", map[string]any{
		"digest":    art.Digest,
		"repo_path": current.RepoPath,
		"files":     len(art.Files),
		"rollback":  rollback,
	})
	_ = s.Store.RecordApplied(r.Context(), current, art.Digest)
	writeJSON(w, http.StatusOK, map[string]any{
		"applied":   len(art.Files),
		"digest":    art.Digest,
		"repo_path": current.RepoPath,
		"rollback":  rollback,
	})
}

func (s *Server) rollbacks(w http.ResponseWriter, r *http.Request) {
	current, err := s.Store.GetRun(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "run not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.Config.DataDir == "" {
		writeError(w, http.StatusInternalServerError, "data directory is not configured")
		return
	}
	if !safeRunDirName(current.ID) {
		writeError(w, http.StatusBadRequest, "invalid run id")
		return
	}
	items, err := listRunRollbacks(s.Config.DataDir, current.ID)
	if err != nil {
		writeReviewError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"run_id":    current.ID,
		"rollbacks": items,
	})
}

func (s *Server) rollback(w http.ResponseWriter, r *http.Request) {
	current, err := s.Store.GetRun(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "run not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if s.Config.DataDir == "" {
		writeError(w, http.StatusInternalServerError, "data directory is not configured")
		return
	}
	if !safeRunDirName(current.ID) {
		writeError(w, http.StatusBadRequest, "invalid run id")
		return
	}
	var req struct {
		RollbackID string `json:"rollback_id"`
	}
	if err := decodeOptional(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	rbDir, info, err := resolveRollbackTarget(s.Config.DataDir, current.ID, req.RollbackID)
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusNotFound, "rollback snapshot not found")
		return
	}
	if err != nil {
		writeReviewError(w, err)
		return
	}
	lockPath := filepath.Join(s.Config.DataDir, "runs", current.ID, "apply.lock")
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		writeError(w, http.StatusConflict, "an apply or rollback for this run is already in progress or was interrupted; remove apply.lock after checking the rollback directory")
		return
	}
	_, _ = lock.WriteString(rbDir + "\n")
	_ = lock.Close()
	if err := patch.Rollback(rbDir, current.RepoPath); err != nil {
		releaseApplyLock(lockPath, err)
		writeReviewError(w, err)
		return
	}
	releaseApplyLock(lockPath, nil)
	_, _ = s.Store.AppendEvent(r.Context(), current.ID, "patch.rolled_back", "user", "local", map[string]any{
		"rollback_id": info.ID,
		"digest":      info.Digest,
		"repo_path":   current.RepoPath,
		"files":       len(info.Files),
		"rollback":    rbDir,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"rolled_back": len(info.Files),
		"rollback_id": info.ID,
		"digest":      info.Digest,
		"repo_path":   current.RepoPath,
		"rollback":    rbDir,
	})
}

func (s *Server) gc(w http.ResponseWriter, r *http.Request) {
	if s.Config.DataDir == "" {
		writeError(w, http.StatusInternalServerError, "data directory is not configured")
		return
	}
	var req struct {
		MaxAge        string `json:"max_age"`
		MaxAgeSeconds *int64 `json:"max_age_seconds"`
		DryRun        bool   `json:"dry_run"`
	}
	if err := decodeOptional(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	maxAge := s.Config.RetentionTTL
	switch {
	case strings.TrimSpace(req.MaxAge) != "":
		parsed, err := time.ParseDuration(strings.TrimSpace(req.MaxAge))
		if err != nil || parsed < 0 {
			writeError(w, http.StatusBadRequest, "max_age must be a non-negative duration")
			return
		}
		maxAge = parsed
	case req.MaxAgeSeconds != nil:
		if *req.MaxAgeSeconds < 0 {
			writeError(w, http.StatusBadRequest, "max_age_seconds must be non-negative")
			return
		}
		maxAge = time.Duration(*req.MaxAgeSeconds) * time.Second
	case maxAge <= 0:
		writeError(w, http.StatusBadRequest, "max_age is required when AGT_RETENTION_TTL is unset")
		return
	}
	report, err := PruneExpiredRuns(r.Context(), s.Store, s.Config.DataDir, maxAge, req.DryRun)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, report)
}

// GCReport summarizes expired run artifact directories reclaimed or eligible for cleanup.
type GCReport struct {
	PrunedRunIDs []string `json:"pruned_run_ids"`
	Removed      int      `json:"removed"`
	Skipped      int      `json:"skipped"`
	BytesFreed   int64    `json:"bytes_freed"`
	DryRun       bool     `json:"dry_run"`
}

// PruneExpiredRuns removes terminal and orphaned run snapshot directories older than maxAge.
// Active or paused runs and runs holding apply.lock are never pruned.
func PruneExpiredRuns(ctx context.Context, st *store.Store, dataDir string, maxAge time.Duration, dryRun bool) (GCReport, error) {
	report := GCReport{PrunedRunIDs: []string{}, DryRun: dryRun}
	if strings.TrimSpace(dataDir) == "" || maxAge < 0 {
		return report, nil
	}
	runsDir := filepath.Join(dataDir, "runs")
	entries, err := os.ReadDir(runsDir)
	if errors.Is(err, os.ErrNotExist) {
		return report, nil
	}
	if err != nil {
		return report, err
	}
	now := time.Now()
	for _, entry := range entries {
		if ctx.Err() != nil {
			return report, ctx.Err()
		}
		name := entry.Name()
		if !entry.IsDir() || !safeRunDirName(name) {
			report.Skipped++
			continue
		}
		runDir := filepath.Join(runsDir, name)
		info, err := os.Lstat(runDir)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			report.Skipped++
			continue
		}
		if _, err := os.Lstat(filepath.Join(runDir, "apply.lock")); err == nil {
			report.Skipped++
			continue
		}
		refTime := info.ModTime()
		if st != nil {
			cur, err := st.GetRun(ctx, name)
			if err == nil {
				if !run.IsTerminal(cur.State) {
					report.Skipped++
					continue
				}
				if !cur.UpdatedAt.IsZero() {
					refTime = cur.UpdatedAt
				}
			} else if !errors.Is(err, store.ErrNotFound) {
				return report, err
			}
		}
		if now.Sub(refTime) < maxAge {
			report.Skipped++
			continue
		}
		size := dirBytes(runDir)
		if !dryRun {
			if err := os.RemoveAll(runDir); err != nil {
				return report, err
			}
		}
		report.PrunedRunIDs = append(report.PrunedRunIDs, name)
		report.Removed++
		report.BytesFreed += size
	}
	sort.Strings(report.PrunedRunIDs)
	return report, nil
}

func releaseApplyLock(lockPath string, err error) {
	if err != nil && strings.Contains(err.Error(), "rollback incomplete") {
		return
	}
	_ = os.Remove(lockPath)
}

func safeRunDirName(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, `/\`)
}

func listRunRollbacks(dataDir, runID string) ([]patch.RollbackInfo, error) {
	rbRoot := filepath.Join(dataDir, "runs", runID, "rollback")
	entries, err := os.ReadDir(rbRoot)
	if errors.Is(err, os.ErrNotExist) {
		return []patch.RollbackInfo{}, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() && safeRunDirName(entry.Name()) {
			names = append(names, entry.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	out := make([]patch.RollbackInfo, 0, len(names))
	for _, name := range names {
		info, err := patch.InspectRollback(filepath.Join(rbRoot, name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, info)
	}
	return out, nil
}

func resolveRollbackTarget(dataDir, runID, rollbackID string) (string, patch.RollbackInfo, error) {
	rbRoot := filepath.Join(dataDir, "runs", runID, "rollback")
	if strings.TrimSpace(rollbackID) != "" {
		rollbackID = strings.TrimSpace(rollbackID)
		if !safeRunDirName(rollbackID) {
			return "", patch.RollbackInfo{}, fmt.Errorf("%w: invalid rollback_id %q", patch.ErrEscape, rollbackID)
		}
		dir := filepath.Join(rbRoot, rollbackID)
		info, err := patch.InspectRollback(dir)
		if err != nil {
			return "", patch.RollbackInfo{}, err
		}
		return dir, info, nil
	}
	items, err := listRunRollbacks(dataDir, runID)
	if err != nil {
		return "", patch.RollbackInfo{}, err
	}
	if len(items) == 0 {
		return "", patch.RollbackInfo{}, os.ErrNotExist
	}
	for _, item := range items {
		if !item.RolledBack {
			return filepath.Join(rbRoot, item.ID), item, nil
		}
	}
	return filepath.Join(rbRoot, items[0].ID), items[0], nil
}

func dirBytes(root string) int64 {
	var total int64
	_ = filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.Type()&os.ModeSymlink != 0 || d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err == nil {
			total += info.Size()
		}
		return nil
	})
	return total
}

func (s *Server) review(w http.ResponseWriter, r *http.Request) (store.Run, patch.Artifact, string, string, bool) {
	current, err := s.Store.GetRun(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "run not found")
		return store.Run{}, patch.Artifact{}, "", "", false
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return store.Run{}, patch.Artifact{}, "", "", false
	}
	art, work, base, err := s.artifact(current)
	if err != nil {
		writeReviewError(w, err)
		return store.Run{}, patch.Artifact{}, "", "", false
	}
	return current, art, work, base, true
}

func (s *Server) artifact(current store.Run) (patch.Artifact, string, string, error) {
	work, base, err := s.snapshot(current)
	if err != nil {
		return patch.Artifact{}, "", "", err
	}
	captured := workspace.ReadCapture(current.RepoPath)
	art, err := patch.Build(base, work, patch.Meta{
		RunID:    current.ID,
		RepoPath: current.RepoPath,
		Revision: captured.Revision,
	})
	if err != nil {
		return patch.Artifact{}, "", "", err
	}
	return art, work, base, nil
}

func (s *Server) snapshot(current store.Run) (string, string, error) {
	if current.Worktree == "" {
		return "", "", errNoWorkspace
	}
	if s.Config.DataDir == "" {
		return "", "", fmt.Errorf("data directory is not configured")
	}
	if strings.Contains(current.ID, "/") || strings.Contains(current.ID, "\\") || current.ID == "" {
		return "", "", fmt.Errorf("run id is not a snapshot name")
	}
	want := filepath.Clean(filepath.Join(s.Config.DataDir, "runs", current.ID, "work"))
	got := filepath.Clean(current.Worktree)
	if want != got {
		return "", "", fmt.Errorf("worktree is not the run snapshot")
	}
	base := filepath.Join(filepath.Dir(got), "base")
	if _, err := os.Stat(got); err != nil {
		return "", "", fmt.Errorf("snapshot is not available")
	}
	if _, err := os.Stat(base); err != nil {
		return "", "", fmt.Errorf("snapshot is not available")
	}
	return got, base, nil
}

var errNoWorkspace = errors.New("workspace has not been captured")

func writeReviewError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errNoWorkspace):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, patch.ErrDigest), errors.Is(err, patch.ErrConflict):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, patch.ErrEscape):
		writeError(w, http.StatusBadRequest, err.Error())
	default:
		if strings.Contains(err.Error(), "restored") {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
	}
}
