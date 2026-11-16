package api

import (
	"bytes"
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

	"github.com/csy20/agt/internal/agent"
	"github.com/csy20/agt/internal/id"
	"github.com/csy20/agt/internal/tools"
	"github.com/csy20/agt/internal/workspace"
)

const (
	maxAutoExcerptFiles = 16
	maxAutoExcerptBytes = 64 << 10
)

func (s *Server) codexAsk(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RepoPath     string   `json:"repo_path"`
		Prompt       string   `json:"prompt"`
		Authorize    bool     `json:"authorize"`
		Excerpts     []string `json:"excerpts"`
		ExcerptGlobs []string `json:"excerpt_globs"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if !req.Authorize {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error":        "live Codex ask requires authorize. A saved login is not permission.",
			"label":        "blocked",
			"live":         false,
			"turn_started": false,
			"prompt_sent":  false,
		})
		return
	}
	if s.Store == nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	if err := s.Store.Ping(r.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	if s.Config.DataDir == "" {
		writeError(w, http.StatusBadRequest, "data dir is not set")
		return
	}
	repo, err := workspace.CanonicalRepo(req.RepoPath)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := workspace.Overlap(repo, s.Config.DataDir); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	runID := id.New("codex_")
	work, _, err := workspace.Materialize(repo, s.Config.DataDir, runID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	defer os.RemoveAll(filepath.Join(s.Config.DataDir, "runs", runID))
	excerpts, err := resolveCodexExcerpts(work, req.Excerpts, req.ExcerptGlobs)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	result, err := agent.Ask(r.Context(), agent.AskRequest{
		Command:   s.CodexCommand,
		WorkDir:   work,
		Prompt:    req.Prompt,
		Excerpts:  excerpts,
		Authorize: true,
	})
	status := http.StatusOK
	if err != nil {
		status = http.StatusConflict
		if errors.Is(err, agent.ErrLogin) {
			status = http.StatusPreconditionFailed
		}
		if errors.Is(err, agent.ErrLiveUnavailable) || errors.Is(err, agent.ErrMutationUnavailable) {
			status = http.StatusForbidden
		}
	}
	body := map[string]any{
		"label":        result.Label,
		"live":         result.Live,
		"turn_started": result.TurnStarted,
		"prompt_sent":  result.PromptSent,
		"result":       result,
	}
	if err != nil {
		body["error"] = err.Error()
	}
	writeJSON(w, status, body)
}

func resolveCodexExcerpts(work string, explicit, globs []string) ([]string, error) {
	if len(explicit) == 0 && len(globs) == 0 {
		return codexExcerpts(work), nil
	}
	seen := map[string]struct{}{}
	var out []string
	add := func(rel string) {
		if _, ok := seen[rel]; ok {
			return
		}
		seen[rel] = struct{}{}
		out = append(out, rel)
	}
	for _, raw := range explicit {
		rel, err := tools.SafeRel(raw)
		if err != nil {
			return nil, fmt.Errorf("excerpt %q: %w", raw, err)
		}
		rel = filepath.ToSlash(rel)
		if tools.SecretRel(rel) {
			return nil, fmt.Errorf("excerpt %q refers to a protected secret path", rel)
		}
		full, err := tools.Within(work, rel)
		if err != nil {
			return nil, fmt.Errorf("excerpt %q: %w", raw, err)
		}
		info, err := os.Lstat(full)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			continue
		}
		add(rel)
	}
	for _, pat := range globs {
		pat = strings.TrimSpace(pat)
		if pat == "" {
			continue
		}
		clean := filepath.ToSlash(filepath.Clean(pat))
		if strings.HasPrefix(clean, "/") || clean == ".." || strings.HasPrefix(clean, "../") {
			return nil, fmt.Errorf("excerpt glob %q escapes workspace", pat)
		}
		matched, err := discoverExcerpts(work, clean, 64, 256<<10)
		if err != nil {
			return nil, fmt.Errorf("excerpt glob %q: %w", pat, err)
		}
		for _, rel := range matched {
			add(rel)
		}
	}
	sort.Strings(out)
	return out, nil
}

func codexExcerpts(work string) []string {
	out, err := discoverExcerpts(work, "", maxAutoExcerptFiles, maxAutoExcerptBytes)
	if err != nil {
		return nil
	}
	return out
}

func discoverExcerpts(work, glob string, maxFiles int, maxTotalBytes int64) ([]string, error) {
	var candidates []string
	err := filepath.WalkDir(work, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(work, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if tools.SkipDir(d.Name()) || tools.SecretDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		slashRel := filepath.ToSlash(rel)
		if tools.SecretFile(d.Name()) || tools.SecretRel(slashRel) {
			return nil
		}
		if glob != "" && !matchExcerptGlob(glob, slashRel, d.Name()) {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > maxAutoExcerptBytes {
			return nil
		}
		if isBinarySample(path) {
			return nil
		}
		candidates = append(candidates, slashRel)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(candidates)
	var out []string
	var total int64
	for _, rel := range candidates {
		if len(out) >= maxFiles {
			break
		}
		info, err := os.Lstat(filepath.Join(work, filepath.FromSlash(rel)))
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if total+info.Size() > maxTotalBytes && len(out) > 0 {
			continue
		}
		total += info.Size()
		out = append(out, rel)
	}
	return out, nil
}

func matchExcerptGlob(glob, slashRel, base string) bool {
	if ok, err := filepath.Match(glob, slashRel); err == nil && ok {
		return true
	}
	if !strings.Contains(glob, "/") {
		if ok, err := filepath.Match(glob, base); err == nil && ok {
			return true
		}
	}
	return false
}

func isBinarySample(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return true
	}
	defer f.Close()
	var buf [512]byte
	n, err := f.Read(buf[:])
	if err != nil && err != io.EOF {
		return true
	}
	return bytes.IndexByte(buf[:n], 0) >= 0
}
