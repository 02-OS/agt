package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/csy20/agt/internal/agent"
	"github.com/csy20/agt/internal/id"
	"github.com/csy20/agt/internal/patch"
	"github.com/csy20/agt/internal/profile"
	"github.com/csy20/agt/internal/verify"
	"github.com/csy20/agt/internal/workspace"
)

func (s *Server) listAgents(w http.ResponseWriter, r *http.Request) {
	probe := s.AgentProbe
	if probe == nil {
		probe = agent.DefaultVersion
	}
	selected := s.selectedName()
	screen := agent.BuildScreen(s.catalog().Public(selected, s.getenv), agent.Probe(probe))
	writeJSON(w, http.StatusOK, screen)
}

func (s *Server) verifyAgentPatch(w http.ResponseWriter, r *http.Request) {
	if s.VerifyExec == nil {
		writeError(w, http.StatusNotImplemented, "sandbox verification is not configured")
		return
	}
	if s.Config.DataDir == "" {
		writeError(w, http.StatusBadRequest, "data dir is not set")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "unable to read request body")
		return
	}
	if imageField(body) {
		writeError(w, http.StatusBadRequest, "image is not accepted; the daemon selects the profile image")
		return
	}
	var req struct {
		RepoPath string          `json:"repo_path"`
		TaskType string          `json:"task_type"`
		Profile  json.RawMessage `json:"profile"`
		Contract json.RawMessage `json:"contract"`
		Artifact patch.Artifact  `json:"artifact"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
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
	if req.Artifact.Contract != patch.Contract || req.Artifact.Strategy != patch.Strategy || req.Artifact.Digest == "" || patch.Digest(req.Artifact) != req.Artifact.Digest {
		writeError(w, http.StatusBadRequest, "invalid patch.v1 artifact")
		return
	}
	if req.Artifact.RepoPath != "" {
		artRepo, err := workspace.CanonicalRepo(req.Artifact.RepoPath)
		if err != nil || artRepo != repo {
			writeError(w, http.StatusConflict, "artifact repo_path does not match repo_path")
			return
		}
	}
	profReq, err := decodeProfile(req.Profile)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	resolved, err := profile.Resolve(profReq, s.Config.ProfileImages(), runtime.GOARCH)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	task := verify.NormalizeTask(req.TaskType)
	if !verify.ValidTask(task) {
		writeError(w, http.StatusBadRequest, "task_type must be repair, feature, or refactor")
		return
	}
	contract, canonical, digest, err := verify.Parse(req.Contract, task, resolved.Name)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	verifyID := id.New("verify_")
	work, _, err := workspace.Materialize(repo, s.Config.DataDir, verifyID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	defer func() {
		if s.VerifyCleanup != nil {
			_ = s.VerifyCleanup(context.Background(), verifyID)
		}
		_ = os.RemoveAll(filepath.Join(s.Config.DataDir, "runs", verifyID))
	}()

	mutated := len(req.Artifact.Files) > 0
	var protected bool
	if verify.NeedsContract(task) {
		for _, f := range req.Artifact.Files {
			if contract.Protects(f.Path) {
				protected = true
			}
		}
	}

	var baseline []verify.CheckResult
	if verify.NeedsContract(task) {
		baseline, err = s.execContractChecks(r.Context(), work, verifyID, resolved, contract.Checks)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		baseDecision := verify.DecideBaseline(task, baseline)
		if !baseDecision.Proceed {
			writeJSON(w, http.StatusOK, map[string]any{
				"passed":            false,
				"outcome":           baseDecision.Outcome,
				"summary":           baseDecision.Summary,
				"digest":            req.Artifact.Digest,
				"task_type":         task,
				"contract_digest":   digest,
				"baseline":          baseline,
				"checks":            []verify.CheckResult{},
				"protected_changed": protected,
				"mutated":           mutated,
			})
			return
		}
	}

	if len(req.Artifact.Files) > 0 {
		rbDir := filepath.Join(s.Config.DataDir, "runs", verifyID, "rollback")
		if err := patch.Apply(work, req.Artifact, rbDir); err != nil {
			if errors.Is(err, patch.ErrConflict) || errors.Is(err, patch.ErrDigest) {
				writeError(w, http.StatusConflict, err.Error())
				return
			}
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	if verify.NeedsContract(task) {
		var finalChecks []verify.CheckResult
		if !protected {
			finalChecks, err = s.execContractChecks(r.Context(), work, verifyID, resolved, contract.Checks)
			if err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
		}
		decision := verify.DecideFinal(task, finalChecks, protected, mutated)
		writeJSON(w, http.StatusOK, map[string]any{
			"passed":            decision.Pass,
			"outcome":           decision.Outcome,
			"summary":           decision.Summary,
			"digest":            req.Artifact.Digest,
			"task_type":         task,
			"contract_digest":   digest,
			"contract":          jsonObject(canonical),
			"baseline":          baseline,
			"checks":            finalChecks,
			"protected_changed": protected,
			"mutated":           mutated,
		})
		return
	}

	checks := contract.Checks
	if len(checks) == 0 {
		checks = []verify.Check{{Name: "repair", Role: verify.RoleRegression, Argv: append([]string(nil), resolved.Argv...)}}
	}
	results, err := s.execContractChecks(r.Context(), work, verifyID, resolved, checks)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	passed := true
	outcome := verify.OutcomeChecksPassed
	summary := "repair check passed"
	for _, res := range results {
		if res.Kind != verify.KindPass {
			passed = false
			if res.Kind == verify.KindInfrastructure {
				outcome = verify.OutcomeVerificationInfra
			} else {
				outcome = verify.OutcomeChecksFailed
			}
			summary = res.Reason
			break
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"passed":    passed,
		"outcome":   outcome,
		"summary":   summary,
		"digest":    req.Artifact.Digest,
		"task_type": task,
		"checks":    results,
		"mutated":   mutated,
	})
}

func (s *Server) execContractChecks(ctx context.Context, work, verifyID string, prof profile.Profile, checks []verify.Check) ([]verify.CheckResult, error) {
	results := make([]verify.CheckResult, 0, len(checks))
	for _, check := range checks {
		clone := prof
		clone.Argv = append([]string(nil), check.Argv...)
		stdout, stderr, code, runErr := s.VerifyExec(ctx, work, verifyID, clone)
		output := stdout
		if stderr != "" {
			if output != "" && !strings.HasSuffix(output, "\n") {
				output += "\n"
			}
			output += stderr
		}
		if runErr != nil && strings.TrimSpace(output) == "" {
			output = runErr.Error()
		}
		kind, reason := verify.Classify(code, output, runErr)
		results = append(results, verify.CheckResult{
			Name:   check.Name,
			Role:   check.Role,
			Exit:   code,
			Kind:   kind,
			Reason: reason,
			Output: verify.ClipOutput(output, 2000),
		})
	}
	return results, nil
}
