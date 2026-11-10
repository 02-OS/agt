package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/csy20/agt/internal/tools"
)

// FileVersion is the only policy document this process accepts.
// The file is not a second authority. Decide remains the code decision,
// and a document may only move an allow toward require_approval or deny.
const FileVersion = "policy.file.v1"

// codeWriteCap is the largest payload Decide already accepts.
const codeWriteCap = 200_000

// File is a local JSON policy document.
type File struct {
	Version   string   `json:"version"`
	Rules     []Rule   `json:"rules,omitempty"`
	Limits    Limits   `json:"limits,omitempty"`
	Approvals []string `json:"approvals,omitempty"`
}

// Rule tightens one tool. Decision is deny or require_approval.
// PathPrefix, when set, matches that relative path or a file beneath it.
type Rule struct {
	Tool       string `json:"tool"`
	Decision   string `json:"decision"`
	PathPrefix string `json:"path_prefix,omitempty"`
}

// Limits can only shrink a run. Zero means the code value stays in force.
// MaxWriteBytes cannot exceed the 200KB cap Decide already enforces.
type Limits struct {
	MaxSteps      int `json:"max_steps,omitempty"`
	MaxWriteBytes int `json:"max_write_bytes,omitempty"`
}

// LoadFile reads a policy document from a regular file. A symlink is refused.
// The file is not fetched and no module is downloaded to parse it.
func LoadFile(path string) (File, error) {
	if strings.TrimSpace(path) == "" {
		return File{}, fmt.Errorf("policy file is required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return File{}, fmt.Errorf("policy file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return File{}, fmt.Errorf("policy file is a symlink")
	}
	if !info.Mode().IsRegular() {
		return File{}, fmt.Errorf("policy file must be a regular file")
	}
	if info.Size() > 64<<10 {
		return File{}, fmt.Errorf("policy file is too large")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return File{}, fmt.Errorf("policy file: %w", err)
	}
	return ParseFile(body)
}

// ParseFile validates a policy document. A rule that says allow is rejected
// here. Tighten also ignores an allow, so a constructed value cannot loosen.
func ParseFile(body []byte) (File, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return File{}, fmt.Errorf("policy file must be an object")
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	var file File
	if err := dec.Decode(&file); err != nil {
		return File{}, fmt.Errorf("policy file: %s", err.Error())
	}
	if dec.More() {
		return File{}, fmt.Errorf("policy file must be one object")
	}
	if file.Version != FileVersion {
		return File{}, fmt.Errorf("policy version must be %s", FileVersion)
	}
	if file.Limits.MaxSteps < 0 || file.Limits.MaxSteps > 10_000 {
		return File{}, fmt.Errorf("policy max_steps is invalid")
	}
	if file.Limits.MaxWriteBytes < 0 || file.Limits.MaxWriteBytes > codeWriteCap {
		return File{}, fmt.Errorf("policy max_write_bytes cannot exceed %d", codeWriteCap)
	}
	seen := map[string]bool{}
	for _, tool := range file.Approvals {
		if !token(tool) {
			return File{}, fmt.Errorf("policy approval tool is invalid")
		}
		if seen[tool] {
			return File{}, fmt.Errorf("duplicate approval %s", tool)
		}
		seen[tool] = true
	}
	for _, rule := range file.Rules {
		if !token(rule.Tool) {
			return File{}, fmt.Errorf("policy rule tool is invalid")
		}
		switch Decision(rule.Decision) {
		case Deny, RequireApproval:
		case Allow:
			return File{}, fmt.Errorf("a policy rule cannot allow a tool")
		default:
			return File{}, fmt.Errorf("policy rule decision must be deny or require_approval")
		}
		if rule.PathPrefix != "" {
			if _, err := tools.SafeRel(rule.PathPrefix); err != nil {
				return File{}, fmt.Errorf("policy path: %w", err)
			}
		}
	}
	return file, nil
}

// DecideWithFile runs Decide and then tightens it. A nil file is Decide.
func DecideWithFile(tool string, raw json.RawMessage, file *File) (Result, error) {
	result, err := Decide(tool, raw)
	if err != nil || file == nil {
		return result, err
	}
	return file.Tighten(result), nil
}

// DecideForFile runs DecideFor and then tightens it. Ask and plan denials stay.
func DecideForFile(interaction, tool string, raw json.RawMessage, file *File) (Result, error) {
	result, err := DecideFor(interaction, tool, raw)
	if err != nil || file == nil {
		return result, err
	}
	return file.Tighten(result), nil
}

// StepLimit returns the smaller positive ceiling. A file value above the
// code ceiling does not raise it. Zero in the file leaves the code value.
func (f File) StepLimit(codeMax int) int {
	if f.Limits.MaxSteps <= 0 {
		return codeMax
	}
	if codeMax <= 0 {
		if codeMax == 0 {
			return 0
		}
		return f.Limits.MaxSteps
	}
	if f.Limits.MaxSteps < codeMax {
		return f.Limits.MaxSteps
	}
	return codeMax
}

// Tighten moves an allow to require_approval or deny. A code denial is
// returned unchanged, including its args hash. The hash is not recomputed.
func (f File) Tighten(result Result) Result {
	if result.Decision == Deny {
		return result
	}
	decision := result.Decision
	reason := result.Reason
	if f.overWrite(result) {
		decision = Deny
		reason = "policy file write limit"
	}
	if decision != Deny {
		if next, why, ok := f.strictest(result); ok && stricter(next, decision) {
			decision = next
			reason = why
		}
	}
	if decision == result.Decision {
		return result
	}
	out := result
	out.Decision = decision
	out.Reason = reason
	return out
}

func (f File) overWrite(result Result) bool {
	limit := f.Limits.MaxWriteBytes
	if limit <= 0 {
		return false
	}
	return canonicalWriteBytes(result.Tool, result.Canonical) > limit
}

func (f File) strictest(result Result) (Decision, string, bool) {
	best := result.Decision
	reason := ""
	matched := false
	for _, rule := range f.Rules {
		next := Decision(rule.Decision)
		if next != Deny && next != RequireApproval {
			continue
		}
		if !rule.matches(result) {
			continue
		}
		if stricter(next, best) {
			best = next
			reason = "policy file tightened " + result.Tool
			matched = true
		}
	}
	if result.Decision == Allow {
		for _, tool := range f.Approvals {
			if tool != result.Tool {
				continue
			}
			if stricter(RequireApproval, best) {
				best = RequireApproval
				reason = "policy file requires approval"
				matched = true
			}
		}
	}
	return best, reason, matched
}

func (rule Rule) matches(result Result) bool {
	if rule.Tool != result.Tool {
		return false
	}
	if rule.PathPrefix == "" {
		return true
	}
	path := canonicalPath(result.Canonical)
	if path == rule.PathPrefix {
		return true
	}
	prefix := strings.TrimSuffix(rule.PathPrefix, "/")
	return prefix != "" && strings.HasPrefix(path, prefix+"/")
}

func stricter(next, current Decision) bool {
	return rank(next) > rank(current)
}

func rank(decision Decision) int {
	switch decision {
	case Deny:
		return 3
	case RequireApproval:
		return 2
	case Allow:
		return 1
	default:
		return 0
	}
}

func canonicalPath(raw []byte) string {
	var body map[string]json.RawMessage
	if err := json.Unmarshal(raw, &body); err != nil {
		return ""
	}
	var path string
	if err := json.Unmarshal(body["path"], &path); err != nil {
		return ""
	}
	return path
}

func canonicalWriteBytes(tool string, raw []byte) int {
	var body map[string]json.RawMessage
	if err := json.Unmarshal(raw, &body); err != nil {
		return 0
	}
	var field string
	switch tool {
	case "write_file":
		field = "content"
	case "apply_patch":
		field = "new"
	default:
		return 0
	}
	var text string
	if err := json.Unmarshal(body[field], &text); err != nil {
		return 0
	}
	return len(text)
}
