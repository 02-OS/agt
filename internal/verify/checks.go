package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// BaselineCheck reports whether a feature may start. Regression must have
// passed and acceptance must have failed for a real test reason. The function
// reads the supplied results only. It does not open a fixture or a process.
func BaselineCheck(checks []CheckResult) (bool, string) {
	decision := DecideBaseline(TaskFeature, checks)
	return decision.Proceed, decision.Summary
}

// AcceptanceCheck reports whether every acceptance result passed.
// An empty acceptance list does not pass. Infrastructure is not a pass.
func AcceptanceCheck(checks []CheckResult) (bool, string) {
	acceptance := byRole(checks, RoleAcceptance)
	if len(acceptance) == 0 {
		return false, "acceptance checks are empty"
	}
	if reason, ok := firstInfra(acceptance); ok {
		return false, "acceptance was not executed: " + reason
	}
	if allKind(acceptance, KindPass) {
		return true, "acceptance checks passed"
	}
	return false, "an acceptance check failed"
}

// PropertyCheck compares two blobs. It does not read the filesystem.
// byte_equal and sha256_equal hold only when the blobs match.
// line_count_equal holds when both sides have the same number of lines.
func PropertyCheck(name string, before, after []byte) (bool, error) {
	switch name {
	case "byte_equal":
		return bytes.Equal(before, after), nil
	case "sha256_equal":
		return sha256Hex(before) == sha256Hex(after), nil
	case "line_count_equal":
		return lineCount(before) == lineCount(after), nil
	default:
		return false, fmt.Errorf("unknown property %s", name)
	}
}

func sha256Hex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func lineCount(body []byte) int {
	if len(body) == 0 {
		return 0
	}
	n := bytes.Count(body, []byte{'\n'})
	if body[len(body)-1] != '\n' {
		n++
	}
	return n
}
