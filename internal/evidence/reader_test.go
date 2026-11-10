package evidence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/csy20/agt/internal/policy"
)

func contractJSON() json.RawMessage {
	return json.RawMessage(`{"version":"verify.v1","checks":[{"name":"regress","role":"regression","argv":["python3","-m","unittest","tests.test_regress"],"paths":["tests/test_regress.py"]}]}`)
}

func TestEvidenceAcceptsAMatchingDigest(t *testing.T) {
	decision, err := policy.Decide("read_file_range", json.RawMessage(`{"path":"greet.py","start":1,"end":20}`))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Seal(Body{
		Contract:    contractJSON(),
		Interaction: "agent",
		Tool:        "read_file_range",
		Canonical:   decision.Canonical,
		ArgsHash:    decision.ArgsHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Open(raw)
	if err != nil {
		t.Fatal(err)
	}
	if opened.ArgsHash != decision.ArgsHash || opened.Applied {
		t.Fatalf("%+v", opened)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	fromFile, err := ReadFile(path)
	if err != nil || fromFile.ArgsHash != decision.ArgsHash {
		t.Fatalf("%+v %v", fromFile, err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFile(link); err == nil {
		t.Fatal("symlink was accepted")
	}

	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	env.Digest = strings.Repeat("ab", 32)
	flipped, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(flipped); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("flipped digest: %v", err)
	}
	wrong := decision.ArgsHash
	wrong = "00" + wrong[2:]
	if _, err := Seal(Body{Contract: contractJSON(), Interaction: "agent", Tool: "read_file_range", Canonical: decision.Canonical, ArgsHash: wrong}); err == nil || !strings.Contains(err.Error(), "args_hash") {
		t.Fatalf("wrong hash: %v", err)
	}
}

func TestEvidenceRejectsAnEmptyContractAndAnAppliedAsk(t *testing.T) {
	if _, err := Seal(Body{Interaction: "agent"}); err == nil || !strings.Contains(err.Error(), "empty contract") {
		t.Fatalf("empty seal: %v", err)
	}
	if _, err := Open([]byte(`{"kind":"agent-runtime","version":"evidence.v1","digest":"` + strings.Repeat("ab", 32) + `","body":{"contract":{},"interaction":"agent","applied":false}}`)); err == nil || !strings.Contains(err.Error(), "empty contract") {
		t.Fatalf("empty open: %v", err)
	}
	applied := `{"kind":"agent-runtime","version":"evidence.v1","digest":"` + strings.Repeat("cd", 32) + `","body":{"contract":{"version":"verify.v1","checks":[{"name":"regress","role":"regression","argv":["python3"],"paths":["tests/test_regress.py"]}]},"interaction":"ask","applied":true}}`
	if _, err := Open([]byte(applied)); err == nil || !strings.Contains(err.Error(), "applied ask") {
		t.Fatalf("applied ask: %v", err)
	}
	if _, err := Seal(Body{Contract: contractJSON(), Interaction: "ask", Applied: true}); err == nil || !strings.Contains(err.Error(), "applied ask") {
		t.Fatalf("applied seal: %v", err)
	}
	raw, err := Seal(Body{Contract: contractJSON(), Interaction: "ask", Applied: false})
	if err != nil {
		t.Fatal(err)
	}
	opened, err := Open(raw)
	if err != nil || opened.Interaction != "ask" || opened.Applied {
		t.Fatalf("unapplied ask %+v %v", opened, err)
	}
}
