// Package evidence reads an Agent Runtime package. The package is accepted
// only when its digest matches the canonical body. An empty contract is
// rejected. An applied ask is rejected. When the body carries a tool call,
// args_hash is checked with policy.Decide and is not replaced.
package evidence

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/csy20/agt/internal/policy"
	"github.com/csy20/agt/internal/verify"
)

const (
	Kind    = "agent-runtime"
	Version = "evidence.v1"
)

// Body is the digested content. Contract is verify.v1 JSON.
type Body struct {
	Contract    json.RawMessage `json:"contract"`
	Interaction string          `json:"interaction"`
	Applied     bool            `json:"applied"`
	Tool        string          `json:"tool,omitempty"`
	Canonical   json.RawMessage `json:"canonical,omitempty"`
	ArgsHash    string          `json:"args_hash,omitempty"`
}

// Envelope is the on-disk package.
type Envelope struct {
	Kind    string `json:"kind"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
	Body    Body   `json:"body"`
}

// Seal writes a package whose digest is the sha256 of the normalized body.
func Seal(body Body) ([]byte, error) {
	norm, digest, err := normalize(body)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(Envelope{Kind: Kind, Version: Version, Digest: digest, Body: norm})
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// Open accepts a package only when the digest matches. It does not apply a
// patch and it does not start a run.
func Open(raw []byte) (Body, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return Body{}, fmt.Errorf("evidence package must be an object")
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	var env Envelope
	if err := dec.Decode(&env); err != nil {
		return Body{}, fmt.Errorf("evidence package: %s", err.Error())
	}
	if dec.More() {
		return Body{}, fmt.Errorf("evidence package must be one object")
	}
	if env.Kind != Kind {
		return Body{}, fmt.Errorf("evidence kind must be %s", Kind)
	}
	if env.Version != Version {
		return Body{}, fmt.Errorf("evidence version must be %s", Version)
	}
	norm, digest, err := normalize(env.Body)
	if err != nil {
		return Body{}, err
	}
	if !sameDigest(env.Digest, digest) {
		return Body{}, fmt.Errorf("evidence digest does not match")
	}
	return norm, nil
}

// ReadFile opens a regular file. A symlink is refused.
func ReadFile(path string) (Body, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Body{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return Body{}, fmt.Errorf("evidence package must be a regular file")
	}
	if info.Size() > 1<<20 {
		return Body{}, fmt.Errorf("evidence package is too large")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return Body{}, err
	}
	return Open(body)
}

func normalize(body Body) (Body, string, error) {
	if body.Applied && strings.TrimSpace(body.Interaction) == "ask" {
		return Body{}, "", fmt.Errorf("applied ask is rejected")
	}
	loaded, err := verify.Load(body.Contract)
	if err != nil {
		return Body{}, "", fmt.Errorf("empty contract")
	}
	contract, err := json.Marshal(loaded)
	if err != nil {
		return Body{}, "", err
	}
	body.Contract = contract
	body.Interaction = strings.TrimSpace(body.Interaction)
	if body.Tool != "" || len(bytes.TrimSpace(body.Canonical)) != 0 || body.ArgsHash != "" {
		if body.Tool == "" || len(bytes.TrimSpace(body.Canonical)) == 0 || body.ArgsHash == "" {
			return Body{}, "", fmt.Errorf("args_hash requires the tool and the canonical arguments")
		}
		decision, err := policy.Decide(body.Tool, body.Canonical)
		if err != nil {
			return Body{}, "", err
		}
		if decision.ArgsHash != body.ArgsHash {
			return Body{}, "", fmt.Errorf("args_hash does not match")
		}
		body.Canonical = append(json.RawMessage(nil), decision.Canonical...)
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return Body{}, "", err
	}
	sum := sha256.Sum256(raw)
	return body, hex.EncodeToString(sum[:]), nil
}

func sameDigest(got, want string) bool {
	if len(got) != 64 || len(want) != 64 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}
