// Package audit is an append-only JSONL log. A line is never rewritten.
// The file mode is 0600. Replay checks a hash chain so a changed line fails.
package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const genesis = "genesis"

// Event is one audit line. ArgsHash is the hash agt already computed.
// This package stores it and does not derive a new one.
type Event struct {
	Seq       int64  `json:"seq"`
	Prev      string `json:"prev"`
	Time      string `json:"time"`
	Kind      string `json:"kind"`
	RunID     string `json:"run_id,omitempty"`
	SandboxID string `json:"sandbox_id,omitempty"`
	State     string `json:"state,omitempty"`
	Tool      string `json:"tool,omitempty"`
	ArgsHash  string `json:"args_hash,omitempty"`
	Decision  string `json:"decision,omitempty"`
}

// Append adds one line. Seq and Prev are assigned here. An existing symlink,
// a non-regular file, or a mode other than owner-only is refused.
func Append(path string, event Event) error {
	if err := validate(event); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	prev, seq, err := chainHead(path)
	if err != nil {
		return err
	}
	event.Seq = seq
	event.Prev = prev
	if event.Time == "" {
		event.Time = time.Now().UTC().Format(time.RFC3339Nano)
	}
	line, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if bytes.Contains(line, []byte{'\n'}) {
		return fmt.Errorf("audit event contains a newline")
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(append(line, '\n'))
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	if cerr != nil {
		return cerr
	}
	return os.Chmod(path, 0o600)
}

// Replay reads the log and checks the hash chain. It does not write.
func Replay(path string) ([]Event, error) {
	if _, err := os.Lstat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if err := privateRegular(path); err != nil {
		return nil, err
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return replayBytes(body)
}

func chainHead(path string) (string, int64, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return genesis, 1, nil
		}
		return "", 0, err
	}
	if err := privateRegular(path); err != nil {
		return "", 0, err
	}
	if info.Size() == 0 {
		return genesis, 1, nil
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return "", 0, err
	}
	events, err := replayBytes(body)
	if err != nil {
		return "", 0, err
	}
	lines := rawLines(body)
	if len(lines) == 0 || len(lines) != len(events) {
		return "", 0, fmt.Errorf("audit log line count does not match")
	}
	return lineHash(lines[len(lines)-1]), int64(len(events) + 1), nil
}

func replayBytes(body []byte) ([]Event, error) {
	if len(body) == 0 {
		return nil, nil
	}
	if bytes.Contains(body, []byte{'\r'}) {
		return nil, fmt.Errorf("audit log contains a carriage return")
	}
	lines := rawLines(body)
	prev := genesis
	out := make([]Event, 0, len(lines))
	for i, line := range lines {
		dec := json.NewDecoder(strings.NewReader(line))
		dec.DisallowUnknownFields()
		var event Event
		if err := dec.Decode(&event); err != nil {
			return nil, fmt.Errorf("audit line %d: %w", i+1, err)
		}
		if dec.More() {
			return nil, fmt.Errorf("audit line %d is not one object", i+1)
		}
		if event.Seq != int64(i+1) {
			return nil, fmt.Errorf("audit sequence %d is not %d", event.Seq, i+1)
		}
		if event.Prev != prev {
			return nil, fmt.Errorf("audit chain broke at %d", event.Seq)
		}
		if err := validate(event); err != nil {
			return nil, err
		}
		out = append(out, event)
		prev = lineHash(line)
	}
	return out, nil
}

func rawLines(body []byte) []string {
	text := strings.TrimSuffix(string(body), "\n")
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

func lineHash(line string) string {
	sum := sha256.Sum256([]byte(line))
	return hex.EncodeToString(sum[:])
}

func validate(event Event) error {
	switch event.Kind {
	case "decision", "state":
	default:
		return fmt.Errorf("audit kind is invalid")
	}
	if event.ArgsHash == "" {
		return nil
	}
	if len(event.ArgsHash) != 64 {
		return fmt.Errorf("audit args_hash must be 64 hex characters")
	}
	for _, c := range event.ArgsHash {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return fmt.Errorf("audit args_hash must be 64 hex characters")
		}
	}
	return nil
}

func privateRegular(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("audit log is a symlink")
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("audit log is not a regular file")
	}
	// Windows reports a writable file as 0666. The Unix owner-only bit is not stored.
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("audit log is not private")
	}
	return nil
}
