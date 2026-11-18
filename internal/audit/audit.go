// Package audit is an append-only JSONL log. A line is never rewritten.
// The file mode is 0600. Replay checks a hash chain so a changed line fails.
package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
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

type tailState struct {
	seq  int64
	hash string
	size int64
}

var (
	locksMu sync.Mutex
	locks   = map[string]*sync.Mutex{}

	tailMu    sync.Mutex
	tailCache = map[string]tailState{}
)

func pathKey(path string) string {
	clean := filepath.Clean(path)
	if abs, err := filepath.Abs(clean); err == nil {
		return abs
	}
	return clean
}

func pathMutex(key string) *sync.Mutex {
	locksMu.Lock()
	defer locksMu.Unlock()
	mu, ok := locks[key]
	if !ok {
		mu = &sync.Mutex{}
		locks[key] = mu
	}
	return mu
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
	key := pathKey(path)
	mu := pathMutex(key)
	mu.Lock()
	defer mu.Unlock()

	f, err := openPrivateNoFollow(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	unlock, err := lockAuditFile(f)
	if err != nil {
		return err
	}
	defer unlock()

	info, err := f.Stat()
	if err != nil {
		return err
	}
	if err := checkPrivateInfo(info); err != nil {
		return err
	}

	size := info.Size()
	prev, seq, err := tailHead(f, key, size)
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

	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	payload := append(line, '\n')
	n, werr := f.Write(payload)
	if werr != nil {
		return werr
	}
	if n != len(payload) {
		return io.ErrShortWrite
	}
	if err := f.Chmod(0o600); err != nil {
		return err
	}

	tailMu.Lock()
	tailCache[key] = tailState{
		seq:  event.Seq,
		hash: lineHash(string(line)),
		size: size + int64(len(payload)),
	}
	tailMu.Unlock()
	return nil
}

// Replay reads the log and checks the hash chain. It does not write.
func Replay(path string) ([]Event, error) {
	f, err := openPrivateNoFollow(path, os.O_RDONLY, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if err := checkPrivateInfo(info); err != nil {
		return nil, err
	}
	body, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	return replayBytes(body)
}

func tailHead(f *os.File, key string, size int64) (string, int64, error) {
	if size == 0 {
		return genesis, 1, nil
	}
	tailMu.Lock()
	cached, ok := tailCache[key]
	tailMu.Unlock()
	if ok && cached.size == size {
		return cached.hash, cached.seq + 1, nil
	}
	lastLine, offset, err := readLastLine(f, size)
	if err != nil {
		return "", 0, err
	}
	event, err := parseEventLine(lastLine)
	if err != nil {
		return "", 0, fmt.Errorf("audit tail: %w", err)
	}
	if event.Seq < 1 {
		return "", 0, fmt.Errorf("audit sequence %d is invalid", event.Seq)
	}
	if offset == 0 && (event.Seq != 1 || event.Prev != genesis) {
		return "", 0, fmt.Errorf("audit chain broke at %d", event.Seq)
	}
	h := lineHash(lastLine)
	tailMu.Lock()
	tailCache[key] = tailState{seq: event.Seq, hash: h, size: size}
	tailMu.Unlock()
	return h, event.Seq + 1, nil
}

func readLastLine(f *os.File, size int64) (string, int64, error) {
	if size <= 0 {
		return "", 0, fmt.Errorf("audit log is empty")
	}
	var tailByte [1]byte
	if _, err := f.ReadAt(tailByte[:], size-1); err != nil {
		return "", 0, err
	}
	if tailByte[0] != '\n' {
		return "", 0, fmt.Errorf("audit log is truncated without trailing newline")
	}
	const chunkSize = 4096
	end := size - 1
	pos := end
	var chunks [][]byte
	for pos > 0 {
		readLen := int64(chunkSize)
		if pos < readLen {
			readLen = pos
		}
		start := pos - readLen
		buf := make([]byte, readLen)
		n, err := f.ReadAt(buf, start)
		if err != nil && err != io.EOF {
			return "", 0, err
		}
		buf = buf[:n]
		if bytes.Contains(buf, []byte{'\r'}) {
			return "", 0, fmt.Errorf("audit log contains a carriage return")
		}
		if idx := bytes.LastIndexByte(buf, '\n'); idx >= 0 {
			lineStart := start + int64(idx) + 1
			var out bytes.Buffer
			out.Write(buf[idx+1:])
			for i := len(chunks) - 1; i >= 0; i-- {
				out.Write(chunks[i])
			}
			if out.Len() == 0 {
				return "", lineStart, fmt.Errorf("audit log contains an empty line")
			}
			return out.String(), lineStart, nil
		}
		chunks = append(chunks, buf)
		pos = start
	}
	var out bytes.Buffer
	for i := len(chunks) - 1; i >= 0; i-- {
		out.Write(chunks[i])
	}
	if out.Len() == 0 {
		return "", 0, fmt.Errorf("audit log contains an empty line")
	}
	return out.String(), 0, nil
}

func parseEventLine(line string) (Event, error) {
	dec := json.NewDecoder(strings.NewReader(line))
	dec.DisallowUnknownFields()
	var event Event
	if err := dec.Decode(&event); err != nil {
		return Event{}, err
	}
	if dec.More() {
		return Event{}, fmt.Errorf("not one JSON object")
	}
	if err := validate(event); err != nil {
		return Event{}, err
	}
	return event, nil
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
		event, err := parseEventLine(line)
		if err != nil {
			return nil, fmt.Errorf("audit line %d: %w", i+1, err)
		}
		if event.Seq != int64(i+1) {
			return nil, fmt.Errorf("audit sequence mismatch at line %d: got seq %d, want %d", i+1, event.Seq, i+1)
		}
		if event.Prev != prev {
			return nil, fmt.Errorf("audit chain broke at seq %d (line %d): got prev %s, want %s", event.Seq, i+1, event.Prev, prev)
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

func checkPrivateInfo(info os.FileInfo) error {
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
