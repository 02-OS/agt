package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/csy20/agt/internal/policy"
)

func TestClaudeVersionSupportedAcceptsNewerVersions(t *testing.T) {
	cases := []struct {
		ver  string
		want bool
	}{
		{"2.1.258", false},
		{"2.0.999", false},
		{"1.9.0", false},
		{"bad", false},
		{"2.1.259", true},
		{"2.1.292", true},
		{"2.2.0", true},
		{"2.9.1", true},
		{"3.0.0", true},
	}
	for _, tc := range cases {
		if got := claudeVersionSupported(tc.ver); got != tc.want {
			t.Fatalf("claudeVersionSupported(%q) = %v, want %v", tc.ver, got, tc.want)
		}
	}
}

func TestAppSessionCallDeletesPendingOnContextCancel(t *testing.T) {
	pr, pw := io.Pipe()
	defer pr.Close()
	defer pw.Close()

	// Drain requests written to stdin so write() does not block.
	go func() {
		_, _ = io.Copy(io.Discard, pr)
	}()

	sess := &appSession{
		stdin:    pw,
		done:     make(chan struct{}),
		finished: make(chan struct{}),
		next:     1,
		pending:  map[string]chan rpcMessage{},
		kinds:    map[string]string{},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	if _, err := sess.call(ctx, "initialize", map[string]any{}); err == nil {
		t.Fatal("expected cancelled call error")
	}
	sess.mu.Lock()
	pendingLen := len(sess.pending)
	kindsLen := len(sess.kinds)
	sess.mu.Unlock()
	if pendingLen != 0 || kindsLen != 0 {
		t.Fatalf("pending maps leaked after cancel: pending=%d kinds=%d", pendingLen, kindsLen)
	}
}

func TestNetworkProbeFallbacksWhenPythonMissing(t *testing.T) {
	runProbe := func(t *testing.T, connectOnCurl bool) (bool, error, []string) {
		t.Helper()
		reqR, reqW := io.Pipe()
		respR, respW := io.Pipe()
		defer reqR.Close()
		defer respW.Close()

		sess := &appSession{
			stdin:    reqW,
			done:     make(chan struct{}),
			finished: make(chan struct{}),
			next:     1,
			pending:  map[string]chan rpcMessage{},
			kinds:    map[string]string{},
		}
		go sess.readLoop(respR)

		var sawTools []string
		doneResponder := make(chan struct{})
		go func() {
			defer close(doneResponder)
			sc := bufio.NewScanner(reqR)
			for sc.Scan() {
				var msg struct {
					ID     json.RawMessage `json:"id"`
					Method string          `json:"method"`
					Params struct {
						Command []string `json:"command"`
					} `json:"params"`
				}
				if err := json.Unmarshal(sc.Bytes(), &msg); err != nil {
					return
				}
				if msg.Method != "command/exec" || len(msg.Params.Command) == 0 {
					continue
				}
				tool := msg.Params.Command[0]
				sawTools = append(sawTools, tool)
				var res map[string]any
				switch tool {
				case "python3":
					res = map[string]any{"exitCode": 127, "stdout": "", "stderr": "sh: python3: not found"}
				case "curl":
					if connectOnCurl {
						url := msg.Params.Command[len(msg.Params.Command)-1]
						r, gerr := http.Get(url)
						body := ""
						if gerr == nil {
							b, _ := io.ReadAll(r.Body)
							r.Body.Close()
							body = string(b)
						}
						res = map[string]any{"exitCode": 0, "stdout": body, "stderr": ""}
					} else {
						res = map[string]any{"exitCode": 7, "stdout": "", "stderr": "curl: (7) Failed to connect"}
					}
				default:
					res = map[string]any{"exitCode": 127, "stdout": "", "stderr": tool + ": not found"}
				}
				line, _ := json.Marshal(map[string]any{"id": msg.ID, "result": res})
				_, _ = fmt.Fprintf(respW, "%s\n", line)
			}
		}()

		netUp, err := sess.networkProbe(context.Background(), t.TempDir())
		_ = reqW.Close()
		_ = respW.Close()
		<-doneResponder
		return netUp, err, sawTools
	}

	netUp, err, tools := runProbe(t, false)
	if err != nil || netUp {
		t.Fatalf("expected clean offline fallback, got net=%v err=%v", netUp, err)
	}
	if len(tools) < 2 || tools[0] != "python3" || tools[1] != "curl" {
		t.Fatalf("expected python3 -> curl fallback sequence, got %v", tools)
	}

	netUp, err, _ = runProbe(t, true)
	if err != nil || !netUp {
		t.Fatalf("expected curl canary detection net=true, got net=%v err=%v", netUp, err)
	}
}

func TestNewStreamWithModeRespectsAskAndAgent(t *testing.T) {
	askStream, err := NewStream(ProtocolClaude)
	if err != nil {
		t.Fatal(err)
	}
	editFixture := `{"type":"assistant","message":{"content":[{"type":"tool_use","id":"toolu_edit","name":"Edit","input":{"file_path":"payments/processor.py","old_string":"a","new_string":"b"}}]}}
{"type":"result","subtype":"success","result":"ok"}
`
	if err := askStream.Push([]byte(editFixture)); err != nil {
		t.Fatal(err)
	}
	if err := askStream.Close(0, false); err != nil {
		t.Fatal(err)
	}
	if len(askStream.Transcript().Tools) != 1 || askStream.Transcript().Tools[0].Decision != string(policy.Deny) {
		t.Fatalf("ask stream allowed edit: %+v", askStream.Transcript().Tools)
	}

	agentStream, err := NewStreamWithMode(ProtocolClaude, "agent")
	if err != nil {
		t.Fatal(err)
	}
	if err := agentStream.Push([]byte(editFixture)); err != nil {
		t.Fatal(err)
	}
	if err := agentStream.Close(0, false); err != nil {
		t.Fatal(err)
	}
	if len(agentStream.Transcript().Tools) != 1 || agentStream.Transcript().Tools[0].Decision != string(policy.Allow) {
		t.Fatalf("agent stream did not mediate edit as allow: %+v", agentStream.Transcript().Tools)
	}
}
