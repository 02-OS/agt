package telemetry

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestOTLPPostsTrace(t *testing.T) {
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/traces" {
			t.Errorf("path = %s", r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		body = string(raw)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	otlp := &OTLP{Endpoint: srv.URL, Client: srv.Client()}
	otlp.Emit(context.Background(), Event{
		TraceID: "0123456789abcdef0123456789abcdef",
		RunID:   "run_abc",
		Name:    "command.finished",
		Seq:     7,
	})
	if !strings.Contains(body, `"traceId":"0123456789abcdef0123456789abcdef"`) {
		t.Fatalf("body = %s", body)
	}
	if !strings.Contains(body, `"name":"command.finished"`) || !strings.Contains(body, "run_abc") {
		t.Fatalf("body = %s", body)
	}
}

func TestOTLPIncludesHeadersTimestampsAndNonZeroSpanID(t *testing.T) {
	var auth string
	var rawBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		rawBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	otlp := &OTLP{
		Endpoint:    srv.URL,
		Headers:     map[string]string{"Authorization": "Bearer secret-tok"},
		ServiceName: "agt-test",
		Client:      srv.Client(),
	}
	start := time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)
	end := start.Add(250 * time.Millisecond)
	otlp.Emit(context.Background(), Event{
		TraceID:   "0123456789abcdef0123456789abcdef",
		RunID:     "run_1",
		Name:      "verify",
		Seq:       3,
		StartTime: start,
		EndTime:   end,
		Status:    "error",
	})
	if auth != "Bearer secret-tok" {
		t.Fatalf("auth header = %q", auth)
	}
	var payload map[string]any
	if err := json.Unmarshal(rawBody, &payload); err != nil {
		t.Fatal(err)
	}
	text := string(rawBody)
	if strings.Contains(text, `"spanId":"0000000000000000"`) || !strings.Contains(text, `"agt-test"`) || !strings.Contains(text, `"code":2`) {
		t.Fatalf("unexpected OTLP payload: %s", text)
	}
}

func TestMetricsRenderPrometheusOutput(t *testing.T) {
	m := NewMetrics()
	m.RecordTransition("PLANNING", "EXECUTING")
	m.ObserveTool("read_file_range", 25*time.Millisecond)
	m.AddSandboxCleanups(3)
	m.AddCostMicros(450)

	out := m.Render(RunStats{
		Active:          2,
		ByState:         map[string]int64{"EXECUTING": 1, "SUCCEEDED": 4},
		TotalCostMicros: 900,
	})
	for _, want := range []string{
		"agt_runs_active 2",
		`agt_runs_by_state{state="EXECUTING"} 1`,
		`agt_state_transitions_total{from="PLANNING",to="EXECUTING"} 1`,
		`agt_tool_duration_seconds_count{tool="read_file_range"} 1`,
		"agt_sandbox_cleanups_total 3",
		"agt_token_cost_micros_total 900",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in metrics:\n%s", want, out)
		}
	}
	if nilOut := (*Metrics)(nil).Render(RunStats{Active: 1}); !strings.Contains(nilOut, "agt_runs_active 1") {
		t.Fatalf("nil receiver metrics failed: %s", nilOut)
	}
}
