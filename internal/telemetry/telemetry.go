package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// Event is one exported span. The database event log remains the audit source.
type Event struct {
	TraceID   string
	RunID     string
	Name      string
	Seq       int64
	StartTime time.Time
	EndTime   time.Time
	Status    string
	Attrs     map[string]string
}

type Emitter interface {
	Emit(context.Context, Event)
}

type Discard struct{}

func (Discard) Emit(context.Context, Event) {}

type Log struct{}

func (Log) Emit(_ context.Context, ev Event) {
	slog.Info("span", "trace_id", ev.TraceID, "run_id", ev.RunID, "name", ev.Name, "seq", ev.Seq)
}

type Multi []Emitter

func (m Multi) Emit(ctx context.Context, ev Event) {
	for _, e := range m {
		e.Emit(ctx, ev)
	}
}

// OTLP posts a minimal OTLP/HTTP JSON span. Export failure does not fail the run.
type OTLP struct {
	Endpoint    string
	Headers     map[string]string
	ServiceName string
	Client      *http.Client
}

// New builds a telemetry Emitter using endpoint (or standard OTLP env vars when empty).
func New(endpoint string) Emitter {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		endpoint = strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"))
	}
	if endpoint == "" {
		endpoint = strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	}
	if endpoint == "" {
		return Log{}
	}
	svc := strings.TrimSpace(os.Getenv("OTEL_SERVICE_NAME"))
	if svc == "" {
		svc = "agtd"
	}
	return Multi{Log{}, &OTLP{
		Endpoint:    endpoint,
		Headers:     parseHeaders(os.Getenv("OTEL_EXPORTER_OTLP_HEADERS")),
		ServiceName: svc,
		Client:      &http.Client{Timeout: 2 * time.Second},
	}}
}

func parseHeaders(raw string) map[string]string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	out := map[string]string{}
	for _, part := range strings.Split(raw, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k != "" {
			out[k] = v
		}
	}
	return out
}

func (o *OTLP) Emit(ctx context.Context, ev Event) {
	if o == nil || o.Endpoint == "" || ev.TraceID == "" {
		return
	}
	body := o.payload(ev)
	endpoint := strings.TrimRight(o.Endpoint, "/")
	if !strings.HasSuffix(endpoint, "/v1/traces") {
		endpoint += "/v1/traces"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range o.Headers {
		req.Header.Set(k, v)
	}
	client := o.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		slog.Debug("otlp export failed", "err", err)
		return
	}
	resp.Body.Close()
}

func (o *OTLP) payload(ev Event) []byte {
	attrs := []map[string]any{
		{"key": "run_id", "value": map[string]any{"stringValue": ev.RunID}},
		{"key": "event_name", "value": map[string]any{"stringValue": ev.Name}},
	}
	for key, value := range ev.Attrs {
		attrs = append(attrs, map[string]any{
			"key":   key,
			"value": map[string]any{"stringValue": value},
		})
	}
	end := ev.EndTime
	if end.IsZero() {
		end = time.Now().UTC()
	}
	start := ev.StartTime
	if start.IsZero() {
		start = end
	}
	seq := ev.Seq
	if seq <= 0 {
		seq = 1
	}
	spanID := fmt.Sprintf("%016x", uint64(seq))
	svc := o.ServiceName
	if svc == "" {
		svc = "agtd"
	}
	span := map[string]any{
		"traceId":           ev.TraceID,
		"spanId":            spanID,
		"name":              ev.Name,
		"kind":              1,
		"startTimeUnixNano": strconv.FormatInt(start.UnixNano(), 10),
		"endTimeUnixNano":   strconv.FormatInt(end.UnixNano(), 10),
		"attributes":        attrs,
	}
	if ev.Status == "error" {
		span["status"] = map[string]any{"code": 2}
	} else if ev.Status == "ok" {
		span["status"] = map[string]any{"code": 1}
	}
	doc := map[string]any{
		"resourceSpans": []any{map[string]any{
			"resource": map[string]any{
				"attributes": []any{
					map[string]any{"key": "service.name", "value": map[string]any{"stringValue": svc}},
				},
			},
			"scopeSpans": []any{map[string]any{
				"scope": map[string]any{"name": "agt"},
				"spans": []any{span},
			}},
		}},
	}
	body, _ := json.Marshal(doc)
	return body
}
