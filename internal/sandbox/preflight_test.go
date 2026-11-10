package sandbox

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/csy20/agt/internal/profile"
)

func TestPreflightReportsMissingImage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	err := (&Runner{Images: profile.Images{Python: "agt-sandbox:does-not-exist"}}).Preflight(ctx)
	if err == nil {
		t.Fatal("expected an error")
	}
	msg := err.Error()
	if _, lookErr := exec.LookPath("docker"); lookErr != nil {
		if !strings.Contains(msg, "docker") || !strings.Contains(msg, "does not fall back") {
			t.Fatal(msg)
		}
		return
	}
	// A Windows runner can have the docker client on PATH while the engine
	// pipe is down. That refusal is the preflight result. It does not inspect
	// an image and it does not run on the host.
	if strings.Contains(msg, "daemon is not reachable") {
		if strings.Contains(msg, "host python") {
			t.Fatal(msg)
		}
		return
	}
	if !strings.Contains(msg, "agt-sandbox:does-not-exist") || !strings.Contains(msg, "make image") {
		t.Fatal(msg)
	}
	if strings.Contains(msg, "host python") {
		t.Fatal(msg)
	}
}
