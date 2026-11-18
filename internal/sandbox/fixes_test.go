package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/csy20/agt/internal/profile"
)

func TestParseRunLabelsSupportsDockerStringAndJSON(t *testing.T) {
	if id, ok := ParseRunLabels(`"agt-run=run_str,com.example=v"`); !ok || id != "run_str" {
		t.Fatalf("json string labels: id=%q ok=%v", id, ok)
	}
	if id, ok := ParseRunLabels(`agt-run=run_raw,other=y`); !ok || id != "run_raw" {
		t.Fatalf("raw labels: id=%q ok=%v", id, ok)
	}
	if _, ok := ParseRunLabels(`other=y`); ok {
		t.Fatal("accepted raw labels without agt-run")
	}
	if _, ok := ParseRunLabels(`not-json`); ok {
		t.Fatal("accepted non-label text")
	}
}

func TestDockerHelperProcess(t *testing.T) {
	if os.Getenv("AGT_TEST_DOCKER_HELPER") != "1" {
		return
	}
	args := os.Args
	idx := -1
	for i, a := range args {
		if a == "--" {
			idx = i + 1
			break
		}
	}
	if idx < 0 || idx >= len(args) {
		os.Exit(2)
	}
	dargs := args[idx:]
	if logPath := os.Getenv("AGT_TEST_DOCKER_LOG"); logPath != "" {
		f, _ := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if f != nil {
			_, _ = f.WriteString(strings.Join(dargs, " ") + "\n")
			_ = f.Close()
		}
	}
	switch dargs[0] {
	case "info":
		os.Exit(0)
	case "image":
		os.Exit(0)
	case "inspect":
		format := ""
		for i := 1; i < len(dargs)-1; i++ {
			if dargs[i] == "--format" {
				format = dargs[i+1]
			}
		}
		if os.Getenv("AGT_TEST_INSPECT_MISSING") == "1" {
			os.Exit(1)
		}
		switch format {
		case "{{.State.Status}}":
			_, _ = os.Stdout.WriteString("running\n")
		case "{{json .Config.Labels}}":
			_, _ = os.Stdout.WriteString(os.Getenv("AGT_TEST_INSPECT_LABELS") + "\n")
		case "{{.Config.Image}}":
			_, _ = os.Stdout.WriteString(os.Getenv("AGT_TEST_INSPECT_IMAGE") + "\n")
		case "{{json .Mounts}}":
			_, _ = os.Stdout.WriteString(os.Getenv("AGT_TEST_INSPECT_MOUNTS") + "\n")
		}
		os.Exit(0)
	case "rm":
		os.Exit(0)
	case "exec":
		if os.Getenv("AGT_TEST_EXEC_SLEEP") == "1" {
			time.Sleep(10 * time.Second)
		}
		os.Exit(0)
	default:
		os.Exit(0)
	}
}

func withStubDocker(t *testing.T, extraEnv map[string]string) string {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "docker.log")
	prev := dockerCommand
	dockerCommand = func(ctx context.Context, args ...string) *exec.Cmd {
		cmdArgs := append([]string{"-test.run=^TestDockerHelperProcess$", "--"}, args...)
		cmd := exec.CommandContext(ctx, os.Args[0], cmdArgs...)
		cmd.Env = append(os.Environ(),
			"AGT_TEST_DOCKER_HELPER=1",
			"AGT_TEST_DOCKER_LOG="+logPath,
		)
		for k, v := range extraEnv {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
		return cmd
	}
	t.Cleanup(func() { dockerCommand = prev })
	return logPath
}

func TestEnsureValidatesLabelsImageAndWorkspaceMount(t *testing.T) {
	work := t.TempDir()
	wrongWork := t.TempDir()
	images := profile.Images{Python: "agt-sandbox:python"}
	runner := &Runner{Images: images, Namespace: "ns_test"}
	spec := ExecSpec{
		Image:   "agt-sandbox:python",
		Argv:    []string{"python", "-m", "unittest"},
		Env:     profile.EnvFor(profile.NamePython),
		Workdir: "/workspace",
		Memory:  "256m",
		CPUs:    "1",
		PIDs:    64,
	}

	// Wrong labels rejected.
	labelsWrong, _ := json.Marshal(map[string]string{"agt-namespace": "ns_other", "agt-run": "run_1"})
	mountsGood, _ := json.Marshal([]map[string]string{{"Type": "bind", "Source": work, "Destination": "/workspace"}})
	withStubDocker(t, map[string]string{
		"AGT_TEST_INSPECT_LABELS": string(labelsWrong),
		"AGT_TEST_INSPECT_IMAGE":  "agt-sandbox:python",
		"AGT_TEST_INSPECT_MOUNTS": string(mountsGood),
	})
	if err := runner.ensure(context.Background(), work, "run_1", spec); err == nil || !strings.Contains(err.Error(), "namespace") {
		t.Fatalf("expected namespace rejection, got %v", err)
	}

	// Wrong image rejected.
	labelsGood, _ := json.Marshal(map[string]string{"agt-namespace": runner.namespace(), "agt-run": "run_1"})
	withStubDocker(t, map[string]string{
		"AGT_TEST_INSPECT_LABELS": string(labelsGood),
		"AGT_TEST_INSPECT_IMAGE":  "python:latest",
		"AGT_TEST_INSPECT_MOUNTS": string(mountsGood),
	})
	if err := runner.ensure(context.Background(), work, "run_1", spec); err == nil || !strings.Contains(err.Error(), "image") {
		t.Fatalf("expected image rejection, got %v", err)
	}

	// Wrong workspace mount rejected.
	mountsWrong, _ := json.Marshal([]map[string]string{{"Type": "bind", "Source": wrongWork, "Destination": "/workspace"}})
	withStubDocker(t, map[string]string{
		"AGT_TEST_INSPECT_LABELS": string(labelsGood),
		"AGT_TEST_INSPECT_IMAGE":  "agt-sandbox:python",
		"AGT_TEST_INSPECT_MOUNTS": string(mountsWrong),
	})
	if err := runner.ensure(context.Background(), work, "run_1", spec); err == nil || !strings.Contains(err.Error(), "/workspace mount") {
		t.Fatalf("expected mount rejection, got %v", err)
	}

	// Matching labels, image, and mount accepted.
	withStubDocker(t, map[string]string{
		"AGT_TEST_INSPECT_LABELS": string(labelsGood),
		"AGT_TEST_INSPECT_IMAGE":  "agt-sandbox:python",
		"AGT_TEST_INSPECT_MOUNTS": string(mountsGood),
	})
	if err := runner.ensure(context.Background(), work, "run_1", spec); err != nil {
		t.Fatalf("valid container rejected: %v", err)
	}
}

func TestExecDestroysContainerOnContextCancel(t *testing.T) {
	work := t.TempDir()
	runner := &Runner{Images: profile.Images{Python: "agt-sandbox:python"}, Namespace: "ns_cancel", ready: true}
	labelsGood, _ := json.Marshal(map[string]string{"agt-namespace": runner.namespace(), "agt-run": "run_cancel"})
	mountsGood, _ := json.Marshal([]map[string]string{{"Type": "bind", "Source": work, "Destination": "/workspace"}})
	logPath := withStubDocker(t, map[string]string{
		"AGT_TEST_INSPECT_LABELS": string(labelsGood),
		"AGT_TEST_INSPECT_IMAGE":  "agt-sandbox:python",
		"AGT_TEST_INSPECT_MOUNTS": string(mountsGood),
		"AGT_TEST_EXEC_SLEEP":     "1",
	})
	spec := ExecSpec{
		Image:   "agt-sandbox:python",
		Argv:    []string{"python", "-c", "import time; time.sleep(10)"},
		Env:     profile.EnvFor(profile.NamePython),
		Workdir: "/workspace",
		Memory:  "256m",
		CPUs:    "1",
		PIDs:    64,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if raw, err := os.ReadFile(logPath); err == nil && strings.Contains(string(raw), "exec ") {
				cancel()
				return
			}
			time.Sleep(15 * time.Millisecond)
		}
		cancel()
	}()
	_, _, _, err := runner.Exec(ctx, work, "run_cancel", spec)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
	logged, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logged), "rm -f agt-ns_cancel-run_cancel") {
		t.Fatalf("container was not destroyed on cancel:\n%s", logged)
	}
}
