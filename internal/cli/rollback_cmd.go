package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"
)

func rollbackCmd(args []string) int {
	fs := flag.NewFlagSet("rollback", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	rbID := fs.String("id", "", "specific rollback snapshot id to restore")
	listOnly := fs.Bool("list", false, "list available rollback snapshots for the run")
	jsonOut := fs.Bool("json", false, "print machine-readable JSON")
	server := fs.String("server", "", "agtd base URL")
	if err := fs.Parse(reorderFlags(args, map[string]bool{"id": true, "server": true})); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "usage: agt rollback RUN [--id ROLLBACK_ID] [--list] [--json]")
		return 2
	}
	base, err := ensureServer(*server)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	runID := rest[0]
	if *listOnly {
		var resp struct {
			RunID     string `json:"run_id"`
			Rollbacks []struct {
				ID           string `json:"id"`
				Digest       string `json:"digest"`
				Repo         string `json:"repo"`
				RolledBack   bool   `json:"rolled_back"`
				RolledBackAt string `json:"rolled_back_at,omitempty"`
				Files        []any  `json:"files"`
			} `json:"rollbacks"`
		}
		if err := getJSON(base+"/v1/runs/"+runID+"/rollbacks", &resp); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if *jsonOut {
			_ = json.NewEncoder(os.Stdout).Encode(resp)
			return 0
		}
		if len(resp.Rollbacks) == 0 {
			fmt.Printf("no rollbacks for %s\n", runID)
			return 0
		}
		for _, item := range resp.Rollbacks {
			state := "pending"
			if item.RolledBack {
				state = "rolled_back"
				if item.RolledBackAt != "" {
					state += "@" + item.RolledBackAt
				}
			}
			fmt.Printf("%s files=%d digest=%s status=%s\n", item.ID, len(item.Files), shortHash(item.Digest), state)
		}
		return 0
	}

	var resp struct {
		RolledBack int    `json:"rolled_back"`
		RollbackID string `json:"rollback_id"`
		Digest     string `json:"digest"`
		RepoPath   string `json:"repo_path"`
		Rollback   string `json:"rollback"`
	}
	if err := postJSON(base+"/v1/runs/"+runID+"/rollback", map[string]any{"rollback_id": *rbID}, &resp); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if *jsonOut {
		_ = json.NewEncoder(os.Stdout).Encode(resp)
		return 0
	}
	fmt.Printf("rolled_back %d rollback_id %s digest %s repo %s\n", resp.RolledBack, resp.RollbackID, shortHash(resp.Digest), resp.RepoPath)
	return 0
}

func gcCmd(args []string) int {
	fs := flag.NewFlagSet("gc", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	maxAge := fs.String("max-age", "", "retention duration (e.g. 24h, 168h)")
	dryRun := fs.Bool("dry-run", false, "report prunable run directories without deleting them")
	jsonOut := fs.Bool("json", false, "print machine-readable JSON")
	server := fs.String("server", "", "agtd base URL")
	if err := fs.Parse(reorderFlags(args, map[string]bool{"max-age": true, "server": true})); err != nil {
		return 2
	}
	if len(fs.Args()) != 0 {
		fmt.Fprintln(os.Stderr, "usage: agt gc [--max-age DURATION] [--dry-run] [--json]")
		return 2
	}
	if *maxAge != "" {
		d, err := time.ParseDuration(*maxAge)
		if err != nil || d < 0 {
			fmt.Fprintln(os.Stderr, "max-age must be a non-negative Go duration")
			return 2
		}
	}
	base, err := ensureServer(*server)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	var report struct {
		PrunedRunIDs []string `json:"pruned_run_ids"`
		Removed      int      `json:"removed"`
		Skipped      int      `json:"skipped"`
		BytesFreed   int64    `json:"bytes_freed"`
		DryRun       bool     `json:"dry_run"`
	}
	if err := postJSON(base+"/v1/gc", map[string]any{"max_age": *maxAge, "dry_run": *dryRun}, &report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if *jsonOut {
		_ = json.NewEncoder(os.Stdout).Encode(report)
		return 0
	}
	prefix := "pruned"
	if report.DryRun {
		prefix = "dry-run"
	}
	fmt.Printf("%s removed=%d skipped=%d bytes_freed=%d\n", prefix, report.Removed, report.Skipped, report.BytesFreed)
	return 0
}
