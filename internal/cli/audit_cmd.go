package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/csy20/agt/internal/audit"
	"github.com/csy20/agt/internal/config"
)

func auditCmd(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: agt audit verify [--file PATH] [--json]")
		return 2
	}
	switch args[0] {
	case "verify":
		return auditVerifyCmd(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown audit command %q\nusage: agt audit verify [--file PATH] [--json]\n", args[0])
		return 2
	}
}

func auditVerifyCmd(args []string) int {
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fileFlag := fs.String("file", "", "path to audit JSONL log")
	jsonOut := fs.Bool("json", false, "print machine-readable JSON")
	if err := fs.Parse(reorderFlags(args, map[string]bool{"file": true})); err != nil {
		return 2
	}
	if len(fs.Args()) != 0 {
		fmt.Fprintln(os.Stderr, "usage: agt audit verify [--file PATH] [--json]")
		return 2
	}
	path := *fileFlag
	if path == "" {
		path = filepath.Join(config.Load().DataDir, "audit.jsonl")
	}

	type verifyReport struct {
		Path    string `json:"path"`
		OK      bool   `json:"ok"`
		Events  int    `json:"events"`
		LastSeq int64  `json:"last_seq"`
		Error   string `json:"error,omitempty"`
	}

	writeReport := func(rep verifyReport) {
		if *jsonOut {
			_ = json.NewEncoder(os.Stdout).Encode(rep)
			return
		}
		if rep.OK {
			fmt.Printf("ok events=%d last_seq=%d path=%s\n", rep.Events, rep.LastSeq, rep.Path)
			return
		}
		fmt.Fprintf(os.Stderr, "audit verification failed (%s): %s\n", rep.Path, rep.Error)
	}

	if _, err := os.Lstat(path); err != nil {
		msg := err.Error()
		if errors.Is(err, os.ErrNotExist) {
			msg = "audit log does not exist"
		}
		writeReport(verifyReport{Path: path, OK: false, Error: msg})
		return 1
	}
	events, err := audit.Replay(path)
	if err != nil {
		msg := err.Error()
		if errors.Is(err, os.ErrNotExist) {
			msg = "audit log does not exist"
		}
		writeReport(verifyReport{Path: path, OK: false, Error: msg})
		return 1
	}
	var lastSeq int64
	if len(events) > 0 {
		lastSeq = events[len(events)-1].Seq
	}
	writeReport(verifyReport{
		Path:    path,
		OK:      true,
		Events:  len(events),
		LastSeq: lastSeq,
	})
	return 0
}
