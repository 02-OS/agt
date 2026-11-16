package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"

	"github.com/csy20/agt/internal/policy"
	"github.com/csy20/agt/internal/tools"
)

// translateClaudeTool maps one documented tool_use block through ask-mode policy.
// The read is not performed. Edit, Write, and Bash are denied in ask mode. A subagent
// call is denied even when the same Read would be allowed for the parent, because a
// parent permission callback does not intercept every Claude call.
func translateClaudeTool(block []byte, subagent bool) (ToolRequest, error) {
	return translateClaudeToolWithMode(block, subagent, "ask")
}

func translateClaudeToolWithMode(block []byte, subagent bool, mode string) (ToolRequest, error) {
	var tool struct {
		ID    string          `json:"id"`
		Name  string          `json:"name"`
		Input json.RawMessage `json:"input"`
	}
	if err := json.Unmarshal(block, &tool); err != nil {
		return ToolRequest{}, protocolf("tool_use")
	}
	if strings.TrimSpace(tool.Name) == "" {
		return ToolRequest{}, protocolf("tool_use requires name")
	}
	if strings.TrimSpace(mode) == "" {
		mode = "ask"
	}
	input := tool.Input
	if len(bytes.TrimSpace(input)) == 0 {
		input = []byte(`{}`)
	}
	req, err := translateNamed(tool.ID, tool.Name, input, mode)
	if err != nil {
		return ToolRequest{}, err
	}
	if subagent {
		req.Subagent = true
		req.Mediated = false
		req.Decision = string(policy.Deny)
		req.Reason = "subagent tool call is outside the parent permission callback and was not executed"
	}
	req.Executed = false
	return req, nil
}

func translateNamed(id, name string, input json.RawMessage, mode string) (ToolRequest, error) {
	switch name {
	case "Read":
		return translateRead(id, input, mode)
	case "Grep":
		return translateGrep(id, input, mode)
	case "Glob":
		return translateGlob(id, input, mode)
	case "Edit":
		return translateEdit(id, input, mode)
	case "Write":
		return translateWrite(id, input, mode)
	case "Bash", "NotebookEdit", "MultiEdit":
		return denyUnmediated(id, name, input, name+" is not an AGT read tool and was not executed"), nil
	default:
		return denyUnmediated(id, name, input, "unrecognised external tool was not executed"), nil
	}
}

func translateRead(id string, input json.RawMessage, mode string) (ToolRequest, error) {
	var args struct {
		FilePath string `json:"file_path"`
		Offset   *int   `json:"offset"`
		Limit    *int   `json:"limit"`
	}
	if err := strict(input, &args); err != nil {
		return denyUnmediated(id, "Read", input, "Read arguments are not the pinned file_path window"), nil
	}
	if strings.TrimSpace(args.FilePath) == "" {
		return denyUnmediated(id, "Read", input, "Read requires file_path"), nil
	}
	start := 1
	end := 400
	if args.Offset != nil {
		start = *args.Offset
		if args.Limit != nil {
			end = start + *args.Limit - 1
		} else {
			end = start + 399
		}
	} else if args.Limit != nil {
		end = *args.Limit
	}
	body := tools.ReadArgs{Path: args.FilePath, Start: start, End: end}
	return mediate(id, "Read", input, mode, "read_file_range", body, "the file was not read")
}

func translateGrep(id string, input json.RawMessage, mode string) (ToolRequest, error) {
	var args struct {
		Pattern string `json:"pattern"`
		Path    string `json:"path"`
		Glob    string `json:"glob"`
	}
	if err := strict(input, &args); err != nil {
		return denyUnmediated(id, "Grep", input, "Grep arguments are not the pinned pattern"), nil
	}
	return mediate(id, "Grep", input, mode, "search_code", tools.SearchArgs{
		Query: args.Pattern,
		Path:  args.Path,
		Glob:  args.Glob,
	}, "search was not executed")
}

func translateGlob(id string, input json.RawMessage, mode string) (ToolRequest, error) {
	var args struct {
		Pattern string `json:"pattern"`
		Path    string `json:"path"`
	}
	if err := strict(input, &args); err != nil {
		return denyUnmediated(id, "Glob", input, "Glob arguments are not the pinned pattern and path"), nil
	}
	if strings.TrimSpace(args.Pattern) == "" {
		return denyUnmediated(id, "Glob", input, "Glob requires pattern"), nil
	}
	return mediate(id, "Glob", input, mode, "search_code", tools.SearchArgs{
		Path: args.Path,
		Glob: args.Pattern,
	}, "search was not executed")
}

func translateEdit(id string, input json.RawMessage, mode string) (ToolRequest, error) {
	var args struct {
		FilePath string `json:"file_path"`
		Old      string `json:"old_string"`
		New      string `json:"new_string"`
	}
	if err := strict(input, &args); err != nil {
		return denyUnmediated(id, "Edit", input, "Edit arguments are not the pinned path, old_string, and new_string"), nil
	}
	body := tools.PatchArgs{Path: args.FilePath, Old: args.Old, New: args.New}
	return mediate(id, "Edit", input, mode, "apply_patch", body, "")
}

func translateWrite(id string, input json.RawMessage, mode string) (ToolRequest, error) {
	var args struct {
		FilePath string `json:"file_path"`
		Content  string `json:"content"`
	}
	if err := strict(input, &args); err != nil {
		return denyUnmediated(id, "Write", input, "Write arguments are not the pinned path and content"), nil
	}
	body := tools.WriteArgs{Path: args.FilePath, Content: args.Content}
	return mediate(id, "Write", input, mode, "write_file", body, "")
}

func mediate(id, providerTool string, providerArgs json.RawMessage, mode, agtTool string, agtArgs any, note string) (ToolRequest, error) {
	body, err := json.Marshal(agtArgs)
	if err != nil {
		return ToolRequest{}, err
	}
	decision, err := policy.DecideFor(mode, agtTool, body)
	if err != nil {
		return ToolRequest{}, err
	}
	reason := decision.Reason
	if note != "" && decision.Decision == policy.Allow {
		reason = decision.Reason + "; " + note
	}
	return ToolRequest{
		CallID:       id,
		ProviderTool: providerTool,
		ProviderArgs: append([]byte(nil), providerArgs...),
		AGTTool:      agtTool,
		AGTArgs:      body,
		ArgsHash:     decision.ArgsHash,
		Decision:     string(decision.Decision),
		Mediated:     true,
		Executed:     false,
		Reason:       reason,
	}, nil
}

func denyUnmediated(id, providerTool string, raw json.RawMessage, reason string) ToolRequest {
	return ToolRequest{
		CallID:       id,
		ProviderTool: providerTool,
		ProviderArgs: append([]byte(nil), raw...),
		Decision:     string(policy.Deny),
		Mediated:     false,
		Executed:     false,
		Reason:       reason,
	}
}

func strict(raw json.RawMessage, dest any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dest); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing json")
	}
	return nil
}
