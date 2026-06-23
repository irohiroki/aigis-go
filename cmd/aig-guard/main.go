// aig-guard is the Aigis hook for Claude Code.
//
// It intercepts all tool calls, scans for threats, evaluates policy,
// and logs to the Activity Stream.  Dangerous operations are blocked.
//
// Auto-generated from: aig init --agent claude-code (Go port)
//
// Exit codes (Claude Code hook contract):
//
//	0  — allow
//	2  — block (fail-closed)
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/killertcell428/aigis-go/internal/activity"
	"github.com/killertcell428/aigis-go/internal/policy"
	"github.com/killertcell428/aigis-go/internal/scanner"
)

// hookInput mirrors the JSON structure Claude Code sends to hooks on stdin.
type hookInput struct {
	ToolName      string         `json:"tool_name"`
	ToolInput     map[string]any `json:"tool_input"`
	SessionID     string         `json:"session_id"`
	HookEventName string         `json:"hook_event_name"`
	CWD           string         `json:"cwd"`
}

// copilotInput mirrors the JSON structure GitHub Copilot CLI sends to preToolUse hooks on stdin.
type copilotInput struct {
	ToolName  string          `json:"toolName"`
	ToolArgs  json.RawMessage `json:"toolArgs"`
	SessionID string          `json:"sessionId"`
	CWD       string          `json:"cwd"`
}

// toolCall is the agent-agnostic view of a tool invocation used for scan + policy evaluation.
type toolCall struct {
	action    string
	target    string
	scannable string
	toolName  string
	sessionID string
	hookEvent string
	cwd       string
	agentType string
}

func main() {
	agent := flag.String("agent", "claude-code", "agent input/output format: claude-code | copilot")
	flag.Parse()

	raw := readStdin()
	if *agent == "copilot" {
		runCopilot(raw)
		return
	}
	runClaude(raw)
}

func readStdin() []byte {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil || len(raw) == 0 {
		fmt.Fprintln(os.Stderr, "Aigis: failed to read hook input — blocking (fail-closed)")
		os.Exit(2)
	}
	return raw
}

func runClaude(raw []byte) {
	var input hookInput
	if err := json.Unmarshal(raw, &input); err != nil {
		fmt.Fprintln(os.Stderr, "Aigis: failed to parse hook input — blocking (fail-closed)")
		os.Exit(2)
	}
	if input.CWD == "" {
		input.CWD, _ = os.Getwd()
	}
	tc := toolCall{
		action:    mapAction(input.ToolName),
		target:    extractTarget(input.ToolName, input.ToolInput),
		scannable: getScannableText(input.ToolName, input.ToolInput),
		toolName:  input.ToolName,
		sessionID: input.SessionID,
		hookEvent: input.HookEventName,
		cwd:       input.CWD,
		agentType: "claude_code",
	}
	decision, ruleID, riskScore := evaluate(tc)
	if decision == "deny" {
		fmt.Fprintln(os.Stderr, denyReason(ruleID, riskScore))
		os.Exit(2)
	}
	os.Exit(0)
}

func runCopilot(raw []byte) {
	var input copilotInput
	if err := json.Unmarshal(raw, &input); err != nil {
		emitCopilotDecision("deny", "Aigis: failed to parse hook input")
		os.Exit(2)
	}
	if input.CWD == "" {
		input.CWD, _ = os.Getwd()
	}
	args := map[string]any{}
	_ = json.Unmarshal(input.ToolArgs, &args)

	tc := toolCall{
		action:    mapActionCopilot(input.ToolName),
		target:    extractTargetCopilot(input.ToolName, args),
		scannable: getScannableTextCopilot(input.ToolName, args),
		toolName:  input.ToolName,
		sessionID: input.SessionID,
		hookEvent: "preToolUse",
		cwd:       input.CWD,
		agentType: "copilot",
	}
	decision, ruleID, riskScore := evaluate(tc)
	switch decision {
	case "deny":
		emitCopilotDecision("deny", denyReason(ruleID, riskScore))
	case "review":
		emitCopilotDecision("ask", fmt.Sprintf("Aigis review: %s", ruleID))
	}
	os.Exit(0)
}

func denyReason(ruleID string, riskScore int) string {
	reason := fmt.Sprintf("Aigis blocked: %s", ruleID)
	if riskScore > 0 {
		reason += fmt.Sprintf(" (risk=%d)", riskScore)
	}
	return reason
}

func emitCopilotDecision(decision, reason string) {
	b, _ := json.Marshal(map[string]string{
		"permissionDecision":       decision,
		"permissionDecisionReason": reason,
	})
	fmt.Println(string(b))
}

// evaluate runs the shared scan + policy + activity-logging core and returns the decision.
func evaluate(tc toolCall) (string, string, int) {
	details := map[string]any{"tool_name": tc.toolName, "hook_event": tc.hookEvent}
	evt := activity.NewEvent(tc.action, tc.target, tc.agentType, tc.sessionID, "tool_call", tc.cwd, details)

	var riskScore int
	var riskLevel string
	var matchedRuleIDs []string
	if tc.scannable != "" {
		result := scanner.Scan(tc.scannable)
		riskScore = result.RiskScore
		riskLevel = result.RiskLevel
		for _, mr := range result.MatchedRules {
			matchedRuleIDs = append(matchedRuleIDs, mr.RuleID)
		}
	} else {
		riskLevel = "low"
	}
	evt.RiskScore = riskScore
	evt.RiskLevel = riskLevel
	evt.MatchedRules = matchedRuleIDs

	pol, err := policy.LoadPolicy(policyPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Aigis: policy error (%v) — blocking (fail-closed)\n", err)
		pol = nil
	}
	decision := "deny"
	ruleID := "_error"
	if pol != nil {
		decision, ruleID = policy.Evaluate(policy.Event{
			Action:    tc.action,
			Target:    tc.target,
			RiskScore: riskScore,
			RiskLevel: riskLevel,
		}, pol)
	}
	evt.PolicyDecision = decision
	evt.PolicyRuleID = ruleID
	if decision == "review" {
		evt.EventType = "policy_review"
	}

	stream := activity.NewStream(".aigis/logs")
	stream.Record(&evt)
	return decision, ruleID, riskScore
}

// policyPath returns the policy file path. It is configurable via AIGIS_POLICY.
func policyPath() string {
	if p := os.Getenv("AIGIS_POLICY"); p != "" {
		return p
	}
	return "aigis-policy.yaml"
}

// mapAction maps a Claude Code tool name to an Aigis action string.
func mapAction(toolName string) string {
	actionMap := map[string]string{
		"Bash":         "shell:exec",
		"Read":         "file:read",
		"Write":        "file:write",
		"Edit":         "file:write",
		"Glob":         "file:search",
		"Grep":         "file:search",
		"WebFetch":     "network:fetch",
		"WebSearch":    "network:search",
		"Agent":        "agent:spawn",
		"NotebookEdit": "file:write",
	}
	if strings.HasPrefix(toolName, "mcp__") {
		return "mcp:tool_call"
	}
	if a, ok := actionMap[toolName]; ok {
		return a
	}
	return "unknown:" + toolName
}

// mapActionCopilot maps a GitHub Copilot CLI tool name to an Aigis action string.
func mapActionCopilot(toolName string) string {
	actionMap := map[string]string{
		"bash": "shell:exec", "powershell": "shell:exec", "shell": "shell:exec",
		"list_bash": "shell:exec", "read_bash": "shell:exec", "stop_bash": "shell:exec", "write_bash": "shell:exec",
		"list_powershell": "shell:exec", "read_powershell": "shell:exec", "stop_powershell": "shell:exec", "write_powershell": "shell:exec",
		"view": "file:read", "read_file": "file:read",
		"create": "file:write", "edit": "file:write", "apply_patch": "file:write", "write_file": "file:write", "delete_file": "file:write",
		"glob": "file:search", "grep": "file:search", "rg": "file:search", "search_files": "file:search", "list_directory": "file:search",
		"web_fetch": "network:fetch",
		"task":      "agent:spawn",
	}
	if a, ok := actionMap[toolName]; ok {
		return a
	}
	if strings.HasPrefix(toolName, "mcp") {
		return "mcp:tool_call"
	}
	return "unknown:" + toolName
}

// extractTarget extracts the primary target from the tool input.
func extractTarget(toolName string, toolInput map[string]any) string {
	str := func(key string) string {
		if v, ok := toolInput[key]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
		return ""
	}
	switch toolName {
	case "Bash":
		t := str("command")
		if len(t) > 500 {
			return t[:500]
		}
		return t
	case "Read", "Write", "Edit":
		return str("file_path")
	case "Glob":
		return str("pattern")
	case "Grep":
		return str("pattern")
	case "WebFetch":
		return str("url")
	case "WebSearch":
		return str("query")
	}
	if strings.HasPrefix(toolName, "mcp__") {
		return toolName
	}
	b, _ := json.Marshal(toolInput)
	s := string(b)
	if len(s) > 200 {
		return s[:200]
	}
	return s
}

// getScannableText returns text worth scanning for a given tool call.
func getScannableText(toolName string, toolInput map[string]any) string {
	str := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := toolInput[k]; ok {
				if s, ok := v.(string); ok {
					return s
				}
			}
		}
		return ""
	}
	switch toolName {
	case "Bash":
		return str("command")
	case "Write":
		s := str("content", "file_text")
		if len(s) > 2000 {
			return s[:2000]
		}
		return s
	case "Edit":
		s := str("new_string", "new_str")
		if len(s) > 2000 {
			return s[:2000]
		}
		return s
	case "WebSearch":
		return str("query")
	}
	return ""
}

// extractTargetCopilot extracts the primary target from Copilot tool args.
func extractTargetCopilot(toolName string, toolArgs map[string]any) string {
	str := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := toolArgs[k]; ok {
				if s, ok := v.(string); ok {
					return s
				}
			}
		}
		return ""
	}
	switch mapActionCopilot(toolName) {
	case "shell:exec":
		t := str("command", "script", "input")
		if len(t) > 500 {
			return t[:500]
		}
		return t
	case "file:read", "file:write":
		return str("path", "file_path", "filename")
	case "file:search":
		return str("pattern", "query", "path")
	case "network:fetch":
		return str("url")
	}
	b, _ := json.Marshal(toolArgs)
	s := string(b)
	if len(s) > 200 {
		return s[:200]
	}
	return s
}

// getScannableTextCopilot returns text worth scanning for a given Copilot tool call.
func getScannableTextCopilot(toolName string, toolArgs map[string]any) string {
	str := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := toolArgs[k]; ok {
				if s, ok := v.(string); ok {
					return s
				}
			}
		}
		return ""
	}
	switch toolName {
	case "bash", "powershell", "shell", "write_bash", "write_powershell":
		return str("command", "script", "input")
	case "create", "write_file":
		s := str("content", "text", "file_text")
		if len(s) > 2000 {
			return s[:2000]
		}
		return s
	case "edit":
		s := str("new_str", "new_string", "content")
		if len(s) > 2000 {
			return s[:2000]
		}
		return s
	case "apply_patch":
		s := str("patch", "input", "content")
		if len(s) > 2000 {
			return s[:2000]
		}
		return s
	case "web_fetch":
		return str("url", "query")
	}
	return ""
}
