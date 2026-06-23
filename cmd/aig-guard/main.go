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

func main() {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil || len(raw) == 0 {
		fmt.Fprintln(os.Stderr, "Aigis: failed to read hook input — blocking (fail-closed)")
		os.Exit(2)
	}

	var input hookInput
	if err := json.Unmarshal(raw, &input); err != nil {
		fmt.Fprintln(os.Stderr, "Aigis: failed to parse hook input — blocking (fail-closed)")
		os.Exit(2)
	}

	if input.CWD == "" {
		input.CWD, _ = os.Getwd()
	}

	action := mapAction(input.ToolName)
	target := extractTarget(input.ToolName, input.ToolInput)

	// Build activity event.
	details := map[string]any{
		"tool_name":  input.ToolName,
		"hook_event": input.HookEventName,
	}
	evt := activity.NewEvent(action, target, "claude_code", input.SessionID, "tool_call", input.CWD, details)

	// Scan scannable content for threats.
	scannable := getScannableText(input.ToolName, input.ToolInput)
	var riskScore int
	var riskLevel string
	var matchedRuleIDs []string

	if scannable != "" {
		result := scanner.Scan(scannable)
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

	// Evaluate policy.
	pol, err := policy.LoadPolicy(policyPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Aigis: policy error (%v) — blocking (fail-closed)\n", err)
		pol = nil
	}

	decision := "deny"
	ruleID := "_error"
	if pol != nil {
		policyEvent := policy.Event{
			Action:    action,
			Target:    target,
			RiskScore: riskScore,
			RiskLevel: riskLevel,
		}
		decision, ruleID = policy.Evaluate(policyEvent, pol)
	}

	evt.PolicyDecision = decision
	evt.PolicyRuleID = ruleID

	// Log to Activity Stream (best-effort; never block on log failure).
	stream := activity.NewStream(".aigis/logs")
	stream.Record(&evt)

	// Act on decision.
	if decision == "deny" {
		reason := fmt.Sprintf("Aigis blocked: %s", ruleID)
		if riskScore > 0 {
			reason += fmt.Sprintf(" (risk=%d)", riskScore)
		}
		fmt.Fprintln(os.Stderr, reason)
		os.Exit(2)
	}

	if decision == "review" {
		evt.EventType = "policy_review"
	}

	os.Exit(0)
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
