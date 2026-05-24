// Package activity implements the Aigis Activity Stream — unified event log.
// Ported from aigis/activity.py.
package activity

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/user"
	"path/filepath"
	"time"
)

// Event captures who/what/when/where for every AI agent operation.
type Event struct {
	// What happened
	Action string `json:"action"`
	Target string `json:"target"`

	// Who did it
	AgentType string `json:"agent_type"`
	UserID    string `json:"user_id"`
	SessionID string `json:"session_id"`

	// Context
	EventType   string         `json:"event_type"`
	CWD         string         `json:"cwd"`
	ProjectName string         `json:"project_name"`
	Details     map[string]any `json:"details"`

	// Security
	RiskScore    int      `json:"risk_score"`
	RiskLevel    string   `json:"risk_level"`
	MatchedRules []string `json:"matched_rules"`

	// Remediation
	RemediationHints []string `json:"remediation_hints"`
	OWASPRefs        []string `json:"owasp_refs"`

	// Policy
	PolicyDecision string `json:"policy_decision"`
	PolicyRuleID   string `json:"policy_rule_id"`

	// Metadata
	Timestamp string `json:"timestamp"`
	EventID   string `json:"event_id"`

	// AGI-era extensions
	AutonomyLevel   int      `json:"autonomy_level"`
	DelegationChain []string `json:"delegation_chain"`
	EstimatedCost   float64  `json:"estimated_cost"`
	MemoryScope     string   `json:"memory_scope"`

	// Auto-fix
	SuggestedFix string `json:"suggested_fix"`
	FixApplied   bool   `json:"fix_applied"`
}

// NewEvent creates an Event with auto-populated metadata.
func NewEvent(action, target, agentType, sessionID, eventType, cwd string, details map[string]any) Event {
	e := Event{
		Action:      action,
		Target:      target,
		AgentType:   agentType,
		SessionID:   sessionID,
		EventType:   eventType,
		CWD:         cwd,
		Details:     details,
		RiskLevel:   "low",
		PolicyDecision: "allow",
		MatchedRules: []string{},
		RemediationHints: []string{},
		OWASPRefs:    []string{},
		DelegationChain: []string{},
	}
	e.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	e.EventID = randHex(12)
	if cwd != "" {
		e.ProjectName = filepath.Base(cwd)
	}
	if u, err := user.Current(); err == nil {
		e.UserID = u.Username
	} else {
		e.UserID = "unknown"
	}
	return e
}

// IsAlert returns true for events that should be archived permanently.
func (e *Event) IsAlert() bool {
	return e.PolicyDecision == "deny" ||
		e.PolicyDecision == "review" ||
		e.RiskScore >= 50 ||
		e.EventType == "policy_block" ||
		e.EventType == "scan_alert"
}

// Stream is the multi-tier activity logger.
type Stream struct {
	localDir     string
	globalDir    string
	alertDir     string
	enableGlobal bool
	enableAlerts bool
}

// NewStream creates a Stream.  logDir defaults to ".aigis/logs".
func NewStream(logDir string) *Stream {
	if logDir == "" {
		logDir = ".aigis/logs"
	}
	home, _ := os.UserHomeDir()
	s := &Stream{
		localDir:     logDir,
		globalDir:    filepath.Join(home, ".aigis", "global"),
		alertDir:     filepath.Join(home, ".aigis", "alerts"),
		enableGlobal: true,
		enableAlerts: true,
	}
	_ = os.MkdirAll(s.localDir, 0755)
	_ = os.MkdirAll(s.globalDir, 0755)
	_ = os.MkdirAll(s.alertDir, 0755)
	return s
}

// Record appends the event to all applicable tiers.
func (s *Stream) Record(e *Event) {
	line, err := json.Marshal(e)
	if err != nil {
		return
	}
	date := time.Now().UTC().Format("2006-01-02")
	_ = appendLine(filepath.Join(s.localDir, date+".jsonl"), string(line))
	if s.enableGlobal {
		_ = appendLine(filepath.Join(s.globalDir, date+".jsonl"), string(line))
	}
	if s.enableAlerts && e.IsAlert() {
		_ = appendLine(filepath.Join(s.alertDir, date+".jsonl"), string(line))
	}
}

func appendLine(path, line string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, line)
	return err
}

func randHex(n int) string {
	const chars = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return string(b)
}
