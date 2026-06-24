package policy_test

import (
	"testing"

	"github.com/killertcell428/aigis-go/internal/policy"
)

func TestDefaultPolicy_SafeAction(t *testing.T) {
	p, _ := policy.LoadPolicy("")
	e := policy.Event{Action: "file:read", Target: "main.go"}
	dec, _ := policy.Evaluate(e, p)
	if dec != "allow" {
		t.Errorf("expected allow for safe read, got %s", dec)
	}
}

func TestDefaultPolicy_RiskThreshold(t *testing.T) {
	p, _ := policy.LoadPolicy("")
	e := policy.Event{Action: "file:read", Target: "safe.txt", RiskScore: 85, RiskLevel: "critical"}
	dec, ruleID := policy.Evaluate(e, p)
	if dec != "deny" {
		t.Errorf("expected deny for high risk, got %s (%s)", dec, ruleID)
	}
}

func TestParseYAML(t *testing.T) {
	const yaml = `
name: "Test Policy"
version: "1.0"
default_decision: allow
rules:
  - id: block_write
    action: "file:write"
    target: "*.secret"
    decision: deny
    reason: "secrets are protected"
`
	p, err := policy.ParseYAMLForTest(yaml)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "Test Policy" {
		t.Errorf("unexpected name: %s", p.Name)
	}
	e := policy.Event{Action: "file:write", Target: "key.secret"}
	dec, _ := policy.Evaluate(e, p)
	if dec != "deny" {
		t.Errorf("expected deny, got %s", dec)
	}
}
