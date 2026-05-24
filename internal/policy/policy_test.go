package policy_test

import (
	"testing"

	"github.com/killertcell428/aigis-go/internal/policy"
)

func TestDefaultPolicy_DangerousCommands(t *testing.T) {
	p, err := policy.LoadPolicy("nonexistent-policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	e := policy.Event{Action: "shell:exec", Target: "rm -rf /home/user"}
	dec, ruleID := policy.Evaluate(e, p)
	if dec != "deny" {
		t.Errorf("expected deny, got %s (%s)", dec, ruleID)
	}
}

func TestDefaultPolicy_EnvFile(t *testing.T) {
	p, _ := policy.LoadPolicy("")
	e := policy.Event{Action: "file:write", Target: ".env"}
	dec, _ := policy.Evaluate(e, p)
	if dec != "deny" {
		t.Errorf("expected deny for .env write, got %s", dec)
	}
}

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

func TestDefaultPolicy_GitPushReview(t *testing.T) {
	p, _ := policy.LoadPolicy("")
	e := policy.Event{Action: "shell:exec", Target: "git push origin main"}
	dec, _ := policy.Evaluate(e, p)
	if dec != "review" {
		t.Errorf("expected review for git push, got %s", dec)
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
