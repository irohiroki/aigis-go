// Package policy implements declarative rule evaluation for AI agent governance.
// Ported from aigis/policy.py.
package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// PolicyRule is a single governance rule.
type PolicyRule struct {
	ID         string            `yaml:"id"        json:"id"`
	Action     string            `yaml:"action"    json:"action"`
	Target     string            `yaml:"target"    json:"target"`
	Decision   string            `yaml:"decision"  json:"decision"`
	Reason     string            `yaml:"reason"    json:"reason"`
	Conditions map[string]string `yaml:"conditions" json:"conditions"`
}

// Policy is a collection of rules that govern agent behaviour.
type Policy struct {
	Name            string       `yaml:"name"             json:"name"`
	Version         string       `yaml:"version"          json:"version"`
	Rules           []PolicyRule `yaml:"rules"            json:"rules"`
	DefaultDecision string       `yaml:"default_decision" json:"default_decision"`
}

// Event carries the fields needed for policy evaluation.
// Only the subset used by evaluate() is required.
type Event struct {
	Action       string
	Target       string
	RiskScore    int
	RiskLevel    string
	AutonomyLevel int
	EstimatedCost float64
	MemoryScope   string
}

// LoadPolicy reads a policy YAML file.  Falls back to the built-in default
// when the file is absent.  Also accepts JSON.
func LoadPolicy(path string) (*Policy, error) {
	if path == "" {
		path = "aigis-policy.yaml"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return defaultPolicy(), nil
	}
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".json" {
		var p Policy
		if err := json.Unmarshal(data, &p); err != nil {
			return nil, err
		}
		return &p, nil
	}
	return parseSimpleYAML(string(data))
}

// Evaluate returns (decision, matchedRuleID).
// Rules are evaluated in order; first match wins.
func Evaluate(event Event, p *Policy) (string, string) {
	for _, rule := range p.Rules {
		if !matches(event, rule) {
			continue
		}
		if !checkConditions(event, rule.Conditions) {
			continue
		}
		return rule.Decision, rule.ID
	}
	return p.DefaultDecision, "_default"
}

// matches checks action + target glob against an event.
func matches(event Event, rule PolicyRule) bool {
	if !globMatch(event.Action, rule.Action) {
		return false
	}
	if rule.Target == "*" || event.Target == "" {
		return true
	}
	target := strings.ReplaceAll(event.Target, "\\", "/")
	pattern := strings.ReplaceAll(rule.Target, "\\", "/")

	if globMatch(target, pattern) {
		return true
	}
	// Also check basename.
	base := filepath.Base(target)
	if globMatch(base, pattern) {
		return true
	}
	// For shell:exec also check substring.
	if event.Action == "shell:exec" {
		if strings.Contains(target, pattern) || globMatch(target, "*"+pattern+"*") {
			return true
		}
	}
	return false
}

// checkConditions validates AGI-era conditions.
func checkConditions(event Event, conds map[string]string) bool {
	if len(conds) == 0 {
		return true
	}
	if v, ok := conds["autonomy_level"]; ok {
		required, _ := strconv.Atoi(v)
		if event.AutonomyLevel < required {
			return false
		}
	}
	if v, ok := conds["cost_limit"]; ok {
		limit, _ := strconv.ParseFloat(v, 64)
		if event.EstimatedCost > limit {
			return false
		}
	}
	if v, ok := conds["department"]; ok {
		if event.MemoryScope != "" && !strings.Contains(event.MemoryScope, v) {
			return false
		}
	}
	if v, ok := conds["risk_above"]; ok {
		threshold, _ := strconv.Atoi(v)
		if event.RiskScore < threshold {
			return false
		}
	}
	if v, ok := conds["risk_level"]; ok {
		order := map[string]int{"low": 0, "medium": 1, "high": 2, "critical": 3}
		required := order[strings.ToLower(v)]
		actual := order[strings.ToLower(event.RiskLevel)]
		if actual < required {
			return false
		}
	}
	return true
}

// globMatch implements fnmatch-style pattern matching (*, ?, no []).
func globMatch(s, pattern string) bool {
	if pattern == "*" {
		return true
	}
	return fnmatch(s, pattern)
}

// fnmatch is a simple glob matcher supporting * and ?.
func fnmatch(s, pattern string) bool {
	for len(pattern) > 0 {
		if pattern[0] == '*' {
			// Skip consecutive stars.
			for len(pattern) > 0 && pattern[0] == '*' {
				pattern = pattern[1:]
			}
			if len(pattern) == 0 {
				return true
			}
			for i := 0; i <= len(s); i++ {
				if fnmatch(s[i:], pattern) {
					return true
				}
			}
			return false
		}
		if len(s) == 0 {
			return false
		}
		if pattern[0] == '?' || pattern[0] == s[0] {
			pattern = pattern[1:]
			s = s[1:]
			continue
		}
		return false
	}
	return len(s) == 0
}

// defaultPolicy returns the built-in policy (mirrors policy.py _default_policy).
func defaultPolicy() *Policy {
	return &Policy{
		Name:            "Aigis Default Policy",
		Version:         "1.0",
		DefaultDecision: "allow",
		Rules: []PolicyRule{
			{ID: "dangerous_commands", Action: "shell:exec", Target: "rm -rf *", Decision: "deny", Reason: "Recursive forced deletion is blocked"},
			{ID: "dangerous_format", Action: "shell:exec", Target: "*mkfs*", Decision: "deny", Reason: "Filesystem format commands are blocked"},
			{ID: "dangerous_dd", Action: "shell:exec", Target: "*dd if=*", Decision: "deny", Reason: "Raw disk operations are blocked"},
			{ID: "sudo_commands", Action: "shell:exec", Target: "sudo *", Decision: "review", Reason: "Privilege escalation requires review"},
			{ID: "env_file_protection", Action: "file:write", Target: ".env*", Decision: "deny", Reason: "Environment files are protected from modification"},
			{ID: "secrets_dir_protection", Action: "file:*", Target: "*secrets*", Decision: "review", Reason: "Access to secrets directories requires review"},
			{ID: "ssh_key_protection", Action: "file:*", Target: "*.ssh/*", Decision: "deny", Reason: "SSH key access is blocked"},
			{ID: "credentials_protection", Action: "file:write", Target: "*credentials*", Decision: "deny", Reason: "Credential files are protected"},
			{ID: "pipe_to_shell", Action: "shell:exec", Target: "*| bash*", Decision: "deny", Reason: "Piping remote content to shell is blocked"},
			{ID: "pipe_to_sh", Action: "shell:exec", Target: "*| sh*", Decision: "deny", Reason: "Piping remote content to shell is blocked"},
			{ID: "git_force_push", Action: "shell:exec", Target: "*--force*", Decision: "deny", Reason: "Force push is blocked"},
			{ID: "git_push_review", Action: "shell:exec", Target: "git push*", Decision: "review", Reason: "Git push requires review"},
			{ID: "agent_spawn_review", Action: "agent:spawn", Target: "*", Decision: "review", Reason: "Spawning sub-agents requires review"},
			{ID: "llm_prompt_scan", Action: "llm:prompt", Target: "*", Decision: "allow", Reason: "LLM prompts are scanned"},
			{ID: "risk_threshold_critical", Action: "*", Target: "*", Decision: "deny", Reason: "Critical-risk content detected", Conditions: map[string]string{"risk_above": "80"}},
			{ID: "risk_threshold_medium", Action: "*", Target: "*", Decision: "review", Reason: "Suspicious content detected", Conditions: map[string]string{"risk_above": "40"}},
		},
	}
}

// ParseYAMLForTest is a test helper that exposes parseSimpleYAML publicly.
func ParseYAMLForTest(text string) (*Policy, error) { return parseSimpleYAML(text) }

// parseSimpleYAML is a minimal YAML parser that handles the aigis policy format.
// It mirrors policy.py _parse_simple_yaml() without requiring a third-party library.
func parseSimpleYAML(text string) (*Policy, error) {
	p := &Policy{}
	var currentItem map[string]string
	var currentConditions map[string]string
	inConditions := false

	flush := func() {
		if currentItem != nil {
			if currentConditions != nil {
				currentItem["_conditions"] = ""
				// encode conditions into the item so we can reconstruct them
			}
			rule := PolicyRule{
				ID:       currentItem["id"],
				Action:   currentItem["action"],
				Target:   currentItem["target"],
				Decision: currentItem["decision"],
				Reason:   currentItem["reason"],
			}
			if rule.Target == "" {
				rule.Target = "*"
			}
			if currentConditions != nil {
				rule.Conditions = currentConditions
			}
			p.Rules = append(p.Rules, rule)
			currentItem = nil
			currentConditions = nil
			inConditions = false
		}
	}

	for _, rawLine := range strings.Split(text, "\n") {
		line := rawLine
		stripped := strings.TrimSpace(line)
		if stripped == "" || strings.HasPrefix(stripped, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " \t"))

		if indent == 0 && strings.Contains(stripped, ":") {
			flush()
			kv := strings.SplitN(stripped, ":", 2)
			key := strings.TrimSpace(kv[0])
			val := strings.Trim(strings.TrimSpace(kv[1]), `"'`)
			switch key {
			case "name":
				p.Name = val
			case "version":
				p.Version = val
			case "default_decision":
				p.DefaultDecision = val
			}
		} else if strings.HasPrefix(stripped, "- ") {
			flush()
			currentItem = map[string]string{}
			rest := stripped[2:]
			if strings.Contains(rest, ":") {
				kv := strings.SplitN(rest, ":", 2)
				k := strings.TrimSpace(kv[0])
				v := strings.Trim(strings.TrimSpace(kv[1]), `"'`)
				currentItem[k] = v
			}
		} else if currentItem != nil && strings.Contains(stripped, ":") {
			kv := strings.SplitN(stripped, ":", 2)
			key := strings.TrimSpace(kv[0])
			val := strings.Trim(strings.TrimSpace(kv[1]), `"'`)
			if key == "conditions" && val == "" {
				inConditions = true
				currentConditions = map[string]string{}
			} else if inConditions && indent >= 6 {
				if currentConditions != nil {
					currentConditions[key] = val
				}
			} else {
				inConditions = false
				currentItem[key] = val
			}
		}
	}
	flush()

	if p.DefaultDecision == "" {
		p.DefaultDecision = "allow"
	}
	return p, nil
}
