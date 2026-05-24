// Package scanner implements text scanning against detection patterns.
// Ported from aigis/scanner.py and aigis/patterns.py.
package scanner

import (
	_ "embed"
	"encoding/json"
	"regexp"
	"strings"
	"unicode"
)

//go:embed patterns.json
var patternsJSON []byte

// DetectionPattern mirrors the Python DetectionPattern dataclass.
type DetectionPattern struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Category        string `json:"category"`
	PatternStr      string `json:"pattern"`
	Flags           int    `json:"flags"` // Python re flags (informational only; we use Go RE2)
	BaseScore       int    `json:"base_score"`
	Description     string `json:"description"`
	OWASPRef        string `json:"owasp_ref"`
	RemediationHint string `json:"remediation_hint"`
	Enabled         bool   `json:"enabled"`

	compiled *regexp.Regexp
}

// MatchedRule is one pattern match with context.
type MatchedRule struct {
	RuleID          string `json:"rule_id"`
	RuleName        string `json:"rule_name"`
	Category        string `json:"category"`
	ScoreDelta      int    `json:"score_delta"`
	MatchedText     string `json:"matched_text"`
	OWASPRef        string `json:"owasp_ref"`
	RemediationHint string `json:"remediation_hint"`
}

// ScanResult holds the outcome of scanning text.
type ScanResult struct {
	RiskScore    int           `json:"risk_score"`
	RiskLevel    string        `json:"risk_level"`
	MatchedRules []MatchedRule `json:"matched_rules"`
	Reason       string        `json:"reason"`
}

// IsSafe returns true when risk level is low (score ≤ 30).
func (r ScanResult) IsSafe() bool { return r.RiskLevel == "low" }

// IsBlocked returns true when risk level is critical (score > 80).
func (r ScanResult) IsBlocked() bool { return r.RiskLevel == "critical" }

var allPatterns []*DetectionPattern

func init() {
	var raw []DetectionPattern
	if err := json.Unmarshal(patternsJSON, &raw); err != nil {
		panic("aigis-go: failed to parse embedded patterns.json: " + err.Error())
	}
	for i := range raw {
		p := &raw[i]
		if !p.Enabled {
			continue
		}
		// Convert Python regex to Go RE2 (case-insensitive, dot-all via inline (?s)).
		goPattern := "(?i)(?s)" + pythonToGoRegex(p.PatternStr)
		compiled, err := regexp.Compile(goPattern)
		if err != nil {
			// Skip patterns that don't compile in RE2.
			continue
		}
		p.compiled = compiled
		allPatterns = append(allPatterns, p)
	}
}

// Scan runs all detection patterns against text and returns a scored result.
func Scan(text string) ScanResult {
	if text == "" {
		return ScanResult{RiskScore: 0, RiskLevel: "low"}
	}
	normalized := normalizeText(text)
	return runPatterns(normalized)
}

// normalizeText mirrors aigis/scanner.py _normalize_text().
func normalizeText(text string) string {
	// Step 1: NFKC normalization (fullwidth → halfwidth, etc.) via rune mapping.
	text = strings.Map(nfkcMap, text)

	// Step 2: Remove zero-width characters.
	zwChars := "\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad\u2060\u2061\u2062\u2063\u2064"
	for _, ch := range zwChars {
		text = strings.ReplaceAll(text, string(ch), "")
	}

	// Step 3: Detect and collapse character spacing ("D R O P" → "DROP").
	spacedRe := regexp.MustCompile(`(?:[A-Za-z] ){3,}[A-Za-z]`)
	if spacedRe.MatchString(text) {
		collapseRe := regexp.MustCompile(`(?:^|[^A-Za-z])([A-Za-z](?:\s[A-Za-z]){2,})(?:[^A-Za-z]|$)`)
		extra := collapseRe.ReplaceAllStringFunc(text, func(m string) string {
			return strings.ReplaceAll(m, " ", "")
		})
		if extra != text {
			text = text + "\n" + extra
		}
	}

	return text
}

// nfkcMap approximates NFKC fullwidth→halfwidth for ASCII range.
func nfkcMap(r rune) rune {
	// Fullwidth ASCII: U+FF01–U+FF5E → U+0021–U+007E
	if r >= '\uFF01' && r <= '\uFF5E' {
		return r - 0xFF01 + 0x21
	}
	// Ideographic space → regular space
	if r == '\u3000' {
		return ' '
	}
	return r
}

// pythonToGoRegex performs light translation of Python regex features to Go RE2.
func pythonToGoRegex(pat string) string {
	// Python uses (?P<name>...) named groups; Go RE2 uses (?P<name>...) too — compatible.
	// \b word boundaries are supported in RE2.
	// The main incompatibility: Python's re.DOTALL is handled by (?s) prefix.
	// Atomic groups (?> ...) and possessive quantifiers are not in RE2; strip them.
	// For now we do a best-effort translation.

	// Replace (?:...) — already RE2-compatible.
	// Replace lookaheads (?=...) and (?!...) — supported in RE2.
	// Replace lookbehinds (?<=...) and (?<!...) — NOT in RE2; remove condition.
	pat = removeLookbehinds(pat)
	return pat
}

// removeLookbehinds strips Python lookbehind assertions which RE2 does not support.
func removeLookbehinds(pat string) string {
	// Simple replacer: (?<=...) → (?:) and (?<!...) → (?:)
	result := strings.Builder{}
	i := 0
	for i < len(pat) {
		if i+4 <= len(pat) && pat[i:i+4] == "(?<=" {
			// Find matching )
			depth := 1
			j := i + 4
			for j < len(pat) && depth > 0 {
				if pat[j] == '(' {
					depth++
				} else if pat[j] == ')' {
					depth--
				}
				j++
			}
			i = j
			continue
		}
		if i+4 <= len(pat) && pat[i:i+4] == "(?<!" {
			depth := 1
			j := i + 4
			for j < len(pat) && depth > 0 {
				if pat[j] == '(' {
					depth++
				} else if pat[j] == ')' {
					depth--
				}
				j++
			}
			i = j
			continue
		}
		result.WriteByte(pat[i])
		i++
	}
	return result.String()
}

func runPatterns(text string) ScanResult {
	var matched []MatchedRule
	categoryScores := map[string]int{}

	for _, p := range allPatterns {
		loc := p.compiled.FindString(text)
		if loc == "" {
			continue
		}
		// Truncate matched text for safety.
		matchedText := loc
		if len(matchedText) > 200 {
			matchedText = matchedText[:200] + "..."
		}

		mr := MatchedRule{
			RuleID:          p.ID,
			RuleName:        p.Name,
			Category:        p.Category,
			ScoreDelta:      p.BaseScore,
			MatchedText:     matchedText,
			OWASPRef:        p.OWASPRef,
			RemediationHint: p.RemediationHint,
		}
		matched = append(matched, mr)
		if categoryScores[p.Category] < p.BaseScore {
			categoryScores[p.Category] = p.BaseScore
		}
	}

	totalScore := 0
	for _, s := range categoryScores {
		totalScore += s
	}
	if totalScore > 100 {
		totalScore = 100
	}

	level := scoreToLevel(totalScore)
	reason := ""
	if len(matched) > 0 {
		names := make([]string, 0, len(matched))
		for _, m := range matched {
			names = append(names, m.RuleName)
		}
		reason = strings.Join(uniqueStrings(names), ", ")
	}

	return ScanResult{
		RiskScore:    totalScore,
		RiskLevel:    level,
		MatchedRules: matched,
		Reason:       reason,
	}
}

func scoreToLevel(score int) string {
	switch {
	case score <= 30:
		return "low"
	case score <= 60:
		return "medium"
	case score <= 80:
		return "high"
	default:
		return "critical"
	}
}

func uniqueStrings(ss []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// PatternCount returns the number of successfully compiled detection patterns.
func PatternCount() int { return len(allPatterns) }

// isLetter is a helper for spacing collapse.
var _ = unicode.IsLetter
