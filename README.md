# aigis-go

Go port of the Aigis Claude Code hook (`aig-guard`).

## What it does

`aig-guard` is a [Claude Code hook](https://docs.anthropic.com/en/docs/claude-code/hooks) that:

1. Reads a tool-call event from stdin (JSON)
2. Maps the tool name to an Aigis action (`shell:exec`, `file:write`, …)
3. Scans scannable content (commands, file content, queries) against 200+ detection patterns
4. Evaluates the configured policy (`aigis-policy.yaml`)
5. Logs every event to the Activity Stream (`.aigis/logs/`, `~/.aigis/global/`, `~/.aigis/alerts/`)
6. Exits `0` (allow) or `2` (block / fail-closed)

## Build

```bash
go build -o aig-guard ./cmd/aig-guard/
```

## Install as Claude Code hook

Copy the binary to your project and add it to `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "*", "hooks": [{ "type": "command", "command": ".claude/hooks/aig-guard" }] }
    ]
  }
}
```

## Project structure

```
cmd/aig-guard/          Main hook binary
internal/scanner/       Text scanning against 200+ regex detection patterns
  patterns.json         Auto-generated from aigis/patterns.py
internal/policy/        YAML policy loader and rule evaluator
internal/activity/      Multi-tier JSONL activity logging
```

## Zero dependencies

The module has no external dependencies.  The policy YAML is parsed with a
hand-written parser that handles the aigis-policy.yaml format, and the detection
patterns are embedded in the binary at compile time via `//go:embed`.

## Tests

```bash
go test ./...
```

## Regenerating patterns.json

```bash
cd ../aigis
python3 -c "
import json, sys
sys.path.insert(0, '.')
from aigis.patterns import ALL_INPUT_PATTERNS
patterns = [{'id': p.id, 'name': p.name, 'category': p.category,
             'pattern': p.pattern.pattern, 'flags': p.pattern.flags,
             'base_score': p.base_score, 'description': p.description,
             'owasp_ref': p.owasp_ref, 'remediation_hint': p.remediation_hint,
             'enabled': p.enabled} for p in ALL_INPUT_PATTERNS]
print(json.dumps(patterns, ensure_ascii=False, indent=2))
" > ../aigis-go/internal/scanner/patterns.json
```
