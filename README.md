# aigis-go

Go port of the [pyaigis](https://pypi.org/project/pyaigis/) Claude Code hook (`aig-guard`).

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

### 1. Copy the binary to your project

```bash
cp aig-guard <your-project-directory>/.claude/hooks/
```

### 2. Create the hook configuration

Add the following to `<your-project-directory>/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "*", "hooks": [{ "type": "command", "command": ".claude/hooks/aig-guard" }] }
    ]
  }
}
```

## Tests

```bash
go test ./...
```

## License

Apache 2.0 — free for personal and commercial use. See [LICENSE](LICENSE).
