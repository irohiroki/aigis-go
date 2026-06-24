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

## Default policy

This port intentionally **diverges from pyaigis** in its default policy.
pyaigis ships a set of glob-based rules that deny or flag specific commands
and paths — `rm -rf *`, `*mkfs*`, `*dd if=*`, `sudo *`, `.env*`, `*secrets*`,
`*.ssh/*`, `*credentials*`, `*| bash*`, `*--force*`, `git push*`, and so on.
This port removes them from both the bundled `aigis-policy.yaml` and the
built-in fallback policy.

The reasoning: a literal command/path pattern is trivially bypassed — an agent
can rephrase the command or rename the path and slip past the glob. Such rules
give a false sense of protection while still spending tokens on every
evaluation. What remains are the controls that are harder to evade:

- `agent:spawn` → review (spawning sub-agents)
- `llm:prompt` → scanned
- content risk score above 80 → deny, above 40 → review

To restore the original behaviour, reverse the commit that removed the rules.
From a clone of this repo:

```bash
git show a63f5c5 | git apply -R
```

This re-adds the rules to both `aigis-policy.yaml` and the built-in fallback
(the commit is `a63f5c5` "Remove ineffective rules" — run `git log` to find it
if the hash has drifted). Alternatively, copy the rules back into your own
`aigis-policy.yaml` by hand.

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
