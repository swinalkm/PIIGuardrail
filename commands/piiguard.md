---
description: Turn the PII Guardrail on or off, or check its status
argument-hint: "[on|off|detect|status]"
---

Run the PII Guardrail control script and show its output to the user verbatim.

The user's argument was: `$ARGUMENTS`

Pick the flag from that argument — `on` → `--on`, `off` → `--off`,
`detect` → `--detect`, anything else or empty → `--status` — then run this
single Bash command, substituting FLAG:

```bash
PG=$(ls -d "$HOME"/.claude/plugins/cache/*/piiguard/*/hooks/run.sh \
         "$HOME"/.claude/plugins/marketplaces/*/hooks/run.sh 2>/dev/null \
      | sort -V | tail -1); \
  [ -n "$PG" ] && sh "$PG" FLAG || echo "PII Guardrail is not installed."
```

The glob resolves the versioned install path, so do not hardcode a version and
do not rely on `$CLAUDE_PLUGIN_ROOT` — it is not set in a shell.

Report the result in one short line. The change applies to the next prompt; no
restart is needed.
