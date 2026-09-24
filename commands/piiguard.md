---
description: Turn the PII Guardrail on or off, or check its status
argument-hint: "[on|off|detect|status]"
---

Run the PII Guardrail control script and show the user its output verbatim.

The argument given was: `$ARGUMENTS`

Map it to a flag and run exactly one command:

| Argument | Command |
|---|---|
| `on` (or empty) | `"${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" --on` |
| `off` | `"${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" --off` |
| `detect` | `"${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" --detect` |
| `status` | `"${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" --status` |

If no argument was given, run `--status` rather than guessing.

Then report the result in one short line — do not re-explain the output, and do
not offer further changes. The change takes effect on the next prompt; no
restart is needed.
