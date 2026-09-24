#!/bin/sh
# Entry point for every PII Guardrail hook event.
#
# Probes for python3 first: on a machine without it, naming python3 directly in
# hooks.json would error on every prompt and every tool call. Exiting 0 with no
# stdout is a clean no-op.
command -v python3 >/dev/null 2>&1 || exit 0
exec python3 -S -E "${CLAUDE_PLUGIN_ROOT}/hooks/scan.py" "$@"
