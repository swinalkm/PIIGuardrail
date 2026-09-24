#!/bin/sh
# Entry point for every PII Guardrail hook event and for the --on/--off CLI.
#
# Resolves its own directory from $0 rather than trusting CLAUDE_PLUGIN_ROOT.
# That variable is set for hook processes but NOT in a normal shell, and when
# it was empty this script silently ran "/hooks/scan.py", which does not exist
# - so the guard did nothing while appearing to work.
#
# Probes for python3 first: naming it directly in hooks.json would error on
# every prompt and every tool call on a machine without it. Exit 0 with no
# stdout is a clean no-op.

DIR=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd) || exit 0
[ -f "$DIR/scan.py" ] || exit 0
command -v python3 >/dev/null 2>&1 || exit 0
exec python3 -S -E "$DIR/scan.py" "$@"
