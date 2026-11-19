#!/usr/bin/env bash
# Launch the functional ForensIQ TUI (not the mock preview).
# Any extra arguments are passed through, e.g. --api-url http://127.0.0.1:8000
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PYTHON="$REPO_ROOT/cli_agent/.venv/bin/python"

if [[ ! -x "$PYTHON" ]]; then
    echo "missing $PYTHON - create the CLI virtualenv first (see PHASE_6_REPORT.md)" >&2
    exit 1
fi

cd "$REPO_ROOT"
exec "$PYTHON" -m cli_agent.tui "$@"
