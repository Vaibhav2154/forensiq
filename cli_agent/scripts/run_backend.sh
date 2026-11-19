#!/usr/bin/env bash
# Run the existing FastAPI backend for local ForensIQ development.
#
# Requires server/.env (git-ignored) with MONGO_URL, SECRET_KEY and
# GEMINI_API_KEY, and the backend virtualenv created by the commands in
# cli_agent/PHASE_6_REPORT.md section 3.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PYTHON="$REPO_ROOT/cli_agent/.venv-backend/bin/python"

if [[ ! -x "$PYTHON" ]]; then
    echo "missing $PYTHON - create the backend virtualenv first (see PHASE_6_REPORT.md)" >&2
    exit 1
fi
if [[ ! -f "$REPO_ROOT/server/.env" ]]; then
    echo "missing server/.env - see PHASE_6_REPORT.md section 3" >&2
    exit 1
fi

cd "$REPO_ROOT/server"
exec "$PYTHON" -m uvicorn main:app --host 127.0.0.1 --port 8000
