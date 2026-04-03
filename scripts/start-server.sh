#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$REPO_ROOT"

if [ -f "$(python -c 'import sys; import os; print(os.path.join(sys.prefix, \"bin\", \"gunicorn\"))')" ]; then
  GUNICORN="$(python -c 'import os, sys; print(os.path.join(sys.prefix, \"bin\", \"gunicorn\"))')"
else
  GUNICORN="gunicorn"
fi

export PYTHONPATH="$REPO_ROOT"

exec "$GUNICORN" app:app --bind "0.0.0.0:${PORT:-5000}" --workers 3 --threads 4
