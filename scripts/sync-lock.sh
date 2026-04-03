#!/usr/bin/env bash
set -euo pipefail

export GIT_PAGER=cat

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$REPO_ROOT/frontend"

echo "Checking git status for frontend..."
git status -sb

echo "Showing diff for package-lock.json"
git -c core.pager=cat diff -- package-lock.json

echo "Adding package-lock.json to staging..."
git add package-lock.json

echo "Committing lockfile..."
git commit -m "sync npm lock"

echo "Pushing to origin/main..."
git push origin main

echo "Done."
