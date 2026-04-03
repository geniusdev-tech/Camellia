#!/usr/bin/env sh
set -euo pipefail

cd frontend

echo "Checking git status for frontend..."
git status -sb

echo "Showing diff for package-lock.json"
git diff -- package-lock.json

echo "Adding package-lock.json to staging..."
git add package-lock.json

echo "Committing lockfile..."
git commit -m "sync npm lock"

echo "Pushing to origin/main..."
git push origin main

echo "Done."
