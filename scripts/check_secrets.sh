#!/usr/bin/env bash
# Quick scan for potential secrets in the working tree (not exhaustive).
set -euo pipefail

echo "Running quick secrets scan..."

patterns=("SECRET_KEY" "AWS_SECRET" "AWS_ACCESS" "AWS_KMS" "PRIVATE KEY" "-----BEGIN PRIVATE KEY" "PASSWORD" "token=" "api_key" "apikey")

found=0
for p in "${patterns[@]}"; do
  echo "Searching for pattern: $p"
  if grep -R --line-number --exclude-dir=.git -I "$p" . | sed -n '1,200p'; then
    found=1
  fi
done

if [ "$found" -eq 1 ]; then
  echo "Potential secrets found. Inspect results above. Do NOT push secrets to remote." >&2
  exit 2
else
  echo "No obvious patterns found. This is NOT a guarantee—use detect-secrets or trufflehog for deeper scans."
fi
