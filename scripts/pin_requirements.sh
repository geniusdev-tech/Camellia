#!/usr/bin/env bash
# Gera um arquivo requirements-pinned.txt a partir do ambiente atual
set -euo pipefail
if [ -z "${VIRTUAL_ENV:-}" ]; then
  echo "Ative seu virtualenv antes de rodar: python -m venv .venv && source .venv/bin/activate"
  exit 1
fi
python -m pip install --upgrade pip
python -m pip freeze > requirements-pinned.txt
echo "Gerado requirements-pinned.txt"
