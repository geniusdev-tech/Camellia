# ─────────────────────────────────────────────────────
#  GateStack — Build Automation
# ─────────────────────────────────────────────────────
.PHONY: help dev build build-win build-mac build-linux \
        install install-py install-node \
        bundle-backend db-migrate db-revision clean

VENV_DIR ?= .venv
PYTHON   ?= $(if $(wildcard $(VENV_DIR)/bin/python),$(VENV_DIR)/bin/python,python3)
NPM      ?= npm
CARGO    ?= cargo
TAURI    ?= npx --prefix frontend tauri
PORT     ?= 5000
HOST_TRIPLE ?= $(shell $(CARGO) -vV | sed -n 's/^host: //p')
NODE_ENV ?= production

# ── Help ──────────────────────────────────────────────
help:
	@echo ""
	@echo "  GateStack — Comandos disponíveis:"
	@echo ""
	@echo "  make install        — instala todas as dependências (Python + Node + Rust)"
	@echo "  make dev            — inicia Next.js dev + Flask API side-by-side"
	@echo "  make build          — empacota para o SO atual (Tauri + Next.js)"
	@echo "  make build-win      — cross-compila para Windows (requer cross + MSVC)"
	@echo "  make build-mac      — build macOS (requer XCode CLI + Codesign)"
	@echo "  make build-linux    — build Linux (.deb, .rpm, .AppImage)"
	@echo "  make bundle-backend — cria executável Python (PyInstaller)"
	@echo "  make db-migrate     — aplica migrações Alembic"
	@echo "  make db-revision    — cria revisão Alembic autogerada (MSG=...)"
	@echo "  make clean          — remove artefatos de build"
	@echo ""

# ── Install ───────────────────────────────────────────
install: install-py install-node
	@echo "✓ Todas as dependências instaladas."

install-py:
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -r requirements.txt
	$(PYTHON) -m pip install pyinstaller

install-node:
	cd frontend && $(NPM) ci

# ── Development ───────────────────────────────────────
dev:
	@echo "→ Iniciando Flask na porta 5000 e Next.js na porta 3000…"
	@set -e; \
	backend_pid=""; \
	cleanup() { \
		if [ -n "$$backend_pid" ]; then \
			kill "$$backend_pid" 2>/dev/null || true; \
			wait "$$backend_pid" 2>/dev/null || true; \
		fi; \
	}; \
	trap cleanup EXIT INT TERM; \
	FLASK_ENV=development FLASK_DEBUG=1 DESKTOP_MODE=1 PORT=$(PORT) $(PYTHON) app.py & \
	backend_pid=$$!; \
	cd frontend && $(NPM) run dev

dev-tauri:
	@echo "→ Iniciando Tauri em modo dev…"
	@set -e; \
	backend_pid=""; \
	cleanup() { \
		if [ -n "$$backend_pid" ]; then \
			kill "$$backend_pid" 2>/dev/null || true; \
			wait "$$backend_pid" 2>/dev/null || true; \
		fi; \
	}; \
	trap cleanup EXIT INT TERM; \
	FLASK_ENV=development DESKTOP_MODE=1 PORT=$(PORT) $(PYTHON) app.py & \
	backend_pid=$$!; \
	PORT=$(PORT) $(TAURI) dev --config src-tauri/tauri.conf.json

# ── Bundle Python backend → single binary ─────────────
bundle-backend:
	@echo "→ Empacotando backend Python com PyInstaller…"
	$(PYTHON) -m PyInstaller \
	    --onefile \
	    --name gatestack-backend \
	    --add-data "core:core" \
	    --add-data "api:api" \
	    --add-data "config.py:." \
	    --hidden-import argon2 \
	    --hidden-import sqlalchemy \
	    --hidden-import flask_talisman \
	    --hidden-import flask_seasurf \
	    --hidden-import flask_limiter \
	    --distpath src-tauri/binaries \
	    app.py
	@if [ -n "$(HOST_TRIPLE)" ] && [ -f src-tauri/binaries/gatestack-backend ]; then \
		cp src-tauri/binaries/gatestack-backend src-tauri/binaries/gatestack-backend-$(HOST_TRIPLE); \
	fi
	@echo "✓ src-tauri/binaries/gatestack-backend criado."

db-migrate:
	$(PYTHON) -m alembic upgrade head

db-revision:
	@test -n "$(MSG)" || (echo "Use MSG='descricao-da-migracao'"; exit 1)
	$(PYTHON) -m alembic revision --autogenerate -m "$(MSG)"

# ── Tauri build helpers ────────────────────────────────
_tauri-build-prep: bundle-backend

build: _tauri-build-prep
	$(TAURI) build --config src-tauri/tauri.conf.json

build-linux: _tauri-build-prep
	$(TAURI) build --config src-tauri/tauri.conf.json --target x86_64-unknown-linux-gnu

build-win: _tauri-build-prep
	$(TAURI) build --config src-tauri/tauri.conf.json --target x86_64-pc-windows-msvc

build-mac: _tauri-build-prep
	$(TAURI) build --config src-tauri/tauri.conf.json --target universal-apple-darwin

# ── Clean ─────────────────────────────────────────────
clean:
	rm -rf build dist __pycache__ *.spec
	rm -rf frontend/.next frontend/out
	rm -rf src-tauri/target
	rm -f src-tauri/binaries/gatestack-backend
	rm -f src-tauri/binaries/gatestack-backend-*
	rm -f src-tauri/binaries/gatestack-backend.exe
	@echo "✓ Limpeza concluída."
