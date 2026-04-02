# ─────────────────────────────────────────────────────
#  Camellia Shield — Build Automation
# ─────────────────────────────────────────────────────
.PHONY: help dev build build-win build-mac build-linux \
        install install-py install-node \
        bundle-backend clean docs

PYTHON   ?= python3
NPM      ?= npm
CARGO    ?= cargo
TAURI    ?= npx tauri
NODE_ENV ?= production

# ── Help ──────────────────────────────────────────────
help:
	@echo ""
	@echo "  Camellia Shield — Comandos disponíveis:"
	@echo ""
	@echo "  make install        — instala todas as dependências (Python + Node + Rust)"
	@echo "  make dev            — inicia Next.js dev + Flask API side-by-side"
	@echo "  make build          — empacota para o SO atual (Tauri + Next.js)"
	@echo "  make build-win      — cross-compila para Windows (requer cross + MSVC)"
	@echo "  make build-mac      — build macOS (requer XCode CLI + Codesign)"
	@echo "  make build-linux    — build Linux (.deb, .rpm, .AppImage)"
	@echo "  make bundle-backend — cria executável Python (PyInstaller)"
	@echo "  make docs           — gera guias do usuário em HTML"
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
	FLASK_ENV=development FLASK_DEBUG=1 DESKTOP_MODE=1 \
	    $(PYTHON) app.py & \
	cd frontend && $(NPM) run dev

dev-tauri:
	@echo "→ Iniciando Tauri em modo dev…"
	FLASK_ENV=development DESKTOP_MODE=1 $(PYTHON) app.py & \
	cd frontend && $(TAURI) dev

# ── Bundle Python backend → single binary ─────────────
bundle-backend:
	@echo "→ Empacotando backend Python com PyInstaller…"
	$(PYTHON) -m PyInstaller \
	    --onefile \
	    --name camellia-backend \
	    --add-data "core:core" \
	    --add-data "api:api" \
	    --add-data "config.py:." \
	    --add-data "services.py:." \
	    --hidden-import cryptography \
	    --hidden-import argon2 \
	    --hidden-import sqlalchemy \
	    --hidden-import flask_talisman \
	    --hidden-import flask_seasurf \
	    --hidden-import flask_limiter \
	    --hidden-import pynacl \
	    --distpath src-tauri/binaries \
	    app.py
	@echo "✓ src-tauri/binaries/camellia-backend criado."

# ── Tauri build helpers ────────────────────────────────
_tauri-build-prep: bundle-backend docs
	mkdir -p src-tauri/resources/docs
	cp -r docs/user-guide/. src-tauri/resources/docs/

build: _tauri-build-prep
	cd frontend && $(TAURI) build

build-linux: _tauri-build-prep
	cd frontend && $(TAURI) build --target x86_64-unknown-linux-gnu

build-win: _tauri-build-prep
	cd frontend && $(TAURI) build --target x86_64-pc-windows-msvc

build-mac: _tauri-build-prep
	cd frontend && $(TAURI) build --target universal-apple-darwin

# ── Docs generation ───────────────────────────────────
docs:
	@echo "→ Gerando guias do usuário…"
	mkdir -p docs/user-guide
	$(PYTHON) scripts/generate_docs.py
	@echo "✓ Guias gerados em docs/user-guide/"

# ── Clean ─────────────────────────────────────────────
clean:
	rm -rf build dist __pycache__ *.spec
	rm -rf frontend/.next frontend/out
	rm -rf src-tauri/target
	rm -f src-tauri/binaries/camellia-backend
	rm -f src-tauri/binaries/camellia-backend.exe
	@echo "✓ Limpeza concluída."
