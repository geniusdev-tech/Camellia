# ─────────────────────────────────────────────────────
#  GateStack — Build Automation
# ─────────────────────────────────────────────────────
.PHONY: help dev build build-win build-mac build-linux \
        install install-backend install-node \
        bundle-backend clean docker-up docker-down docker-logs db-migrate db-seed

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
	@echo "  make install        — instala dependências (backend TS + frontend + Rust)"
	@echo "  make dev            — inicia backend Node/TS na 5000 + Next.js na 3000"
	@echo "  make build          — empacota para o SO atual (Tauri + Next.js)"
	@echo "  make build-win      — cross-compila para Windows (requer cross + MSVC)"
	@echo "  make build-mac      — build macOS (requer XCode CLI + Codesign)"
	@echo "  make build-linux    — build Linux (.deb, .rpm, .AppImage)"
	@echo "  make bundle-backend — build do backend Node/TS para produção"
	@echo "  make docker-up      — sobe stack completa Docker (backend, postgres, redis, nginx, prometheus, grafana)"
	@echo "  make docker-down    — derruba stack Docker"
	@echo "  make docker-logs    — acompanha logs da stack Docker"
	@echo "  make db-migrate     — aplica migrações Prisma no DATABASE_URL"
	@echo "  make db-seed        — executa seed Prisma no DATABASE_URL"
	@echo "  make clean          — remove artefatos de build"
	@echo ""

# ── Install ───────────────────────────────────────────
install: install-backend install-node
	@echo "✓ Todas as dependências instaladas."

install-backend:
	cd backend && $(NPM) install

install-node:
	cd frontend && $(NPM) ci

# ── Development ───────────────────────────────────────
dev:
	@echo "→ Iniciando backend Node/TS na porta 5000 e Next.js na porta 3000…"
	@set -e; \
	backend_pid=""; \
	cleanup() { \
		if [ -n "$$backend_pid" ]; then \
			kill "$$backend_pid" 2>/dev/null || true; \
			wait "$$backend_pid" 2>/dev/null || true; \
		fi; \
	}; \
	trap cleanup EXIT INT TERM; \
	NODE_ENV=development DESKTOP_MODE=1 PORT=$(PORT) $(NPM) --prefix backend run dev & \
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
	NODE_ENV=development DESKTOP_MODE=1 PORT=$(PORT) $(NPM) --prefix backend run dev & \
	backend_pid=$$!; \
	PORT=$(PORT) $(TAURI) dev --config src-tauri/tauri.conf.json

# ── Bundle backend TS ─────────────────────────────────
bundle-backend:
	@echo "→ Compilando backend TypeScript…"
	cd backend && $(NPM) run build
	@echo "✓ backend/dist atualizado."

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
	rm -rf build dist
	rm -rf backend/dist
	rm -rf frontend/.next frontend/out
	rm -rf src-tauri/target
	@echo "✓ Limpeza concluída."

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down

docker-logs:
	docker compose logs -f

db-migrate:
	npm --prefix backend run prisma:migrate:deploy

db-seed:
	npm --prefix backend run prisma:seed
