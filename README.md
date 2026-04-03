# GateStack

GateStack e uma plataforma de repositório com backend Flask e frontend Next.js/Tauri. O produto hoje cobre autenticação, MFA, auditoria, workflow de releases, ACL por usuário e por time, jobs assíncronos, métricas operacionais e catálogo público de pacotes.

## O que o projeto entrega hoje

- autenticação com email/senha, MFA TOTP, refresh rotativo e logout global
- upload de pacotes `.zip` com checksum, validação estrutural, deduplicação e metadata
- workflow formal de release: `draft`, `submitted`, `approved`, `published`, `archived`, `rejected`
- compartilhamento por usuário e por time
- convites de time
- signed URLs para download interno e público
- jobs assíncronos para scan e publish
- métricas por rota e `request_id`
- auditoria de eventos
- frontend organizado por domínio: repositório, times, operações, catálogo e conta
- shell desktop com Tauri

## Arquitetura

### Backend

- [app.py](/home/zeus/Documentos/camellia-shield/app.py): bootstrap Flask
- [api/auth.py](/home/zeus/Documentos/camellia-shield/api/auth.py): login, MFA, refresh, logout
- [api/projects.py](/home/zeus/Documentos/camellia-shield/api/projects.py): repositório, workflow e API pública
- [api/access.py](/home/zeus/Documentos/camellia-shield/api/access.py): times, convites e grants
- [api/ops.py](/home/zeus/Documentos/camellia-shield/api/ops.py): jobs e métricas
- [core/iam/models.py](/home/zeus/Documentos/camellia-shield/core/iam/models.py): modelos principais
- [core/async_jobs.py](/home/zeus/Documentos/camellia-shield/core/async_jobs.py): worker local
- [core/observability.py](/home/zeus/Documentos/camellia-shield/core/observability.py): métricas e headers

### Frontend

- [frontend/src/app/(app)/dashboard/page.tsx](/home/zeus/Documentos/camellia-shield/frontend/src/app/(app)/dashboard/page.tsx): overview
- [frontend/src/app/(app)/repository/page.tsx](/home/zeus/Documentos/camellia-shield/frontend/src/app/(app)/repository/page.tsx): lista e upload
- [frontend/src/app/(app)/repository/[projectId]/page.tsx](/home/zeus/Documentos/camellia-shield/frontend/src/app/(app)/repository/[projectId]/page.tsx): detalhe profundo do release
- [frontend/src/app/(app)/teams/page.tsx](/home/zeus/Documentos/camellia-shield/frontend/src/app/(app)/teams/page.tsx): times, convites e grants
- [frontend/src/app/(app)/ops/page.tsx](/home/zeus/Documentos/camellia-shield/frontend/src/app/(app)/ops/page.tsx): jobs e métricas
- [frontend/src/app/(app)/catalog/page.tsx](/home/zeus/Documentos/camellia-shield/frontend/src/app/(app)/catalog/page.tsx): catálogo público
- [frontend/src/app/(app)/settings/page.tsx](/home/zeus/Documentos/camellia-shield/frontend/src/app/(app)/settings/page.tsx): conta, MFA e auditoria

## Pré-requisitos

- Python 3.12+ (o backend Flask e o empacotamento com `PyInstaller` rodam dentro de `python -m venv .venv`)
- Node 20+ com `npm`/`npx` (Next.js + Tauri WebView)
- Rust toolchain **stable** com `cargo` e `rustup` (necessário para Tauri dev/build e `npx --prefix frontend tauri`)
- Tauri CLI (`@tauri-apps/cli`) disponível globalmente ou via `npx --prefix frontend tauri`
- Projeto Supabase com bucket configurado para armazenamento de uploads (`SUPABASE_URL`, `SUPABASE_BUCKET`, `SUPABASE_SERVICE_KEY`)

### Configuração local recomendada

1. `python3 -m venv .venv` e, sempre que for trabalhar, rode `source .venv/bin/activate`.
2. `make install` (ou `make install-py && cd frontend && npm ci`) instala Python, Node e dependências Rust necessárias para builds.
3. `make dev` sobe o Flask e o Next.js side-by-side; o `trap cleanup` no Makefile garante que o backend seja finalizado junto com o `npm run dev`.
4. `make dev-tauri` roda Flask + Tauri dev server; ele também usa um `trap` para evitar processos órfãos quando você abortar o comando.
5. Para builds do desktop use `make bundle-backend` (PyInstaller) seguido de `make build` (Tauri + Next estático). Garanta que o `rustup` esteja apontado para `stable` e que o target desejado esteja instalado (`rustup target add x86_64-unknown-linux-gnu`, por exemplo).

### Variáveis de ambiente obrigatórias e convenções

| Variável | Obrigatória | Notas |
| --- | --- | --- |
| `SECRET_KEY` | ✅ em produção | Chave do Flask/JWT. Em dev/desktop é gerada automaticamente (`app.py`). |
| `DATABASE_URL`, `IAM_DATABASE_URL` ou `POSTGRES_URL` | ✅ em ambientes externos | Define o banco SQLAlchemy. Sem um valor usa `sqlite:///gatestack-dev.db`. |
| `IAM_DB_PATH` | ❌ | Override para o arquivo SQLite/local. |
| `SUPABASE_URL`, `SUPABASE_SERVICE_KEY`, `SUPABASE_BUCKET` | ✅ | Usado por `api/projects.upload` e `utils/supabase_storage.py`. |
| `GATESTACK_DEV_EMAIL` / `GATESTACK_DEV_PASSWORD` | ✅ no dev | Semente um owner local se o DB não tem admin. Dev padrão (sem env) funciona apenas em `FLASK_ENV=development` fora de ambientes serverless. |
| `PORT` | ❌ (default 5000) | Porta do Flask; o desktop escolhe automaticamente quando não definido. |
| `HOST` | ❌ (default 127.0.0.1) | Bind do Flask (`app.run`). |
| `FLASK_ENV`, `FLASK_DEBUG` | ❌ | Controle comportamento (debug, recursos de segurança e CSRF). |
| `DESKTOP_MODE` | ❌ | Define recursos liberados para o Tauri bundle. É marcado como `1` pelo runtime desktop. |
| `ALLOWED_ORIGIN` | ❌ (necessário fora de Tauri/dev) | Lista separada por vírgula usada pelo middleware CORS. |
| `AUDIT_LOG_PATH` | ❌ (`./audit.log`) | Caminho do log de auditoria escrito por `core.audit.logger`. |
| `SIEM_ENDPOINT` | ❌ | Endpoint externo para `configure_json_logging`. |
| `GATESTACK_ASYNC_WORKER` | ❌ (`1`) | `core.async_jobs.start_async_job_worker()` respeita `0` para desabilitar o worker local. |
| `GATESTACK_ASYNC_POLL_SECONDS` | ❌ (`0.5`) | Polling interval para o worker assíncrono. |
| `SESSION_LIFETIME` | ❌ (`300`) | Tempo em segundos para cookies de sessão (`config.py`). |
| `REDIS_URL` | ❌ | Host Redis para rate limiting e sessões compartilhadas (`redis.from_url`). |
| `LIMITER_STORAGE_URI` | ❌ | Força o `Flask-Limiter` a usar Redis ou outro storage; cai para `REDIS_URL` se não definido. |

Além das variáveis acima, o desktop precisa encontrar o binário `gatestack-backend` dentro de `src-tauri/binaries/` e ler o log em `/tmp/gatestack-desktop.log` (ou `*-dev.log` em debug).

## Instalação

```bash
python3 -m venv .venv
source .venv/bin/activate
make install
```

## Desenvolvimento

### Stack web local

```bash
make dev
```

Isso sobe:

- backend Flask em `http://127.0.0.1:5000`
- frontend Next em `http://127.0.0.1:3000`

### Desktop

```bash
make dev-tauri
```

Isso sobe:

- backend Flask
- frontend Next
- shell Tauri usando [src-tauri/tauri.conf.json](/home/zeus/Documentos/camellia-shield/src-tauri/tauri.conf.json)

### Frontend isolado

```bash
cd frontend
npm run dev
```

### Backend isolado

```bash
source .venv/bin/activate
python app.py
```

## Build e empacotamento

```bash
make bundle-backend
make build
```

No Render (ou em qualquer deploy onde PyInstaller falha porque o Python não foi compilado com `--enable-shared`) Ignore o bundle e use `./scripts/start-server.sh` (gunicorn) definido no `render.yaml`. O backend roda diretamente o Flask, enquanto o empacotamento continua sendo usado apenas para lançamentos desktop.

- `make bundle-backend`: gera o binário Python em `src-tauri/binaries/`
- `make build`: build desktop Tauri
- `make db-migrate`: aplica migrações Alembic
- `make db-revision MSG="descricao"`: cria revisão nova

### Deploy com Fly.io

Para quem quer controlar o runtime completo (Python com biblioteca compartilhada) e rodar o frontend/backend no mesmo container, o `Dockerfile` deste repositório já é compatível com [Fly.io](https://fly.io). Ele:

1. Usa `node:20-alpine` para compilar o Next.js (`npm ci`, `npm run build`).  
2. Baseia o runtime em `python:3.12-slim-bullseye` com `libpq`, `alembic`, `gunicorn` e `redis`.  
3. Copia a saída `frontend/out` para `static/dist` e executa `./scripts/start-server.sh` para subir `gunicorn app:app --bind 0.0.0.0:$PORT`.

Passos rápidos:

a. Instale o CLI (`curl -L https://fly.io/install.sh | sh`), faça login (`flyctl auth login`) e crie o app (`flyctl launch`).  
b. Configure secrets no Fly (`flyctl secrets set SECRET_KEY=... DATABASE_URL=... SUPABASE_BUCKET=... REDIS_URL=...`).  
c. Deploy: `flyctl deploy --config fly.toml`.

O mesmo container pode ser usado para os jobs (`flyctl scale memory`/`flyctl scale count`) e o banco PostgreSQL/Redis pode ficar dentro da infraestrutura da Fly ou ser apontado para Supabase/Neon.
- `make build`: build desktop Tauri
- `make db-migrate`: aplica migrações Alembic
- `make db-revision MSG="descricao"`: cria revisão nova

## Testes e validações

### Backend

```bash
source .venv/bin/activate
python -m compileall app.py api core utils tests
pytest -q tests/test_repository_api.py
```

### Frontend

```bash
cd frontend
npm run type-check
npm test
npm run test:e2e
```

Observação:

- `npm test` roda Vitest
- `npm run test:e2e` usa Playwright e depende do ambiente de browser estar pronto

## Fluxos suportados

### Repositório

- upload de `.zip`
- checksum SHA-256
- deduplicação
- metadata e changelog
- workflow de status
- histórico de transições
- version matrix
- signed download

### Compartilhamento

- grants por usuário
- grants por time
- convites de time
- acesso público, privado e compartilhado

### Operações

- enfileirar scan
- enfileirar publish async
- listar jobs
- ver métricas por rota

### Catálogo público

- listar pacotes públicos
- ver `latest`
- ver versão específica
- gerar signed URL de download

## Observabilidade

O backend hoje expõe:

- `X-Request-Id`
- `X-Response-Time-Ms`
- métricas em `/api/ops/metrics`
- auditoria em arquivo e painel

O desktop também grava logs de runtime em `/tmp/gatestack-desktop*.log`.

## Estrutura resumida do repositório

- `api/`: endpoints REST
- `core/`: IAM, jobs, auditoria, observabilidade
- `frontend/`: cliente Next.js
- `src-tauri/`: shell desktop
- `utils/`: integrações como Supabase
- `alembic/`: migrações formais
- `tests/`: testes backend

## Documentação complementar

- relatório técnico atualizado: [backend-frontend-report.md](/home/zeus/Documentos/camellia-shield/docs/backend-frontend-report.md)

## Estado atual

Hoje o projeto já não é apenas um upload manager. Ele funciona como base real de uma plataforma de repositório com:

- backend de produto
- frontend operacional
- testes de backend e frontend
- scaffold de E2E
- distribuição desktop

Os próximos passos mais naturais agora são:

1. ampliar E2E
2. endurecer a11y e mobile
3. adicionar analytics visuais melhores
4. integrar validações e testes no CI
