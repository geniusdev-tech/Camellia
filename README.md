# GateStack

Backend agora padronizado em **NestJS + Prisma + PostgreSQL + Zod + BullMQ/Redis**, com observabilidade em **Pino + Prometheus + Grafana** e infra com **Docker + Nginx**.

`QUEUE_ENABLED` e `QUEUE_WORKER_ENABLED` ficam desabilitados por padrao em ambiente local (fail-open) para evitar falha da API quando Redis estiver indisponivel ou com credencial incorreta.

## Stack

- Backend: NestJS (TypeScript)
- ORM: Prisma
- Banco: PostgreSQL
- Filas: BullMQ + Redis
- Validação: Zod
- Logging: Pino (`nestjs-pino`)
- Métricas: Prometheus (`/metrics`)
- Dashboard: Grafana
- Dev tools: `tsx`, ESLint, Prettier
- Testes: Jest + Playwright

## Backend local

```bash
npm --prefix backend install
npm --prefix backend run prisma:generate
npm --prefix backend run dev
```

API principal:

- `POST /api/auth/login`
- `GET /health`
- `GET /api/releases`
- `POST /api/releases`
- `POST /api/releases/:releaseId/publish`
- `POST /api/releases/:releaseId/rollback`
- `GET /metrics` (protegido por token)

## Infra completa (Docker)

```bash
docker compose up --build
```

Serviços:

- Backend: `http://localhost:5000`
- Nginx (reverse proxy): `http://localhost`
- PostgreSQL: `localhost:5432`
- Redis: `localhost:6379`
- Prometheus: `http://localhost:9090`
- Grafana: `http://localhost:3001`

Grafana já sobe com:

- datasource Prometheus provisionado automaticamente
- dashboard `GateStack Overview` provisionado automaticamente

## Segurança aplicada

- JWT + RBAC (`admin`, `writer`, `reader`)
- hardening com `helmet`
- rate limiting global com `@nestjs/throttler`
- endpoint `/metrics` protegido por `METRICS_TOKEN`
- Snyk com bloqueio por severidade alta no CI
- Prometheus configurado para enviar token bearer em `infra/prometheus/prometheus.yml`

## Prisma

```bash
npm --prefix backend run prisma:migrate:dev
npm --prefix backend run prisma:generate
npm --prefix backend run prisma:migrate:deploy
npm --prefix backend run prisma:seed
```

Login inicial:

- usa `ADMIN_EMAIL` e `ADMIN_PASSWORD` configurados no ambiente
- usuário admin é criado/atualizado automaticamente no bootstrap

## Qualidade

```bash
npm --prefix backend run lint
npm --prefix backend run type-check
npm --prefix backend run test
npm --prefix backend run test:e2e
```
