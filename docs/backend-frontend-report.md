# Relatorio Tecnico do Backend e Impacto no Frontend

## Atualizacao 2026-04-05 (GitHub OAuth + Comunidade/Repos)

### Escopo concluido

- Login com GitHub via OAuth implementado no backend:
  - `GET /api/auth/github`
  - `GET /api/auth/github/callback`
- Persistencia de dados do GitHub no `User`:
  - `githubId`, `name`, `avatarUrl`, `githubToken`
  - `passwordHash` agora opcional para suportar login social
- Cache de repositorios GitHub no banco:
  - tabela `github_repositories`
  - endpoint autenticado `GET /api/github/repos`
  - endpoint autenticado `POST /api/github/repos/sync`
- Frontend atualizado para experiencia de comunidade/repositorios:
  - botao "Continuar com GitHub" no login
  - captura de token via query string no retorno do callback
  - tratamento de erro OAuth no login
  - avatar real e nome do GitHub no layout autenticado
  - secoes de repositorios GitHub no dashboard e na pagina `/repository`

### Migracao e banco de dados

- Nova migracao criada e aplicada:
  - `backend/prisma/migrations/20260405103000_github_oauth_and_repos/migration.sql`
- Estado atual: migracoes aplicadas com sucesso no PostgreSQL local.

### Configuracao de ambiente

- Variaveis documentadas em `.env.example`:
  - `GITHUB_CLIENT_ID`
  - `GITHUB_CLIENT_SECRET`
  - `GITHUB_CALLBACK_URL`
- Validacao de env reforcada:
  - se qualquer variavel GitHub estiver setada, as 3 devem estar setadas.

### Validacao tecnica recente

Backend:

- `npm --prefix backend run type-check` ✅
- `npm --prefix backend run prisma:migrate:deploy` ✅
- `npm --prefix backend run test -- auth.controller.github.spec.ts secret-crypto.spec.ts` ✅

Frontend:

- `npm --prefix frontend run type-check` ✅

### Observacao operacional (frontend local)

Para fluxo local com frontend em `http://localhost:3000`:

- manter `ALLOWED_ORIGIN=http://localhost:3000,http://127.0.0.1:3000`
- manter callback OAuth no backend conforme app GitHub
- backend redireciona para `/login?oauth=success` no frontend local

### Mitigacoes de seguranca aplicadas

- Remocao de token JWT da query string no callback OAuth:
  - callback agora usa cookie temporario `httpOnly` e redireciona com `?oauth=success`
  - endpoint de troca: `GET /api/auth/github/session`
- Token de acesso do GitHub agora protegido em repouso:
  - criptografia simetrica AES-GCM (`v1`) antes de persistir em `users.github_token`
  - leitura com fallback para legado nao criptografado
- Cache de repositorios GitHub corrigido para escopo por usuario:
  - chave unica composta (`user_id`, `github_id`)
  - permite mesmo repo aparecer em contas diferentes sem colisao

## Estado Atual (Atualizado)

Backend consolidado em **Node.js + TypeScript** com arquitetura NestJS.

Stack principal:

- `backend/nest-src/main.ts`: bootstrap Nest + Helmet + CORS + logger Pino
- `backend/nest-src/app.module.ts`: modulos de Auth, Releases, Metrics, Queue, Prisma
- `backend/prisma/schema.prisma`: modelo de dados (User, Release)
- `backend/prisma/migrations/*`: migracoes PostgreSQL
- `backend/nest-src/modules/queue/*`: BullMQ + Redis para scan/publish/rollback/DLQ
- `frontend/src/lib/api.ts`: cliente HTTP mantendo contrato de API

## Acoes Estrategicas Implementadas

1. Seguranca de supply chain
- Pipeline com scan de vulnerabilidade e bloqueio por policy (Snyk)
- Base pronta para assinatura e SBOM no fluxo de release (camada de jobs/eventos)

2. Policy engine
- Regras por contexto com `PUBLISH_MAX_CVSS`
- Fluxo de aprovacao por estagio de ambiente (`dev`, `staging`, `prod`)
- Eventos de auditoria preservados no fluxo de release

3. Distribuicao inteligente
- Canais de release: `alpha`, `beta`, `stable`
- Jobs dedicados para publish progressivo e rollback
- Estrutura pronta para extensao de espelhamento/cache regional

4. Integracao de ecossistema
- Eventos de dominio via fila (scan/publish/rollback/falha)
- CI ajustado para backend Node/TS only
- Base de autenticacao pronta para evolucao com SSO/OIDC + SCIM

5. Diferencial alem do GitHub
- Campos de compliance e risco por versao (`complianceScore`, `riskScore`, `maxCvss`)
- Base para recomendacao de versao segura por time/produto

## Qualidade e Testes

- Lint/type-check/build funcionando no backend.
- E2E reestruturado para padrao profissional:
  - sem `app.listen()`
  - sem `localhost`/`127.0.0.1`
  - com `await app.init()`
  - com `Supertest` + `app.getHttpServer()`
- Arquivos E2E atualizados:
  - `backend/test/e2e/setup.ts`
  - `backend/test/e2e/app.e2e-spec.ts`

## Compatibilidade Frontend

O frontend continua compativel com os contratos principais de resposta (`success`, objetos de dominio e listagens), sem necessidade de reescrita estrutural das telas existentes.

## Expansao Social (Backend + Banco)

Foi adicionada uma camada social completa para suportar os blocos de feed exibidos no frontend.

### Novas entidades Prisma

- `ReactionType` (`like`, `insight`, `celebrate`)
- `SocialPost`
- `SocialReaction`
- `SocialComment`
- `SocialBookmark`
- `SocialRepost`
- `SocialCommunity`
- `SocialCommunityMember`

Arquivos-chave:

- `backend/prisma/schema.prisma`
- `backend/prisma/migrations/20260404071000_social_features/migration.sql`

### Modulo NestJS social

- `backend/nest-src/modules/social/social.module.ts`
- `backend/nest-src/modules/social/social.controller.ts`
- `backend/nest-src/modules/social/social.service.ts`
- `backend/nest-src/modules/social/social.schemas.ts`
- Integrado em `backend/nest-src/app.module.ts`

### Endpoints sociais autenticados

- `GET /api/social/feed`
- `GET /api/social/sidebar`
- `POST /api/social/posts/:postId/reaction`
- `POST /api/social/posts/:postId/comment`
- `POST /api/social/posts/:postId/bookmark`
- `POST /api/social/posts/:postId/repost`
- `POST /api/social/communities/:communityId/toggle`

### Comportamento implementado

1. Feed sincronizado com releases
- Cada `Release` gera/usa um `SocialPost` correspondente.
- O feed agrega contadores de reacao/comentario/repost/bookmark.
- Retorna estado do viewer autenticado (reacao atual, bookmark, repost).

2. Sidebar social dinamica
- Comunidades com estado `joined` por usuario.
- Tendencias calculadas a partir de nomes de pacote.
- Sugestoes de usuarios com base nos usuarios mais recentes (exceto o viewer).

3. Seed social inicial
- Comunidades padrao adicionadas no `seed.mjs`:
  - `security-watch`
  - `release-ops`
  - `team-hub`
- Posts iniciais sincronizados para releases existentes.

## Integracao Frontend com Social API

### Cliente HTTP e tipos

- Tipos adicionados em `frontend/src/lib/types.ts`:
  - `SocialFeedPost`, `SocialFeedResponse`
  - `SocialSidebarResponse`
  - `SocialReactionType` e modelos de sidebar
- Cliente `socialAPI` adicionado em `frontend/src/lib/api.ts`

### Dashboard conectado ao backend

- `frontend/src/app/(app)/dashboard/page.tsx` convertido para `use client`.
- Busca dados reais via React Query:
  - `socialAPI.feed()`
  - `socialAPI.sidebar()`
- Acoes conectadas:
  - reagir (`like`/`insight`)
  - comentar (acao rapida)
  - bookmark toggle
  - repost toggle
  - entrar/sair de comunidade

### Resultado pratico

- Os cards sociais do dashboard deixaram de ser apenas placeholder.
- Contadores e estado do usuario agora refletem dados persistidos no PostgreSQL.
- O layout social continua compativel com os modulos de dominio existentes (`releases`, `teams`, `ops`, `catalog`).

## Validacao Tecnica Executada

Backend:

- `npm --prefix backend run prisma:generate` ✅
- `npm --prefix backend run build` ✅
- `npm --prefix backend run type-check` ✅
- `npm --prefix backend run lint` ✅

Frontend:

- `npm --prefix frontend run type-check` ✅

## Proximo passo recomendado

1. Aplicar migracao em producao (`prisma migrate deploy`) no deploy do backend.
2. Validar fluxo social ponta-a-ponta com usuario autenticado:
- feed carregando releases reais
- toggle de reacoes/bookmarks/reposts
- comunidades entrando/saindo
3. Expandir comentario social para composer livre no frontend (atualmente acao rapida).
