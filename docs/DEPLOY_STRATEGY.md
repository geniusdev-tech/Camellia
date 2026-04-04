# Estratégia de Deploy - Backend, Frontend e Banco de Dados

## 🏗️ Arquitetura Atual

```
Seu Notebook (Local)
├── PostgreSQL + Redis (dados)
├── Backend NestJS (em desenvolvimento)
└── Frontend Next.js (em desenvolvimento)

Deploy Planejado:
├── Backend: Render.com (ou Railway/Fly.io)
├── Frontend: Firebase Hosting
└── Database: ❓ (Este é o ponto crítico!)
```

---

## ⚠️ Problema Principal

**Não recomendado:** Expor seu PostgreSQL local na internet sem uma camada de segurança adequada.

**Razões:**
- PostgreSQL na porta 5432 exposto é alvo de ataques
- Conexão sem tunnel/VPN é insegura
- IP dinâmico do notebook causa instabilidade

---

## ✅ OPÇÃO 1: Database Remoto (RECOMENDADO)

Migrar o banco de dados para um serviço gerenciado na nuvem.

### 1.1 Usando Render PostgreSQL (mais simples)

**Passos:**

1. **Criar banco no Render:**
   ```
   Dashboard Render.com → New+ → PostgreSQL
   - Plan: Starter (gratuito com limitações) ou Starter Plus
   - Region: us-east
   - Name: gatestack-db
   ```

2. **Atualizar render.yaml:**
   ```yaml
   services:
     - type: web
       name: gatestack-backend
       env: docker
       envVars:
         - key: DATABASE_URL
           sync: false  # ← Importante: não sincronizar
   
   databases:
     - name: gatestack-db
       databaseName: gatestack
       user: gatestack
       region: us-east
   ```

3. **Render gerará automaticamente DATABASE_URL com acesso seguro**

4. **Executar migrations no Render:**
   ```bash
   # No render.yaml, adicionar pre-deploy script:
   preDeployCommand: npm run prisma:migrate:deploy
   ```

5. **Configurar no Firebase (frontend):**
   ```bash
   # .env.local (local testing)
   NEXT_PUBLIC_API_BASE_URL=http://localhost:5000
   
   # .env.production (production)
   NEXT_PUBLIC_API_BASE_URL=https://seu-backend.onrender.com
   ```

**Custo:** ~$7-15/mês (PostgreSQL) + ~$7-12/mês (Backend container)

**Vantagens:**
- ✅ Seguro e gerenciado
- ✅ Backups automáticos
- ✅ Escalável
- ✅ Seu notebook fica isolado
- ✅ IP fixo garantido
- ✅ HTTPS/TLS automático

---

## 🔄 OPÇÃO 2: Tunnel SSH do Notebook (ALTERNATIVA)

Se quiser manter dados locais por enquanto, use um tunnel seguro.

### 2.1 Usando ngrok

```bash
# 1. Instalar ngrok
brew install ngrok  # ou download do site

# 2. Autenticar
ngrok config add-authtoken SEU_TOKEN_AQUI

# 3. Criar tunnel para PostgreSQL
ngrok tcp 5432 --log stdout

# Resultado: tcp://X.tcp.ngrok.io:PORT
```

### 2.2 Configurar Backend (Render ou outro host)

```env
# Backend .env no Render
DATABASE_URL=postgresql://gatestack:senha@X.tcp.ngrok.io:PORT/gatestack?schema=public
REDIS_URL=redis://:senha@X.redis.ngrok.io:PORT
```

⚠️ **Limitações:**
- URL ngrok muda a cada 8 horas (versão free)
- Precisa deixar seu notebook ligado 24/7
- Menos performático
- Arriscado: credenciais no túnel

---

## 🎯 OPÇÃO 3: Monolito no Render + Notebook para Desenvolvimento

Backend e banco no Render, seu notebook só para desenvolvimento local.

### 3.1 Estrutura

```
Development (Seu Notebook):
- npm run dev (frontend + backend local)
- PostgreSQL + Redis locais
- Usa localhost:5000

Production (Render):
- Backend container
- PostgreSQL gerenciado
- Redis gerenciado
- Usa HTTPS
```

### 3.2 Implementação

**1. Setup local (já tem):**
```bash
cd /home/zeus/Documentos/GateStack
docker-compose up -d  # Roda BD + Redis + Backend localmente
```

**2. Setup Render (production):**

Atualizar `render.yaml`:

```yaml
services:
  - type: web
    name: gatestack-backend
    env: docker
    plan: starter
    branch: main
    dockerfile: Dockerfile
    envVars:
      - key: NODE_ENV
        value: production
      - key: PORT
        value: "5000"
      - key: HOST
        value: 0.0.0.0
      - key: ALLOWED_ORIGIN
        value: https://seu-frontend.firebaseapp.com,https://seu-custom-domain.com
      - key: JWT_SECRET
        generateValue: true
      - key: METRICS_TOKEN
        generateValue: true
      - key: ADMIN_EMAIL
        value: admin@seu-dominio.com
      - key: ADMIN_PASSWORD
        generateValue: true
    preDeployCommand: npm run prisma:migrate:deploy
    buildCommand: npm run build
    startCommand: npm start

databases:
  - name: gatestack-db
    databaseName: gatestack
    user: gatestack
    region: us-east
```

**3. Configurar CORS no Backend:**

```typescript
// backend/nest-src/main.ts
const app = await NestFactory.create(AppModule);

app.enableCors({
  origin: process.env.ALLOWED_ORIGIN?.split(',').map(o => o.trim()) || ['http://localhost:3000'],
  credentials: true,
  methods: 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS',
  allowedHeaders: 'Content-Type,Authorization',
});

await app.listen(process.env.PORT || 5000);
```

**4. Firebase Hosting (frontend):**

```bash
# 1. Instalar Firebase CLI
npm install -g firebase-tools

# 2. Login
firebase login

# 3. Inicializar no projeto frontend
cd frontend
firebase init hosting

# 4. Configurar para build do Next.js
# .firebaserc
{
  "projects": {
    "default": "seu-projeto-id"
  }
}

# 5. firebase.json
{
  "hosting": {
    "public": ".next/static",
    "ignore": ["firebase.json", "**/.*", "**/node_modules/**"],
    "cleanUrls": true,
    "rewrites": [
      {
        "source": "**",
        "destination": "/index.html"
      }
    ]
  }
}

# 6. Build e deploy
npm run build
firebase deploy --only hosting
```

**5. Variáveis de Ambiente do Firebase:**

```bash
# firebase.json com env vars
{
  "hosting": {
    "env": ["production"],
    "before": [
      {
        "action": "set",
        "env": {
          "NEXT_PUBLIC_API_BASE_URL": "https://seu-backend.onrender.com"
        }
      }
    ]
  }
}

# Ou criar .env.production do Next.js
# frontend/.env.production
NEXT_PUBLIC_API_BASE_URL=https://seu-backend.onrender.com
```

---

## 📋 Checklist de Deploy Recomendado (OPÇÃO 3)

### Fase 1: Preparar Código

- [ ] Remover dados sensíveis do código (chaves hardcoded)
- [ ] Criar `.env.example` com variáveis necessárias
- [ ] Testar localmente com `docker-compose up`
- [ ] Verificar build com `npm run build` (frontend + backend)

### Fase 2: Configurar Serviços

**Render.com:**
- [ ] Criar conta no Render
- [ ] Conectar GitHub
- [ ] Criar novo Web Service
- [ ] Conectar banco PostgreSQL
- [ ] Definir variáveis de ambiente

**Firebase:**
- [ ] Criar projeto no Firebase Console
- [ ] Instalar Firebase CLI
- [ ] Gerar URL pública do backend
- [ ] Configurar CORS no backend

### Fase 3: Deploy Backend

```bash
# No Render, fazer push para main branch
git push origin main

# Render faz deploy automático
# Verificar logs:
# Dashboard Render → seu-projeto → Logs
```

### Fase 4: Deploy Frontend

```bash
# No seu notebook
cd frontend
npm install
npm run build
NEXT_PUBLIC_API_BASE_URL=https://seu-backend.onrender.com npm run build
firebase login
firebase deploy --only hosting
```

### Fase 5: Testar Fluxo Completo

- [ ] Acessar https://seu-frontend.firebaseapp.com
- [ ] Fazer login e testar endpoints
- [ ] Verificar network na DevTools (requisições para backend)
- [ ] Testar upload/download de arquivos
- [ ] Validar CORS (sem erros de cross-origin)

---

## 🔐 Segurança - Checklist

### Variáveis Sensíveis

✅ NUNCA comitar em GitHub:
```
DATABASE_URL
JWT_SECRET
ADMIN_PASSWORD
REDIS_PASSWORD
METRICS_TOKEN
```

✅ Usar ambiente variable do serviço:
```bash
# Render → Environment
DATABASE_URL: Auto-generated por Render
JWT_SECRET: generateValue: true
```

### CORS

✅ Configurar domínios específicos (não `*` em produção):

```typescript
app.enableCors({
  origin: [
    'https://seu-frontend.firebaseapp.com',
    'https://seu-custom-domain.com'
  ],
  credentials: true,
});
```

### Rate Limiting

✅ Seu backend já tem (env-schema.ts):
```env
THROTTLE_TTL=60
THROTTLE_LIMIT=120  # 120 requisições por minuto
```

### HTTPS

✅ Render + Firebase ambos issuem certificados SSL/TLS automaticamente

---

## 🚀 Comandos Rápidos

### Desenvolvimento Local
```bash
# Terminal 1: Backend
cd backend
npm run dev

# Terminal 2: Frontend
cd frontend
npm run dev

# Terminal 3: Database (garantir docker-compose está rodando)
docker-compose up -d postgres redis
```

### Deploy Backend (Render)
```bash
git add .
git commit -m "Deploy para render"
git push origin main
# Render faz deploy automático
```

### Deploy Frontend (Firebase)
```bash
cd frontend
NEXT_PUBLIC_API_BASE_URL=https://seu-backend.onrender.com npm run build
firebase deploy --only hosting
```

### Executar Migrations
```bash
# Local
npm run prisma:migrate:dev

# Produção (Render executa via preDeployCommand)
# Mas se precisar manual:
npm run prisma:migrate:deploy --database-url "postgresql://..."
```

---

## 📊 Resumo de Custos (OPÇÃO 3 Recomendada)

| Serviço | Plano | Custo/Mês |
|---------|-------|-----------|
| Render Backend | Starter | $7 |
| Render PostgreSQL | Starter Plus | $15 |
| Render Redis | Starter | $5 |
| Firebase Hosting | Free tier | *Gratuito* até 10GB |
| Domínio Custom | Opcional | $12+ |
| **TOTAL** | | **~$39-50/mês** |

*Firebase oferece 10GB/mês grátis de storage e transferência de dados*

---

## ❓ FAQ

**P: E meu banco de dados local? Perco os dados?**
R: Não! Você continua tendo local para desenvolvimento. Crie um script de migrações para trazer dados se necessário.

**P: Posso fazer CI/CD?**
R: Sim! Render suporta:
- Deploy automático ao fazer push
- Webhooks do GitHub
- Preview deployments para PRs

**P: E se meu notebook cair?**
R: Com dados em Render: zero impacto. Backend continua online.

**P: Quantos usuários suporta?**
R: 
- Starter Backend: ~50 usuários simultâneos
- Startup PostgreSQL: dados para ~10M registros
- Se crescer: upgrade é simples

**P: Como debugar problemas em produção?**
R: Render oferece logs em tempo real. Firebase também.

---

## 🎓 Próximos Passos

1. Escolher entre OPÇÃO 1 (melhor) ou OPÇÃO 3 (mais controle)
2. Criar conta no Render se não tiver
3. Seguir o checklist de deploy
4. Testar fluxo completo
5. Configurar CI/CD

Quer ajuda em algum passo específico? 🚀
