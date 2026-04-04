# Arquivos de Configuração - Deploy Backend + Frontend

## 📄 1. render.yaml (Backend + Database)

Copie este conteúdo para `render.yaml` na raiz do seu projeto:

```yaml
services:
  - type: web
    name: gatestack-backend
    env: docker
    plan: starter
    region: us-east-1
    branch: main
    repo: seu-github-repo-url
    dockerfile: ./Dockerfile
    dockerContext: .
    
    # Build configuration
    buildCommand: npm run build
    startCommand: npm start
    preDeployCommand: npm run prisma:migrate:deploy
    
    # Variáveis de Ambiente
    envVars:
      # Node
      - key: NODE_ENV
        value: production
      - key: PORT
        value: "5000"
      - key: HOST
        value: 0.0.0.0
      - key: LOG_LEVEL
        value: info
      
      # Frontend URL (seu Firebase Hosting)
      - key: ALLOWED_ORIGIN
        value: "https://seu-frontend.firebaseapp.com,https://seu-custom-domain.com.br"
      
      # JWT & Security (Render gera automaticamente)
      - key: JWT_SECRET
        generateValue: true
      - key: JWT_EXPIRES_IN
        value: "7d"
      - key: METRICS_TOKEN
        generateValue: true
      
      # Admin padrão (mude IMEDIATAMENTE após primeiro login!)
      - key: ADMIN_EMAIL
        value: admin@seu-empresa.com
      - key: ADMIN_PASSWORD
        generateValue: true
      
      # Rate Limiting
      - key: THROTTLE_TTL
        value: "60"
      - key: THROTTLE_LIMIT
        value: "120"
      
      # Publicação Max CVSS
      - key: PUBLISH_MAX_CVSS
        value: "7"
      
      # Database (Link automático com banco PostgreSQL abaixo)
      - key: DATABASE_URL
        fromDatabase:
          name: gatestack-db
      
      # Redis (Render gerenciado)
      - key: REDIS_HOST
        value: localhost
      - key: REDIS_PORT
        value: "6379"
      - key: REDIS_PASSWORD
        generateValue: true
    
    # Health check
    healthCheckPath: /health
    
    # Logs
    maxInstances: 3

# ============================================================
# BASE DE DADOS - PostgreSQL Gerenciado pelo Render
# ============================================================
databases:
  - name: gatestack-db
    ipAllowList: []  # Permite acesso interno do Render
    databaseName: gatestack
    user: gatestack
    region: us-east-1
    plan: starter-plus  # ~$15/mês - tem backups diários

# ============================================================
# CACHE - Redis Gerenciado pelo Render (OPCIONAL)
# ============================================================
# Descomente se quiser Redis também no Render
# caches:
#   - name: gatestack-cache
#     plan: starter
#     region: us-east-1
#     maxmemoryPolicy: allkeys-lru
```

---

## 📄 2. next.config.mjs (Frontend - Firebase)

Adicione ao seu `frontend/next.config.mjs`:

```javascript
/** @type {import('next').NextConfig} */
const nextConfig = {
  // Rewrite API calls para o backend
  async rewrites() {
    const apiBase = process.env.NEXT_PUBLIC_API_BASE_URL || '';
    
    if (!apiBase) {
      // Modo local - sem rewrite
      return [];
    }
    
    return {
      beforeFiles: [
        {
          source: '/api/:path*',
          destination: `${apiBase}/:path*`,
        },
      ],
    };
  },
  
  // Headers de segurança
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff',
          },
          {
            key: 'X-Frame-Options',
            value: 'SAMEORIGIN',
          },
          {
            key: 'X-XSS-Protection',
            value: '1; mode=block',
          },
          {
            key: 'Strict-Transport-Security',
            value: 'max-age=31536000; includeSubDomains',
          },
        ],
      },
    ];
  },
  
  poweredByHeader: false,
};

export default nextConfig;
```

---

## 📄 3. frontend/.env.production

```bash
# API Backend (atualize com seu domínio Render)
NEXT_PUBLIC_API_BASE_URL=https://gatestack-backend.onrender.com

# Firebase / Tauri flags
NEXT_PUBLIC_ENABLE_TAURI=false
NEXT_PUBLIC_ENABLE_FIREBASE=true
```

---

## 📄 4. frontend/firebase.json

```json
{
  "hosting": {
    "public": ".next/public",
    "ignore": [
      "firebase.json",
      "**/.*",
      "**/node_modules/**"
    ],
    "cleanUrls": true,
    "rewrites": [
      {
        "source": "/",
        "destination": "/index.html"
      }
    ],
    "headers": [
      {
        "source": "**/*.{js,css}",
        "headers": [
          {
            "key": "Cache-Control",
            "value": "public, max-age=31536000, immutable"
          }
        ]
      },
      {
        "source": "/**",
        "headers": [
          {
            "key": "Cache-Control",
            "value": "public, max-age=3600"
          },
          {
            "key": "X-Content-Type-Options",
            "value": "nosniff"
          },
          {
            "key": "X-Frame-Options",
            "value": "SAMEORIGIN"
          }
        ]
      }
    ]
  }
}
```

---

## 📄 5. .firebaserc

```json
{
  "projects": {
    "default": "seu-projeto-id-aqui"
  },
  "targets": {},
  "etags": {}
}
```

---

## 📄 6. .gitignore (Atualizado)

Adicione estas linhas para não comitar dados sensíveis:

```bash
# Variáveis sensíveis
.env
.env.local
.env.*.local
.env.production.local

# Firebase
.firebase/
.firebaserc

# Render
render.yaml.backup

# Credenciais e secrets
*.pem
*.key
secrets/
credentials/

# Build outputs
.next/
out/
dist/
build/

# Node
node_modules/
npm-debug.log
yarn-error.log

# Database (local)
postgres-data/
redis-data/

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
.env.*.local
```

---

## 📄 7. Scripts de Deploy no package.json

Adicione na seção `"scripts"` do `frontend/package.json`:

```json
{
  "scripts": {
    "dev": "next dev",
    "build": "next build",
    "start": "next start",
    "lint": "next lint",
    
    "build:production": "NEXT_PUBLIC_API_BASE_URL=https://gatestack-backend.onrender.com npm run build",
    "deploy:firebase": "npm run build:production && firebase deploy --only hosting",
    "deploy:firebase:staging": "npm run build && firebase deploy --only hosting --project staging",
    "firebase:login": "firebase login",
    "firebase:init": "firebase init hosting"
  }
}
```

---

## 📄 8. backend/nest-src/main.ts (CORS Configurado)

```typescript
import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { AppModule } from './app.module';
import { parseEnv } from './common/config/env.schema';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const config = parseEnv(process.env);

  // CORS - Permitir requisições do frontend
  app.enableCors({
    origin: (origin, callback) => {
      const allowedOrigins = [
        'http://localhost:3000',
        'http://localhost:3001',
        'http://127.0.0.1:3000',
        'http://127.0.0.1:3001',
      ];

      // Em produção, adicionar Firebase URL
      if (process.env.NODE_ENV === 'production') {
        allowedOrigins.push('https://seu-frontend.firebaseapp.com');
        // Se tiver domínio customizado:
        // allowedOrigins.push('https://seu-dominio.com');
      }

      // Permitir via variável de ambiente
      const envOrigins = config.ALLOWED_ORIGIN?.split(',').map((o) => o.trim()) || [];
      allowedOrigins.push(...envOrigins);

      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error(`CORS not allowed for origin: ${origin}`));
      }
    },
    credentials: true,
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS',
    allowedHeaders: 'Content-Type,Authorization',
    optionsSuccessStatus: 200,
  });

  // Global validation pipe
  app.useGlobalPipes(new ValidationPipe());

  // Remover header X-Powered-By
  app.disable('x-powered-by');

  // Helmet para segurança
  import('helmet').then(({ default: helmet }) => {
    app.use(helmet());
  });

  const port = config.PORT || 5000;
  const host = config.HOST || '0.0.0.0';

  await app.listen(port, host);
  console.log(`✅ Backend running at http://${host}:${port}`);
  console.log(`📊 Health: http://${host}:${port}/health`);
  console.log(`📈 Metrics: http://${host}:${port}/metrics`);
}

bootstrap();
```

---

## 📄 9. .env.example (Documentação)

Crie `frontend/.env.example`:

```bash
# ============================================================
# FRONTEND - VARIÁVEIS DE AMBIENTE
# ============================================================

# API Backend
# Local: deixar vazio para usar proxy Next.js
# Produção: https://seu-backend.onrender.com
NEXT_PUBLIC_API_BASE_URL=

# Feature flags
NEXT_PUBLIC_ENABLE_TAURI=false
NEXT_PUBLIC_ENABLE_FIREBASE=true

# Analytics (opcional)
NEXT_PUBLIC_GOOGLE_ANALYTICS_ID=

# Sentry (opcional)
NEXT_PUBLIC_SENTRY_DSN=
```

Crie `backend/.env.example`:

```bash
# ============================================================
# BACKEND - VARIÁVEIS DE AMBIENTE
# ============================================================

# Node environment
NODE_ENV=production
HOST=0.0.0.0
PORT=5000
LOG_LEVEL=info

# Database - Render fornecerá esto automáticamente
DATABASE_URL=postgresql://user:password@host:5432/database?schema=public

# Redis
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=change_me

# Security - Render gerará automáticamente
JWT_SECRET=seu-secret-super-seguro-com-pelo-menos-32-caracteres
JWT_EXPIRES_IN=7d
METRICS_TOKEN=token-metricas-seguro-com-32-caracteres-minimo

# CORS - Adicione seus domínios
ALLOWED_ORIGIN=http://localhost:3000,https://seu-frontend.firebaseapp.com

# Admin padrão - MUDE IMEDIATAMENTE
ADMIN_EMAIL=admin@gatestack.local
ADMIN_PASSWORD=ChangeMeNow_12345

# Rate limiting
THROTTLE_TTL=60
THROTTLE_LIMIT=120

# Publishing rules
PUBLISH_MAX_CVSS=7
```

---

## 🚀 Passo a Passo de Deploy Completo

### 1️⃣ Preparar Repositório

```bash
# Na raiz do projeto
git add -A
git commit -m "Setup: Configuração de deploy prod"
git push origin main
```

### 2️⃣ Criar Projeto no Render

1. Ir para https://render.com
2. Criar nova conta ou login
3. Conectar repositório GitHub
4. Criar novo "Web Service"
5. Cole o conteúdo de `render.yaml` (Render vai detectar automaticamente)
6. Clicar "Create Web Service"
7. Render vai:
   - Dar automaticamente as variáveis `DATABASE_URL` e `REDIS_PASSWORD`
   - Criar as migrations no banco
   - Fazer deploy

### 3️⃣ Deploy Frontend no Firebase

```bash
# Login no Firebase
firebase login

# Build para produção
NEXT_PUBLIC_API_BASE_URL=https://gatestack-backend.onrender.com npm run build

# Deploy
firebase deploy --only hosting
```

### 4️⃣ Testar

```bash
# Visitar seu frontend
https://seu-projeto.firebaseapp.com

# Testar login
# DevTools → Network → Verificar requisições para seu backend

# Verificar backend
curl https://gatestack-backend.onrender.com/health
```

---

## 📌 Notas Importantes

✅ **Segurança:**
- Render issu certificado SSL automaticamente
- Todas as env vars sensíveis são privadas
- CORS configurado apenas para seus domínios

✅ **Performance:**
- Firebase CDN distribui frontend globalmente
- Render gerencia escala automátita
- PostgreSQL com backups automáticos

✅ **Dados:**
- Nenhum dado sai do Render (está na nuvem da Render, não de terceiros)
- Backups diários automáticos
- Seu notebook é apenas para desenvolvimento

✅ **Custo:**
- Firebase: Grátis até 10GB/mês
- Render: ~$20-30/mês (backend + DB)
- Bem mais barato que servidor dedicado

---

## ❌ O Que NÃO Fazer

- ❌ Comitar `.env` com valores reais
- ❌ Expor `DATABASE_URL` no frontend
- ❌ Usar `ALLOWED_ORIGIN: *` em produção
- ❌ Deixar senha padrão do admin
- ❌ Fazer deploy sem executar migrations
- ❌ Expor seu notebook na internet direto

---

## 🆘 Troubleshooting

**Erro: CORS bloqueado**
→ Verificar `ALLOWED_ORIGIN` no render.yaml

**Erro: Database connection failed**
→ Render criou o banco? Verificar logs: Render Dashboard → Logs

**Erro: Migrations não rodaram**
→ Verificar `preDeployCommand` está no render.yaml
→ Ver logs de deploy no Render

**Frontend não conecta ao backend**
→ Verificar `NEXT_PUBLIC_API_BASE_URL` está correto
→ DevTools → Network → Verificar requisição
→ Backend está respondendo? `curl backend-url/health`

---

Pronto! Agora é só seguir os passos e seu deploy estará seguro e profissional! 🚀
