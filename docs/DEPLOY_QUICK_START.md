# GUIA RÁPIDO - Deploy GateStack

## 🎯 Seu Cenário

```
AGORA (Desenvolvimento):
├── Seu Notebook
│   ├── Backend (NestJS) → localhost:5000
│   ├── Frontend (Next.js) → localhost:3000
│   ├── PostgreSQL → localhost:5432
│   └── Redis → localhost:6379

DEPOIS (Produção):
├── Backend → Render.com (https://seu-backend.onrender.com)
├── Frontend → Firebase Hosting (https://seu-projeto.firebaseapp.com)
├── PostgreSQL → Render Managed DB (automático)
└── Seu Notebook → Apenas desenvolvimento local
```

---

## ✅ Checklist Pré-Deploy

### Configuração de Código

- [ ] Remover dados hardcoded (URLs, senhas)
- [ ] Criar `.env.example` documentando variáveis
- [ ] Adicionar ao `.gitignore`: `.env`, `.env.local`, `firebase.json`
- [ ] Testar localmente: `docker-compose up -d && npm run dev` (frontend)
- [ ] Verificar build local: `npm run build` (ambos)

### Contas Necessárias

- [ ] Criar conta em [render.com](https://render.com)
- [ ] Conectar GitHub ao Render
- [ ] Criar projeto no [Firebase Console](https://console.firebase.google.com)
- [ ] Instalar Firebase CLI: `npm install -g firebase-tools`

### Variáveis de Ambiente

Backend (Render fornecerá automaticamente):
- [x] `DATABASE_URL` - Gerado pelo Render
- [x] `JWT_SECRET` - `generateValue: true` no render.yaml
- [x] `METRICS_TOKEN` - `generateValue: true` no render.yaml
- [ ] `ALLOWED_ORIGIN` - Seu Firebase URL

Frontend (você configura):
- [ ] `NEXT_PUBLIC_API_BASE_URL` - URL do backend Render

---

## 🚀 Processo de Deploy (Ordem Correta)

### Passo 1: Preparar Backend no Render (10 min)

```bash
# ✅ Você tem render.yaml no repositório?
ls -la render.yaml

# Se não, use esse conteúdo:
# Veja: docs/DEPLOYMENT_CONFIG.md - seção "1. render.yaml"

# ✅ Commit e push
git add -A
git commit -m "Deploy: render.yaml config"
git push origin main
```

**No site Render:**

1. Ir para https://render.com
2. Conectar repositório GitHub
3. Criar novo "Web Service"
4. Render vai detectar `render.yaml` automaticamente
5. Clicar "Create Web Service"
6. **Aguardar ~5-10 minutos** para deploy inicial

**Resultado:**
- Seu backend estará em: `https://seu-projeto.onrender.com`
- PostgreSQL está sendo inicializado automaticamente

### Passo 2: Verificar Backend Online

```bash
# ✅ Health check
curl https://seu-projeto.onrender.com/health

# Deve responder com:
# {"status":"ok","version":"3.0.0"}

# Ou acessar no navegador:
# https://seu-projeto.onrender.com/health
```

⏳ **Se falhar:** Pode estar ainda iniciando, aguarde mais alguns minutos

### Passo 3: Atualizar Frontend

```bash
# ✅ Arquivo: frontend/.env.production
echo 'NEXT_PUBLIC_API_BASE_URL=https://seu-projeto.onrender.com' > frontend/.env.production

# ✅ Ou usar variável de ambiente no Firebase
# (ver próxima seção)
```

### Passo 4: Deploy Frontend no Firebase

```bash
# ✅ Login no Firebase
firebase login

# ✅ Estar no diretório frontend
cd frontend

# ✅ Build com URL do backend correct
# Opção A: Usando .env.production
npm run build

# Opção B: Direto na linha de comando
NEXT_PUBLIC_API_BASE_URL=https://seu-projeto.onrender.com npm run build

# ✅ Deploy
firebase deploy --only hosting

# ✓ Sucesso! URL será mostrada
# Para exemplo: https://seu-projeto-id.firebaseapp.com
```

### Passo 5: Teste Completo

```bash
# 1. Acessar frontend
https://seu-projeto-id.firebaseapp.com

# 2. DevTools (F12) → Network
# 3. Fazer login
# 4. Verificar requisições:
#    ✓ Deve ir para https://seu-projeto.onrender.com/auth/login
#    ✓ Não deve ter erro CORS
#    ✓ Status 200 ou 401 (senha errada é ok)

# 5. Se houver erro CORS:
#    ↳ Backend: Verificar ALLOWED_ORIGIN no Render
#    ↳ Frontend: Verificar NEXT_PUBLIC_API_BASE_URL
```

---

## 📊 URLs e Referências

| Serviço | URL | Login |
|---------|----|-------|
| **Render Dashboard** | https://dashboard.render.com | GitHub |
| **Firebase Console** | https://console.firebase.google.com | Google |
| **Backend Render** | https://seu-projeto.onrender.com | Admin email/senha |
| **Frontend Firebase** | https://seu-projeto-id.firebaseapp.com | Admin email/senha |
| **Backend Health** | https://seu-projeto.onrender.com/health | Não requer auth |
| **Backend Metrics** | https://seu-projeto.onrender.com/metrics | Requer token |

---

## 🔧 Depois do Deploy - Operações Comuns

### Atualizar Backend (novo código)

```bash
# É automático! Quando você faz push no main:
git add -A
git commit -m "Fix: descrição do fix"
git push origin main
# Render detecta e faz deploy automaticamente

# Acompanhe em: Render Dashboard → seu-projeto → Logs
```

### Executar Migrations

```bash
# Automático: preDeployCommand no render.yaml
# Mas se precisar manual:

# Pegar connection string segura no Render Dashboard
# Depois rodar localmente:
DATABASE_URL="postgresql://..." npm run prisma:migrate:deploy
```

### Restart Backend

```
Render Dashboard → seu-projeto → Settings → Restart Instance
```

### Ver Logs

```
Render Dashboard → seu-projeto → Logs (tail em tempo real)
```

### Atualizar Variáveis de Ambiente

```
Render Dashboard → seu-projeto → Environment
# Editar valores e fazer restart automático
```

### Recuperar Dados de Produção (se necessário)

```bash
# Conectar ao banco em produção
DATABASE_URL="postgresql://..." psql

# Fazer backup
pg_dump "postgresql://..." > backup.sql

# Restaurar localmente
psql postgres://local_user:password@localhost/gatestack < backup.sql
```

---

## ⚠️ Segurança - Checklist Final

- [ ] Alterar `ADMIN_PASSWORD` padrão imediatamente após primeiro deploy
- [ ] Configurar `ALLOWED_ORIGIN` apenas com seus domínios (sem `*`)
- [ ] Habilitar autenticação de 2FA se suportar
- [ ] Revisar logs regularmente para atividades suspeitas
- [ ] Fazer backup regular do banco
- [ ] Usar HTTPS em produção (Render + Firebase fazem automaticamente)
- [ ] Manter JWT_SECRET e METRICS_TOKEN seguros (não commitar!)
- [ ] Revisar permissões de banco (usuário não deve ser `postgres`)

---

## 🆘 Troubleshooting Rápido

### "CORS error" do frontend

**Causa:** Frontend não consegue conectar ao backend

**Solução:**
```bash
# 1. Verificar Backend está online
curl https://seu-backend.onrender.com/health

# 2. Verificar ALLOWED_ORIGIN no render.yaml
# Deve incluir seu Firebase URL

# 3. Verificar NEXT_PUBLIC_API_BASE_URL no frontend
# Deve apontar para URL correta do backend
```

### Backend não sai do status "Updating"

**Causa:** Deploy travado

**Solução:**
```
Render Dashboard → seu-projeto → Logs
# Procurar por erros
# Comum: Migration falhando, porta em uso
```

### Firebase deploy falha

**Causa:** Build error ou autenticação

**Solução:**
```bash
# 1. Verificar autenticação
firebase login

# 2. Verificar projeto
firebase use seu-projeto-id

# 3. Build local
npm run build  # Deve estar em frontend/

# 4. Deploy verbose
firebase deploy --only hosting -d
```

### Banco de dados não inicializa

**Causa:** Postgresql não subiu ou configuração errada

**Solução:**
```
Render Dashboard → seu-projeto → Resources
# Verificar se banco está listado
# Se não, remover serviço e recriá-lo
```

---

## 📝 Documentos Relacionados

- **DEPLOY_STRATEGY.md** - Explicação detalhada de cada opção
- **DEPLOYMENT_CONFIG.md** - Arquivos de configuração prontos para copiar
- **scripts/deploy.sh** - Script automático de deploy (opcional)

---

## 🎓 Próximos Passos Recomendados

1. **Primeiro Deploy:** Seguir este checklist na ordem
2. **Depois de funcionar:**
   - [ ] Configurar CI/CD automático
   - [ ] Adicionar monitoring/alertas
   - [ ] Documentar runbooks de recuperação
   - [ ] Treinar equipe no processo
3. **Otimizações:**
   - [ ] Adicionar Edge caching no Firebase
   - [ ] Otimizar queries do PostgreSQL
   - [ ] Implementar rate limiting
   - [ ] Adicionar logs centralizados

---

## 💡 Dicas Importantes

✅ **Mantenha backup de dados:**
```bash
# Backup semanal automático
pg_dump "postgresql://..." | gzip > backup-$(date +%Y%m%d).sql.gz
```

✅ **Monitore logs:**
```bash
# Render oferece logs, use-os regularmente
# Procure por errors, warnings
```

✅ **Teste antes de mergear:**
```bash
# Sempre teste localmente antes
# Deploy é rápido, mas reverter é mais lento
```

✅ **Versione seu banco:**
```bash
# Cada migração é uma versão
# Fácil de rollback se necessário
```

---

## 📞 Suporte

Se preso em algo:

1. Revisar Render Logs: Dashboard → Logs
2. Revisar Firebase Logs: Console → Logs
3. Revisar DevTools do navegador: F12 → Network e Console
4. Verificar `.env` files estão corretos
5. Verificar CORS está habilitado

---

Sucesso no seu deploy! 🚀✨
