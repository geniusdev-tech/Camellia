<h1 align="center">🛡️ Camellia Shield</h1>
<h4 align="center">Hardened Secure Local Workspace — AES-256-GCM · Argon2id · Ed25519</h4>

<p align="center">
  <a href="#-stack">Stack</a> •
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-build">Build</a> •
  <a href="#-security">Security</a> •
  <a href="#-deploy">Deploy</a>
</p>

---

## 🏗 Stack

| Camada | Tecnologia |
|--------|-----------|
| **Desktop shell** | Tauri 2 (Rust) |
| **Frontend** | Next.js 14 · TypeScript · Tailwind CSS · Framer Motion |
| **Estado** | Zustand · TanStack Query |
| **Backend API** | Flask 3 · Python 3.12 |
| **Criptografia** | AES-256-GCM · XChaCha20-Poly1305 · Argon2id · Ed25519 |
| **Autenticação** | JWT (RS256) · TOTP 2FA · RBAC |
| **KMS** | FileKMS (dev) · AWS KMS / Vault Transit (prod) |
| **Auditoria** | Append-only log assinado Ed25519 |

---

## 🚀 Quick Start (Desenvolvimento)

```bash
# 1. Clone e configure ambiente Python
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. Configure variáveis de ambiente
cp .env.example .env
# Edite .env: defina SECRET_KEY

# 3. Inicialise banco IAM e usuário admin
python scripts/init_iam_db.py

# 4. Instale dependências Node
cd frontend && npm install && cd ..

# 5. Inicie Flask + Next.js lado a lado
make dev
# Flask: http://localhost:5000
# Next:  http://localhost:3000

# 6. Ou inicie dentro do Tauri (janela nativa)
make dev-tauri
```

---

## 📦 Build

### Desktop (executável nativo)

```bash
# Todas as dependências
make install

# Gerar executável backend + app Tauri para o SO atual
make build

# Targets específicos
make build-linux    # .deb + .rpm + .AppImage
make build-win      # .msi + .exe  (requer MSVC cross-compiler)
make build-mac      # .dmg universal (Apple Silicon + Intel)
```

Os artefatos ficam em `src-tauri/target/<target>/release/bundle/`.  
Junto com cada instalador, o build copia os **guias do usuário** em `docs/user-guide/`.

### Servidor headless (Docker)

```bash
docker compose up --build
# API disponível em http://localhost:5000
```

---

## 🔒 Arquitetura de Segurança

```
Senha ──► Argon2id ──► KEK
                          └──► AES-GCM(decrypt) ──► Chave Mestra (só em RAM)
                                                          └──► HKDF ──► Subchave por arquivo
                                                                            └──► AES-256-GCM / XChaCha20
```

- **Manifesto do cofre** cifrado (Fernet) + assinado digitalmente (Ed25519)  
- **Log de auditoria** tamper-evident — cada entrada encadeada por hash e assinada  
- **Panic Wipe** — zera chaves da memória ao menor sinal de comprometimento  
- **Deep Integrity Inspection** — verifica magic bytes, entropia Shannon, SHA-256 + BLAKE2b  

---

## 🌐 Deploy em Produção

```bash
# Variáveis mínimas obrigatórias
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
KMS_PROVIDER=aws
AWS_KMS_KEY_ID=arn:aws:kms:us-east-1:123456789:key/...

# Com Docker Compose
docker compose up -d
```

Coloque um **nginx / Caddy** na frente para TLS. Veja `docs/user-guide/readme.html` para o guia completo.

---

### Backend na Vercel

O backend Flask pode ser publicado na Vercel usando [`app.py`](/home/zeus/Documentos/camellia-shield/app.py) como entrypoint e a configuração em [`vercel.json`](/home/zeus/Documentos/camellia-shield/vercel.json).

```bash
vercel deploy --prod \
  -e SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
```

Na Vercel, `audit.log`, `kms.key` e os bancos SQLite padrão passam a usar `/tmp`.
Isso permite o boot da aplicação, mas esses dados continuam efêmeros entre execuções. Para produção real, use banco externo e KMS externo.

O bootstrap automático de usuário só usa credenciais padrão em desenvolvimento local.
Em produção/serverless, defina `CAMELLIA_DEV_EMAIL` e `CAMELLIA_DEV_PASSWORD` se quiser criar um usuário inicial automaticamente.

O backend agora usa `DATABASE_URL` ou `POSTGRES_URL` automaticamente quando essas variáveis existem, com SQLAlchemy + `psycopg`.

Para CORS em produção, defina `ALLOWED_ORIGIN` com uma ou mais origens separadas por vírgula.
Sem isso, a API não responde com `Access-Control-Allow-Origin` em produção.

Para AWS KMS, defina `AWS_KMS_KEY_ID` e `AWS_REGION`.

Para Vault Transit, defina:
- `KMS_PROVIDER=transit`
- `VAULT_ADDR`
- `VAULT_TOKEN`
- `VAULT_TRANSIT_KEY_NAME`
- opcionalmente `VAULT_TRANSIT_MOUNT` se o mount não for `transit`

Na Vercel, o backend não cria mais `kms.key` local por padrão; com AWS KMS ou Vault Transit configurado, novas master keys passam a ser protegidas externamente.

---

## 📄 Licença

MIT © 2024 Rodrigo Lima
