# Camellia Shield (Hardened Edition)

Camellia Shield is a secure local workspace for file encryption and management. It combines a modern web-based interface with military-grade cryptography to protect your sensitive data.

## 🚀 Key Features

### 🔒 Army-Grade Security
- **Argon2id Hashing**: Protects your master password against brute-force attacks.
- **Master Key Architecture**: Data is encrypted with a random key, which is itself encrypted by your password. This allows password changes without re-encrypting terabytes of data.
- **Metadata Privacy**: Filenames are renamed to random UUIDs on disk. Only you see the real names when unlocked.

### �️ Safety & UX
- **Vault System**: Files are managed via an encrypted manifest (`vault_manifest.enc`).
- **Safe Delete**: Critical actions require typing `DELETE` to confirm, preventing accidental data loss.
- **Session Security**: Auto-locks after 5 minutes of inactivity. Master keys are never written to disk.

## � Installation

### Requirements
- Python 3.8+
- Linux (GTK) / Windows / macOS

### Setup
```bash
# Camellia Shield — Guia do Projeto

Camellia Shield é uma aplicação para gerenciamento local de arquivos com criptografia forte e interface web/desktop.

Visão rápida: a aplicação roda um servidor Flask que serve uma interface web (em [templates/index.html](templates/index.html)) e pode ser empacotada como app desktop via `pywebview` (ponto de entrada: `main.py`).

**Principais objetivos**
- Proteger arquivos com criptografia moderna (Argon2 para derivação de chave, AES-GCM para cifragem).
- Ocultar metadados e nomes de arquivos no disco (UUIDs no vault).
- Fornecer uma interface simples para encriptar/desencriptar e gerenciar um cofre local.

---

## Funcionalidades
- Derivação de chave com Argon2id.
- Arquitetura com Master Key: permite troca de senha sem recriptografar todo o armazenamento.
- Manifesto de cofre criptografado (vault manifest).
- Proteções UX: confirmação segura para ações destrutivas, auto-lock de sessão.

## Arquitetura do Projeto

- `main.py` — inicializador da aplicação e da janela desktop via `pywebview`.
- `app.py` — cria a aplicação Flask e registra blueprints em `api/`.
- `core/` — lógica de domínio (crypto, auth, vault, tasks).
- `api/` — endpoints (blueprints) que expõem funcionalidades para o frontend.
- `static/` e `templates/` — frontend web (JS/CSS/HTML).

Estrutura relevante:

- [app.py](app.py)
- [main.py](main.py)
- [requirements.txt](requirements.txt)
- [SECURITY.md](SECURITY.md)

---

## Instalação (desenvolvimento)

Requisitos: Python 3.8+ (Linux/macOS/Windows). Recomenda-se usar um virtualenv.

Passos mínimos:

 - Para travar (fixar) dependências para builds reprodutíveis, ative seu virtualenv e execute:

```bash
./scripts/pin_requirements.sh
```

```bash
# criar e ativar virtualenv
python3 -m venv .venv
source .venv/bin/activate

# instalar dependências
pip install -r requirements.txt
```

Observação: `requirements.txt` contém dependências como `Flask`, `pywebview`, `cryptography` e `python-dotenv`.

## Variáveis de ambiente
O projeto usa `python-dotenv`. Crie um arquivo `.env` na raiz (opcional) com:

```
FLASK_ENV=development
PORT=5000
# outras chaves se necessário
```

Nota: `app.py` gera `secret_key` automaticamente se não for fornecida.

---

## Execução

- Modo desktop (inicia Flask e abre janela webview):

```bash
python main.py
```

- Modo servidor (apenas Flask):

```bash
python -m app
# ou
python app.py
```

 - Consulte `docs/kms_migration.md` para um playbook sobre como usar o AWS KMS e migrar material de chave local.
 - Documentação detalhada do projeto: `docs/DETAILED_DOCUMENTATION.md`.

**Publicação no GitHub**

Antes de publicar o repositório, siga o checklist: [docs/GITHUB_PUBLISH_CHECKLIST.md](docs/GITHUB_PUBLISH_CHECKLIST.md). Em resumo: não comite arquivos `.env`, `kms.key`, `audit.log` ou outros segredos; gere `requirements-pinned.txt`; rode `./scripts/check_secrets.sh`; instale `pre-commit` e configure hooks.
Após a inicialização, acesse `http://127.0.0.1:5000` ou interaja pela janela criada pelo `pywebview`.

### Produção

Recomendações mínimas para ambiente de produção:

- Defina `SECRET_KEY` como variável de ambiente forte (ex.: 32+ bytes aleatórios).
- Execute a aplicação via WSGI (ex.: `gunicorn app:app`) por trás de um proxy reverso (nginx) que termine TLS.
- Não exponha `debug` em produção; use `FLASK_ENV=production` e `FLASK_DEBUG=0`.
- Use um vault/KMS para chaves de produção; não deixe chaves em arquivos de texto.

Exemplo mínimo (systemd/nginx):

```bash
# export SECRET_KEY=$(openssl rand -hex 32)
export SECRET_KEY=...
gunicorn -w 4 -b 127.0.0.1:5000 app:app
```

## Uso (resumo)

1. Na primeira execução, registre um usuário para gerar a Master Key.
2. Faça unlock para ver os arquivos e ações disponíveis.
3. Use a UI para encriptar/decriptar arquivos; ações críticas pedem confirmação explícita.

---

## Desenvolvimento e testes

- Existem testes iniciais: `tests_2fa.py`, `tests_batch.py`, `tests_fs_hardening.py`.
- Recomenda-se instalar `pytest` em desenvolvimento e executar:

```bash
pip install pytest
pytest -q
```

---

## Segurança

Leia [SECURITY.md](SECURITY.md) para práticas, limites de responsabilidade e notas sobre migrações de formatos de cofre. Há uma nota de breaking change entre versões que afeta compatibilidade de arquivos cifrados.

---

## Contribuindo

- Abra issues para bugs ou melhorias.
- Para PRs: escreva testes e documente mudanças.

---

## Licença

Consulte o arquivo `LICENSE` na raiz do repositório.

---

## Contato

Para dúvidas e reportes de segurança, veja [SECURITY.md](SECURITY.md) ou abra uma issue.
