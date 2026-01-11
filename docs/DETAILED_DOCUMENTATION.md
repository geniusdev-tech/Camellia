# Documentação Detalhada do Projeto Camellia

Este documento fornece uma análise técnica detalhada do software, incluindo arquitetura, design criptográfico, integração com KMS, fluxo do `VaultManager`, operação, CI/CD e orientações de segurança e implantação.

**Sumário**
- Visão geral
- Arquitetura e componentes
- Design criptográfico
- Formato de manifestos e auditoria
- Gerenciamento de chaves (KMS)
- Fluxos do `VaultManager`
- Segurança, middleware e configuração
- CI / QA / SCA
- Testes e cobertura
- Implantação e playbook operacional
- Troubleshooting comum
- Referências de arquivos importantes

**Visão geral**
Camellia é uma aplicação Python (Flask) para gerenciamento criptográfico de arquivos/segredos com foco em operações seguras: derivação de chaves com Argon2id, cifragem AEAD (AES-GCM por padrão, XChaCha20 quando disponível), assinaturas Ed25519 para integridade de manifestos e suporte para envelope encryption via KMS.

**Arquitetura e componentes**
- `app.py` / `main.py`: inicialização da aplicação, carregamento de `config.py`, inicialização de logging e KMS (veja `app.kms`).
- `core/crypto/engine.py`: abstração `CryptoEngine` com AEAD, Argon2/KDFs, derivação de subchaves, encapsula `aead_encrypt`/`aead_decrypt` e helpers para `wrap_master_key`/`unwrap_master_key`.
- `core/crypto/stream.py`: cifragem/decifragem em streaming usando a camada AEAD do `CryptoEngine`.
- `core/vault/manager.py`: lógica do cofre — salvar/carregar manifestos, encriptar/descrifrar arquivos, integração com KMS para envelope encryption.
- `core/kms/`: provedores de KMS
  - `file_kms.py`: provedor de arquivo (mock/for local dev) — implementa `generate_data_key` e `decrypt_data_key` usando AES-GCM local.
  - `aws_kms.py`: provedor AWS KMS (usa `boto3`) — `GenerateDataKey` e `Decrypt` integrados.
- `core/audit/logger.py`: log de auditoria em append-only, assinado com Ed25519; entradas JSON com carimbo e assinatura.
- `core/security/sanitizers.py`: funções de sanitização (nomes de arquivos e paths) para reduzir RCE/Path Traversal.
- `scripts/argon2_bench.py`: benchmark local para avaliar `time_cost` do Argon2.

**Design criptográfico**
- Argon2: O projeto usa Argon2id para derivação de chaves. Parâmetros configuráveis via variáveis de ambiente (ver `ARGON2_PARAMS` em `core/crypto/engine.py`):
  - `ARGON2_TIME_COST` (padrão 3), `ARGON2_MEMORY_KB` (64MB), `ARGON2_PARALLELISM` (4), `ARGON2_HASH_LEN` (32), `ARGON2_SALT_LEN` (16).
- AEAD: suporte a AES-GCM por padrão; quando `AEAD_ALGO=XCHACHA20` e `PyNaCl` está instalado, usa XChaCha20-Poly1305 (mais seguro para nonces aleatórios longos). Implementação centralizada em `CryptoEngine.aead_encrypt`/`aead_decrypt`.
- Master Key: chave mestra gerada aleatoriamente (`MASTER_KEY_LEN`, padrão 32 bytes). Deriva-se subchaves via HKDF (SHA-256) com `info` contextual.
- Wrap/Unwrap: o `CryptoEngine.wrap_master_key` encripta a MK com uma KEK derivada da senha (Argon2 low-level) e retorna salt/nonce/ciphertext base64 e nome do AEAD.
- Assinaturas: manifestos são assinados com Ed25519 para garantir integridade e não‑repúdio local; a chave pública é exposta no cabeçalho do arquivo de log de auditoria.

**Formato do manifesto (resumo)**
- Armazenado como JSON (manifest). Campos típicos:
  - `version`: versão do esquema
  - `files`: lista de entradas com `path`, `ciphertext_blob` (ou referência), `nonce`, `aead`, `encrypted_dek` (base64) — quando envelope KMS é usado
  - `wrapped_master_key` ou `encrypted_dek`: dependendo do fluxo
  - `signature`: assinatura Ed25519 do blob do manifesto
  - `meta`: timestamps, author, etc.

Para ver a implementação e pontos de integração, consulte `core/vault/manager.py`.

**Auditoria**
- O logger de auditoria (`core/audit/logger.py`) produz entradas JSON assinadas com Ed25519. Cada entrada inclui `created_at`, `event_type`, `payload` e `signature`. Use isso para integridade de logs e stream de auditoria.

**Gerenciamento de chaves e KMS**
- `FileKMS` (dev): implementa envelope encryption local; útil para desenvolvimento e testes, não para produção.
- `AWSKMSProvider`: usa `boto3` para `GenerateDataKey` (retorna ciphertext blob em base64) e `Decrypt` para recuperar o DEK em tempo de uso.
- Variáveis de ambiente relevantes:
  - `KMS_PROVIDER`: `file` (padrão) ou `aws`
  - `AWS_KMS_KEY_ID`: KeyId/ARN quando `KMS_PROVIDER=aws`
  - `SECRET_KEY`: segredo Flask / sessão
- Playbook de migração: `docs/kms_migration.md` (ex.: gerar data keys via KMS, atualizar manifests para armazenar o `encrypted_dek` retornado pelo KMS e descartar plaintext imediatamente).

**Fluxos do `VaultManager` (alto nível)**
1. Inicializar ou carregar `MasterKey` (gerado ou desembrulhado via senha).
2. Para cada arquivo a ser protegido:
   - Derivar `file_key` via HKDF a partir da MK com contexto `file:path`.
   - Encriptar conteúdo com AEAD (nonce aleatório) em streaming via `core/crypto/stream.py`.
   - Se KMS ativo: gerar DEK via `KMS.generate_data_key`, usar o plaintext DEK para cifrar o arquivo (ou usar envelope) e armazenar `encrypted_dek` (base64) no manifesto; garantir remoção imediata do plaintext da memória.
   - Assinar/atualizar manifesto e persistir.

**Segurança, middleware e configuração**
- `Flask-Talisman` para CSP/HSTS (opcional conforme `config.py`).
- `Flask-SeaSurf` para CSRF.
- `Flask-Limiter` para rate limiting.
- `SECRET_KEY` deve vir de variáveis de ambiente em produção. Veja `config.py`.
- Sanitização de caminhos e nomes implementada em `core/security/sanitizers.py`.

**CI / QA / SCA**
- Workflows adicionados:
  - `.github/workflows/ci.yml`: executa lint, bandit, safety (quando `requirements-pinned.txt` presente) e `pytest`.
  - `.github/workflows/argon2_benchmark.yml`: roda `scripts/argon2_bench.py` em PRs e semanalmente.
- Geração de dependências fixadas: `scripts/pin_requirements.sh` gera `requirements-pinned.txt`. Recomenda-se commitar o arquivo para builds reprodutíveis.

**Testes**
- Os testes automatizados estão em `tests/` e cobrem: integração KMS (envelope mock), engine de crypto, stream engine, vault manager, auth. Execute com `pytest -q`.

**Implantação e playbook operacional**
- Variáveis de ambiente recomendadas:
  - `FLASK_ENV=production`, `SECRET_KEY`, `KMS_PROVIDER`, `AWS_KMS_KEY_ID`, `AEAD_ALGO` (opcional)
- Docker: Use `Dockerfile` (não root) e configure secrets via CI/CD (GitHub Secrets) ou orquestrador (Kubernetes Secrets, HashiCorp Vault).
- Rotação de chaves: rotacione a CMK no provider (AWS KMS) e re-encripte manifests conforme playbook em `docs/kms_migration.md`.

**Troubleshooting comum**
- Erro: `Invalid Password or Corrupted Key` → verifique salt/nonce em manifest e parâmetros Argon2 (consistência entre derivação e unwrap).
- Erro: falha ao inicializar AWS KMS → verifique `AWS` credentials e permissões (`kms:GenerateDataKey`, `kms:Decrypt`).
- Bandit/SCA flags apontando para dependências → fixe pins e atualize `requirements-pinned.txt` e reexecute `safety`.

**Referências de arquivos importantes**
- `app.py` — inicialização e configuração
- `core/crypto/engine.py` — CryptoEngine, Argon2 params
- `core/crypto/stream.py` — streaming AEAD
- `core/vault/manager.py` — lógica do vault e manifest
- `core/kms/file_kms.py` — provedor KMS local
- `core/kms/aws_kms.py` — provedor AWS KMS
- `core/audit/logger.py` — log de auditoria assinado
- `scripts/pin_requirements.sh` — gerar `requirements-pinned.txt`
- `docs/kms_migration.md` — playbook de migração KMS

---
Esta documentação é um ponto de partida. Posso expandir seções específicas (ex.: descrição de cada função pública, diagrama de sequência de operações, exemplos de API/CLI, checklist de compliance) conforme você desejar.
