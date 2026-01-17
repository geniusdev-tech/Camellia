# Análise Detalhada do Camellia Shield

**Data**: 11 de janeiro de 2026  
**Versão Analisada**: 2.1 (Hardened Edition)

---

## 📋 Sumário Executivo

**Camellia Shield** é uma aplicação desktop/web para gerenciamento local de arquivos com criptografia forte. A arquitetura é bem fundamentada em segurança, mas há oportunidades de melhorias em testes, documentação e tratamento de erros.

| Aspecto | Status | Risco |
|---------|--------|-------|
| **Criptografia** | ✅ Sólido | Baixo |
| **Autenticação** | ✅ Bom | Baixo |
| **Gestão de Sessão** | ⚠️ Adequado | Médio |
| **Testes** | ❌ Limitado | Alto |
| **Documentação** | ⚠️ Parcial | Médio |
| **Tratamento de Erros** | ⚠️ Inconsistente | Médio |
| **API REST** | ✅ Segura | Baixo |
| **Sanitização** | ✅ Bom | Baixo |

---

## 🔐 1. Segurança Criptográfica

### 1.1 Pontos Fortes

#### ✅ **Argon2id para derivação de chave**
```python
# core/crypto/engine.py
ARGON2_PARAMS = {
    "time_cost": 3,
    "memory_cost": 65536,  # 64 MB
    "parallelism": 4,
    "type": Type.ID
}
```
- Resistente a ataques GPU/ASIC
- Memória configurável via env vars
- Parâmetros bem calibrados (3 iterações = ~200ms de derivação)

#### ✅ **Arquitetura Master Key com separação de chaves**
- **Auth Verifier**: Hash Argon2 do password (para verificação)
- **Key Wrapping**: Password → Argon2 → KEK → AES-GCM(Master Key)
- Permite mudança de senha sem re-encriptar arquivos
- Master Key nunca escrito em disco em plaintext

#### ✅ **AES-GCM com integrity (autenticação)**
- Usa `cryptography.hazmat.primitives.ciphers.aead.AESGCM`
- Também suporta XChaCha20-Poly1305 como fallback
- Nonces aleatórios por operação (12 bytes para AES, 24 para XChaCha)

#### ✅ **Assinatura de manifesto com Ed25519**
```python
# core/vault/manager.py
private_key = ed25519.Ed25519PrivateKey.generate()
signature = priv.sign(encrypted_manifest_blob)
```
- Detecta tamper-evidence no manifesto
- Chaves de assinatura armazenadas em disco com permissões 0o600

### 1.2 Preocupações e Recomendações

#### ⚠️ **1. Fernet vs. AES-GCM direto**
**Problema**: O código menciona Fernet (que usa AES-128-CBC) mas também implementa AES-GCM:

```python
# Manifesto usa Fernet
fernet = Fernet(keys["manifest"])
encrypted_data = fernet.encrypt(data)

# Arquivos usam StreamEngine (AES-GCM)
self.stream_engine.encrypt_stream(file_path, target_path, enc_key)
```

**Impacto**: Fernet é seguro, mas AES-GCM é mais moderno e oferece melhor performance.

**Recomendação**:
- Migrar manifesto para usar AES-GCM também (ou AEAD configurável)
- Documentar por que Fernet foi escolhido para manifesto

```python
# Sugestão
def _load_manifest(self):
    keys = self._get_keys()
    manifest_path = os.path.join(self.root_path, MANIFEST_FILENAME)
    
    # Usar AEAD genérico em vez de Fernet
    nonce = os.urandom(12)
    aead = AESGCM(keys["manifest"])
    try:
        plaintext = aead.decrypt(nonce, encrypted_data, None)
        self.manifest = json.loads(plaintext)
    except InvalidTag:
        logger.error("Manifest integrity check failed")
        self.manifest = {}
```

---

#### ⚠️ **2. Ausência de testes criptográficos abrangentes**
**Problema**: Testes existentes são mínimos:
- `test_wrap_unwrap_master_key()` — apenas happy path
- `test_unwrap_wrong_password_raises()` — apenas case negativo simples
- **Faltam**: testes de nonce collision, AEAD tag verification, stream cipher correctness

**Recomendação**:
```python
# tests/test_crypto_comprehensive.py
def test_aead_tag_verification():
    """Corrupting ciphertext should fail decryption"""
    ce = CryptoEngine()
    key = os.urandom(32)
    plaintext = b"sensitive data"
    nonce = os.urandom(12)
    
    # Encrypt
    ct = ce.aead_encrypt(key, nonce, plaintext, None)
    
    # Corrupt 1 bit
    corrupted = bytearray(ct)
    corrupted[0] ^= 0x01
    
    # Should raise
    with pytest.raises(InvalidTag):
        ce.aead_decrypt(key, nonce, bytes(corrupted), None)

def test_nonce_reuse_with_same_key_fails():
    """Reusing nonce with same key must not happen"""
    ce = CryptoEngine()
    key = os.urandom(32)
    nonce = os.urandom(12)
    pt1 = b"message 1"
    pt2 = b"message 2"
    
    ct1 = ce.aead_encrypt(key, nonce, pt1, None)
    # This should never happen in production, but test the risk
    ct2 = ce.aead_encrypt(key, nonce, pt2, None)  # DANGER: same nonce!
    
    # ct1 XOR ct2 would leak plaintext bits (known plaintext XOR attack)
    # This test documents the risk
    assert ct1 != ct2  # Different ciphertexts (still unsafe!)
    logger.warning("Nonce reuse detected - this is a critical security flaw")
```

---

#### ⚠️ **3. Nonce gerado mas não armazenado para descriptor de arquivo**
**Problema**: No `StreamEngine.encrypt_stream()`, o nonce é gerado aleatoriamente. Precisa ser armazenado/recuperável durante descriptografia.

**Recomendação**: Verificar em [core/crypto/stream.py](core/crypto/stream.py) que:
- Nonce é prepended ao arquivo criptografado, OU
- Nonce é derivado de maneira determinística (por ex: HKDF do Master Key + file UUID)

---

### 1.3 Criptografia: Scorecard Final

| Critério | Score | Observação |
|----------|-------|-----------|
| KDF (Argon2id) | 10/10 | Excelente |
| Master Key Architecture | 9/10 | Separação clara; falta documentação |
| AEAD Algorithm | 8/10 | AES-GCM bom; Fernet inconsistente |
| Test Coverage | 3/10 | Mínimo; não testa edge cases |
| Nonce Management | ? | Precisa verificar stream.py |

---

## 🔑 2. Autenticação & Sessão

### 2.1 Pontos Fortes

#### ✅ **Argon2id para hash de password (Auth Verifier)**
```python
# core/auth/manager.py
def register(self, email, password):
    auth_verifier = self.crypto.hash_password(password)
    wrapped_key = self.crypto.wrap_master_key(master_key, password)
    # Armazena os dois, não a senha
```

- Duas chaves derivadas do password (auth_verifier ≠ KEK)
- Leak de database não compromete Master Key diretamente

#### ✅ **Rate Limiting em login**
```python
def login(self, email, password, ip_address=None):
    allowed, retry_after = self.rate_limiter.check_limit("login", ip_address or email)
    if not allowed:
        return False, f"Too many login attempts. Try again in {retry_after}s"
```

- Protege contra brute force
- Configurável (padrão: "200 per day, 50 per hour")

#### ✅ **2FA (TOTP) implementado**
```python
if totp_secret:
    self._temp_login_state = {"email": email, "master_key": master_key, "ip_address": ip_address}
    return False, "AUTH_2FA_REQUIRED"
```

- Separação clara entre password auth e 2FA
- QR code para setup (via `pyotp` + `qrcode`)

#### ✅ **Audit logging integrado**
```python
log_event(
    EventType.LOGIN_FAILURE,
    user=email,
    details={"reason": "invalid_password", "ip": ip_address},
    severity="WARNING",
    ip_address=ip_address
)
```

- Registra falhas de login com IP
- Estrutura de eventos bem definida

### 2.2 Preocupações

#### ⚠️ **1. Sessão armazenada em memória sem sincronização**
**Problema**:
```python
self.session = None  # Stores {email, master_key, login_time}
```

Sem lock/thread-safety para casos multi-threaded.

**Risco**: Se múltiplas requests acessarem `session` simultaneamente, pode haver race condition.

**Recomendação**:
```python
import threading

class AuthManager:
    def __init__(self, db_path="users.db"):
        self.session_lock = threading.RLock()
        self.session = None
    
    def get_session(self):
        with self.session_lock:
            return self.session.copy() if self.session else None
    
    def set_session(self, session):
        with self.session_lock:
            self.session = session
```

---

#### ⚠️ **2. Session timeout não verificado em operações**
**Problema**: Não há verificação de timestamp em `get_session()`:

```python
def get_session(self):
    # No timeout check!
    return self.session

# Em api/vault.py
auth, vault, _, _ = _get_managers()
if not auth.get_session():
    return jsonify({'success': False, 'msg': "Vault Locked"}), 401
```

**Risco**: Se uma operação demora 5+ minutos, session continua válida apesar do timeout.

**Recomendação**:
```python
def get_session(self):
    with self.session_lock:
        if not self.session:
            return None
        
        # Verificar timeout (PERMANENT_SESSION_LIFETIME = 300s = 5 min)
        elapsed = time.time() - self.session.get("login_time", 0)
        if elapsed > 300:
            self.session = None
            return None
        
        return self.session.copy()
```

---

#### ⚠️ **3. Verificação 2FA incompleta**
**Problema**: O código menciona `_temp_login_state` mas não mostra a lógica de verify_2fa:

```python
# Em api/auth.py
def verify_2fa():
    auth_manager = _get_auth_manager()
    data = request.json
    success, msg = auth_manager.verify_2fa(data.get('code'))
    if success:
        session['user_email'] = auth_manager.get_session()['email']
        return jsonify({'success': True, 'msg': msg})
```

**Problema**: `session['user_email']` é set na Flask session, mas não há validação de que 2FA foi passado. Um atacante pode chamar `/api/vault/files/list` e a verificação em `auth.get_session()` retornaria None (correto). Mas precisa verificar que o fluxo é:

1. POST /api/auth/login → AUTH_2FA_REQUIRED (session limpa)
2. POST /api/auth/2fa/verify → sucesso → session criada
3. POST /api/files/list → sucesso (com session)

**Recomendação**: Documentar o fluxo de 2FA e garantir que `verify_2fa()` atualiza a sessão corretamente.

---

### 2.3 Autenticação: Scorecard

| Critério | Score | Observação |
|----------|-------|-----------|
| Password Hashing | 9/10 | Argon2id; falta test de timing attack |
| Rate Limiting | 8/10 | Implementado; não testa exhaustivamente |
| 2FA (TOTP) | 7/10 | Implementado; fluxo não está totalmente claro |
| Session Management | 6/10 | Sem thread-safety, sem timeout em get_session() |
| Audit Logging | 9/10 | Bem estruturado |

---

## 📁 3. Gerenciamento de Arquivo & Vault

### 3.1 Pontos Fortes

#### ✅ **Manifesto criptografado + assinado**
- Manifesto armazenado em `vault_manifest.enc` (Fernet)
- Assinado com Ed25519 para integridade
- Backups rotacionados (últimos 5)
- Escrita atômica com fsync()

#### ✅ **UUID para metadados**
- Arquivos renomeados para UUID (ex: `f47ac10b-58cc-4372-a567-0e02b2c3d479`)
- Nomes reais e paths armazenados cifrados no manifesto
- Oculta estrutura de diretórios

#### ✅ **Suporte a KMS envelope**
```python
if self.kms is not None:
    dek_plain, enc_dek = self.kms.generate_data_key(file_uuid)
    self.manifest[file_uuid]["encrypted_dek"] = enc_dek
    enc_key = dek_plain
```
- Suporta AWS KMS ou local FileKMS
- DEK (Data Encryption Key) gerado por KMS; Master Key não precisa encriptar tudo

### 3.2 Preocupações

#### ⚠️ **1. Path traversal parcialmente sanificado**
**Problema**: `sanitize_path()` trata `.` e `..` mas não valida contra jailbreak de raiz:

```python
def sanitize_path(path: str) -> str:
    norm = os.path.normpath(path)
    if os.path.isabs(path):
        # Processa caminho absoluto...
        return os.sep + os.path.join(*parts)
    return os.sep.join(parts)
```

**Risco**: Usuário pode encriptar `/etc/passwd` se o path for absoluto:
```
POST /api/files/action
{
  "action": "encrypt",
  "path": "/etc/passwd"
}
```

**Recomendação**:
```python
def sanitize_path(path: str, base_dir: str = None) -> str:
    """
    Ensure path is within base_dir (prevent jailbreak).
    """
    if base_dir is None:
        base_dir = os.path.expanduser("~")
    
    # Resolve to absolute
    if os.path.isabs(path):
        full_path = os.path.abspath(path)
    else:
        full_path = os.path.abspath(os.path.join(base_dir, path))
    
    # Verify it's under base_dir
    if not full_path.startswith(os.path.abspath(base_dir)):
        raise ValueError(f"Path {path} escapes base directory")
    
    return full_path
```

---

#### ⚠️ **2. Falta de testes para operações de arquivo**
**Problema**: Não há teste de decrypt_file, encrypt_stream sob carga, ou erro handling.

**Arquivo**: [tests/test_vault_manager.py](tests/test_vault_manager.py) — muito simples:
```python
def test_manifest_save_and_load(tmp_path):
    # Only tests manifest, não testa encripton de arquivo real
```

**Recomendação**:
```python
# tests/test_vault_manager.py
def test_encrypt_decrypt_file_roundtrip(tmp_path, auth_manager):
    vault = VaultManager(tmp_path, auth_manager)
    
    # Create test file
    test_file = tmp_path / "secret.txt"
    test_file.write_text("sensitive data")
    
    # Encrypt
    success, uuid = vault.encrypt_file(str(test_file))
    assert success
    assert not test_file.exists()  # Original deleted
    
    # Decrypt
    success, decrypted_path = vault.decrypt_file(uuid)
    assert success
    assert test_file.read_text() == "sensitive data"

def test_encrypt_large_file(tmp_path, auth_manager):
    """Test streaming encryption of large file."""
    vault = VaultManager(tmp_path, auth_manager)
    
    # Create 100MB test file
    test_file = tmp_path / "large.bin"
    with open(test_file, 'wb') as f:
        f.write(os.urandom(100 * 1024 * 1024))
    
    start = time.time()
    success, uuid = vault.encrypt_file(str(test_file))
    elapsed = time.time() - start
    
    assert success
    print(f"Encrypted 100MB in {elapsed:.2f}s")
```

---

#### ⚠️ **3. Erro de integridade não tratado**
**Problema**: Se arquivo for corrompido/truncado, decrypt pode falhar silenciosamente:

```python
def decrypt_file(self, file_uuid, progress_callback=None):
    # ...
    try:
        method = meta.get("method", "fernet-legacy")
        # Decrypt logic...
    except Exception:
        # Generic catch!
        return False, str(e)  # Não log!
```

**Recomendação**:
```python
except InvalidTag:
    # AEAD authentication failed - file corrupted or tampered
    log_event(
        EventType.FILE_DECRYPT_FAILURE,
        details={"file": file_uuid, "reason": "authentication_failed"},
        severity="ERROR"
    )
    return False, "File integrity check failed (corrupted or tampered)"
except Exception as e:
    log_event(
        EventType.FILE_DECRYPT_FAILURE,
        details={"file": file_uuid, "error": str(e)},
        severity="ERROR"
    )
    return False, f"Decryption failed: {str(e)}"
```

---

### 3.3 Vault: Scorecard

| Critério | Score | Observação |
|----------|-------|-----------|
| Manifesto | 9/10 | Bem assinado; faltam testes |
| Encriptação de arquivo | 8/10 | Suporta KMS; sanitização incompleta |
| Path Validation | 5/10 | Não previne jailbreak absoluto |
| Test Coverage | 2/10 | Mínimo |
| Error Handling | 4/10 | Genérico; falta logging |

---

## 🌐 4. API REST & Web Interface

### 4.1 Pontos Fortes

#### ✅ **CSRF Protection (Flask-SeaSurf)**
```python
if SeaSurf is not None and not desktop_mode:
    SeaSurf(app)
```

#### ✅ **Content Security Policy (CSP)**
```python
csp = {
    'default-src': ['\'self\''],
    'script-src': ['\'self\''],
    'style-src': ['\'self\''],
    'img-src': ['\'self\'', 'data:']
}
Talisman(app, content_security_policy=csp, ...)
```

#### ✅ **Rate Limiting em app.py**
- 200 requests/dia, 50 por hora (padrão)

#### ✅ **Session Cookies Secure**
```python
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
PERMANENT_SESSION_LIFETIME = 300  # 5 min
```

### 4.2 Preocupações

#### ⚠️ **1. Desktop mode desabilita proteções de segurança**
**Problema**:
```python
desktop_mode = os.getenv('DESKTOP_MODE', '0').lower() in ('1', 'true', 'yes')

if Talisman is not None and not desktop_mode:
    Talisman(app, ...)

if SeaSurf is not None and not desktop_mode:
    SeaSurf(app)
```

**Risco**: Se `DESKTOP_MODE=1`, Talisman (HTTPS force, HSTS) e SeaSurf (CSRF) são desabilitados. Embora justificado ("webview embedded"), reduz proteção.

**Recomendação**:
```python
# Manter CSRF mesmo em desktop (importante)
if SeaSurf is not None:  # Sempre aplicar
    SeaSurf(app)

# Talisman: relax HTTPS para desktop, mas manter CSP
if Talisman is not None:
    Talisman(
        app,
        content_security_policy=csp,
        force_https=False if desktop_mode else True,  # OK para desktop
        strict_transport_security=not desktop_mode  # HSTS apenas web
    )
```

---

#### ⚠️ **2. Falta de validação de entrada em JSON**
**Problema**: Endpoints aceitam JSON sem schema validation:

```python
@vault_bp.route('/files/action', methods=['POST'])
def file_action():
    data = request.json
    action = data.get('action')
    raw_path = data.get('path')
    # Sem validação de tipo, tamanho, etc.
```

**Recomendação**: Usar `marshmallow` ou `pydantic` para validação:

```python
from marshmallow import Schema, fields, validate, ValidationError

class FileActionSchema(Schema):
    action = fields.Str(required=True, validate=validate.OneOf(['delete', 'rename']))
    path = fields.Str(required=True)
    new_name = fields.Str(required=False, allow_none=True)

@vault_bp.route('/files/action', methods=['POST'])
def file_action():
    try:
        data = FileActionSchema().load(request.json)
    except ValidationError as err:
        return jsonify({'success': False, 'errors': err.messages}), 400
    # ... rest of logic
```

---

#### ⚠️ **3. Sem rate limiting de upload**
**Problema**: Nenhuma validação de tamanho de arquivo:

```python
@vault_bp.route('/process/start', methods=['POST'])
def start_process():
    data = request.json
    raw_path = data.get('path')
    # Sem verificação: file size, disk space, etc.
```

**Recomendação**:
```python
MAX_FILE_SIZE = int(os.getenv('MAX_FILE_SIZE', 5 * 1024 ** 3))  # 5GB default

def start_process():
    file_size = os.path.getsize(path)
    if file_size > MAX_FILE_SIZE:
        return jsonify({'success': False, 'msg': f'File too large (>{MAX_FILE_SIZE}GB)'}), 413
```

---

### 4.3 Web Interface: Scorecard

| Critério | Score | Observação |
|----------|-------|-----------|
| CSRF Protection | 8/10 | Implementado; desktop mode desabilita |
| CSP | 9/10 | Bem configurado |
| Rate Limiting | 7/10 | Global; não por endpoint |
| Input Validation | 3/10 | Nenhuma schema; sanitização parcial |
| HTTPS/TLS | 5/10 | Requer reverse proxy em produção |

---

## 🧪 5. Testes & Cobertura

### 5.1 Status Atual

```
tests/
├── test_auth.py              (~30 linhas)
├── test_aws_kms.py          (~40 linhas)
├── test_crypto_engine.py    (~20 linhas) ✓
├── test_kms_integration.py  (~50 linhas)
├── test_stream_engine.py    (~30 linhas)
└── test_vault_manager.py    (~40 linhas)

Total: ~210 linhas de teste
```

**Cobertura estimada**: < 20% (baseado em análise manual)

### 5.2 Testes Existentes

| Teste | Coverage | Observação |
|-------|----------|-----------|
| `test_wrap_unwrap_master_key` | ✅ | Verifica roundtrip |
| `test_unwrap_wrong_password_raises` | ✅ | Testa erro |
| Outros | ❓ | Não testei; refatoração pode ter quebrado |

### 5.3 Testes Críticos Faltando

1. **Criptografia**:
   - Nonce collision/reuse
   - Tag authentication failure
   - Large file encryption/decryption
   - AEAD with associated data

2. **Autenticação**:
   - Login com timeout
   - 2FA roundtrip completo
   - Rate limiting
   - Session cleanup

3. **Vault**:
   - File encrypt/decrypt roundtrip
   - Manifest integrity
   - KMS envelope mode
   - Path traversal prevention

4. **API**:
   - CSRF token validation
   - Input validation (schema)
   - Error responses
   - Concurrency (multiple users)

### 5.4 Recomendação: Estratégia de Teste

```python
# pytest.ini
[pytest]
testpaths = tests
python_files = test_*.py
addopts = --cov=core --cov=api --cov-report=html --cov-report=term

# Objetivo: 70% coverage
# Crítico: 100% em core/crypto/, core/auth/, core/vault/
```

---

## 📖 6. Documentação

### 6.1 O que existe

| Arquivo | Qual | Status |
|---------|------|--------|
| [README.md](README.md) | Overview, features, install | ✅ Bom |
| [SECURITY.md](SECURITY.md) | Threat model, best practices | ✅ Bom |
| [ROADMAP.md](ROADMAP.md) | Futuras features | ✅ OK |
| [docs/](docs/) | Vários guides | ⚠️ Alguns desatualizados |
| Docstrings | Em módulos | ⚠️ Inconsistentes |

### 6.2 O que falta

1. **API Documentation**
   - Endpoint specs (request/response schema)
   - Error codes e tratamento
   - Rate limit info
   
2. **Architecture Guide**
   - Diagrama de componentes (agora temos em fluxograma)
   - Fluxo de dados (plaintext → encrypted)
   - Fluxo de autenticação (login → 2FA → session)

3. **Deployment Guide**
   - Configuração para produção
   - HTTPS setup
   - Database migration
   - KMS setup (AWS)

4. **Code Comments**
   - Faltam docstrings em funções críticas
   - Nenhum diagrama de sequência

### 6.3 Recomendações

```python
# Exemplo: adicionar docstrings detalhados

def wrap_master_key(self, master_key: bytes, password: str) -> dict:
    """
    Encrypts the Master Key using the user's password.
    
    This implements the "Master Key Architecture" pattern:
    - Master Key (MK): Random 256-bit key, stored encrypted
    - Key Encryption Key (KEK): Derived from password via Argon2id
    - Wrapped MK: AES-GCM(KEK, MK)
    
    Args:
        master_key: 256-bit random key to wrap
        password: User password (not the hash)
    
    Returns:
        dict with keys:
            - salt: Base64-encoded Argon2 salt (16 bytes)
            - nonce: Base64-encoded AES-GCM nonce (12 bytes)
            - ciphertext: Base64-encoded AES-GCM ciphertext
            - aead: Algorithm name ('AESGCM' or 'XCHACHA20')
    
    Security Notes:
        - Nonce is generated fresh every call (critical for AES-GCM security)
        - KEK derivation is intentionally slow (Argon2: ~200ms)
        - Allows password change without re-encrypting file data
    
    Raises:
        ValueError: If master_key is wrong size
    """
    ...
```

---

## 🏗️ 7. Arquitetura Geral

### 7.1 Pontos Fortes

- **Separação clara de camadas**: API → Core → Crypto
- **Stateless endpoints**: Cada request valida session
- **Modular KMS**: Suporta multiple backends (file, AWS)
- **Audit logging**: Estruturado e persistido

### 7.2 Melhorias Propostas

1. **Dependency Injection**: Passar managers como args em vez de usar `_get_managers()` global
2. **Error Handling**: Classe base `CamelliaException` com codes
3. **Config Management**: Usar pydantic Settings em vez de env vars espalhados
4. **Logging**: Logger estruturado (já usa JSON, mas não centralizado)

---

## 🔧 8. Qualidade de Código

### 8.1 Pontos Fortes

- **Type hints**: Presentes em funções críticas
- **Error handling**: Try-except em operações risky
- **Security mindset**: Validação, sanitização, rate limiting

### 8.2 Áreas a melhorar

| Aspecto | Issue | Severity |
|---------|-------|----------|
| **Unused imports** | Alguns modules importados não usados | ⚠️ Baixa |
| **Docstrings** | Inconsistentes/faltando | ⚠️ Média |
| **Type hints** | Nem todas as funções têm | ⚠️ Média |
| **Error messages** | Genéricos ("Critical: Key Unwrapping Failed") | ⚠️ Média |
| **Magic numbers** | 256 (key len), 300 (timeout) sem constantes | ⚠️ Baixa |
| **Global state** | `_temp_login_state`, `current_master_key` | ⚠️ Alta |

---

## 📊 9. Scorecard Geral

| Categoria | Score | Trend |
|-----------|-------|-------|
| **Segurança Criptográfica** | 8/10 | ↗ (bom, mas faltam testes) |
| **Autenticação** | 7/10 | → (solido, mas session handling é fraco) |
| **Gerenciamento de Arquivo** | 6/10 | ↘ (path validation incompleto) |
| **API & Web** | 7/10 | → (CSP/CSRF ok, validação fraca) |
| **Testes** | 2/10 | ↘ (crítico: precisa expandir muito) |
| **Documentação** | 6/10 | → (bom overview, faltam detalhes) |
| **Código** | 7/10 | → (legível, mas refactor needed) |
| **Arquitetura** | 8/10 | ↗ (modular, bem separado) |

**Score Geral: 6.4/10**

---

## 🚀 10. Prioridades para Melhorias

### 🔴 CRÍTICO (Sprint 1)

1. **Path traversal validation** — Implementar validação contra jailbreak
2. **Session timeout** — Verificar timeout em `get_session()`
3. **Thread safety** — Adicionar locks em session storage
4. **Test coverage** — Expandir testes de crypto e vault
5. **Input validation** — Adicionar schema validation (marshmallow/pydantic)

### 🟡 IMPORTANTE (Sprint 2)

6. **Error handling** — Logging consistente, mensagens específicas
7. **API documentation** — OpenAPI/Swagger spec
8. **Deployment guide** — Production setup
9. **Manifest encryption** — Migrar Fernet → AES-GCM
10. **2FA flow documentation** — Clarificar fluxo completo

### 🟢 BOM TER (Sprint 3+)

11. **Performance tuning** — Benchmark encrypt/decrypt
12. **Rate limit by endpoint** — Mais granular
13. **Hardware key support** — YubiKey, TPM
14. **Mobile app** — React Native viewer

---

## 📝 11. Exemplo: Fix para Path Traversal

```python
# core/security/path_validator.py
import os
from pathlib import Path

class PathValidator:
    """Validates and sanitizes file paths to prevent jailbreak."""
    
    @staticmethod
    def validate(user_path: str, base_dir: str = None, require_exists: bool = False) -> tuple[bool, Path, str]:
        """
        Validates user-provided path against jailbreak.
        
        Returns:
            (is_valid, resolved_path, error_message)
        """
        if base_dir is None:
            base_dir = os.path.expanduser("~")
        
        if not user_path:
            return (False, Path(base_dir), "Path cannot be empty")
        
        # Prevent path traversal with .., null bytes, etc.
        if '\x00' in user_path or user_path.count('..') > 0:
            return (False, Path(base_dir), "Invalid path characters")
        
        # Resolve relative to base
        if os.path.isabs(user_path):
            # Absolute paths are not allowed
            return (False, Path(base_dir), "Absolute paths not allowed")
        
        full_path = Path(base_dir).resolve() / user_path
        
        try:
            # Verify path is under base_dir
            full_path.resolve().relative_to(Path(base_dir).resolve())
        except ValueError:
            return (False, Path(base_dir), f"Path escapes base directory")
        
        if require_exists and not full_path.exists():
            return (False, full_path, "Path does not exist")
        
        return (True, full_path, "")
```

**Uso em api/vault.py**:
```python
from core.sys.fs import PathValidator

@vault_bp.route('/files/action', methods=['POST'])
def file_action():
    data = request.json
    action = data.get('action')
    raw_path = data.get('path')
    
    is_valid, path_obj, error = PathValidator.validate(raw_path, require_exists=True)
    if not is_valid:
        return jsonify({'success': False, 'msg': error}), 400
    
    # ... use path_obj safely
```

---

## 📋 Conclusão

**Camellia Shield** é uma aplicação **bem fundada em segurança criptográfica**, com boa separação de concerns e implementação sólida de:
- Argon2id KDF
- Master Key Architecture
- AES-GCM encryption
- Audit logging
- CSRF/CSP proteção

**Mas precisa urgentemente**:
1. **Expandir testes** (< 20% cobertura → alvo 70%)
2. **Validação de path** (path traversal risk)
3. **Session timeout** (race condition risk)
4. **Input validation** (API robustez)

Com essas melhorias, o score geral pode subir de **6.4/10 → 8.5/10**.

---

**Próximos passos recomendados**:
1. [ ] Fork repo e criar branch `improve/security-hardening`
2. [ ] Implementar path traversal fix + testes
3. [ ] Adicionar schema validation em API
4. [ ] Expandir testes de crypto/auth
5. [ ] Documentar API com Swagger/OpenAPI
6. [ ] Setup CI/CD com pytest + coverage
7. [ ] Code review com security focus
8. [ ] Penetration testing (contratar consultoria se possível)

