#!/usr/bin/env python3
"""
Generate per-OS user guides (HTML) for Camellia Shield.
Output goes to docs/user-guide/
"""
import os, textwrap

OUT = os.path.join(os.path.dirname(__file__), "..", "docs", "user-guide")
os.makedirs(OUT, exist_ok=True)

# ── Shared CSS & header ───────────────────────────────────────────────────────
CSS = """
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #c9d1d9;
       line-height: 1.7; padding: 2rem; max-width: 860px; margin: 0 auto; }
h1  { font-size: 2rem; color: #58a6ff; margin-bottom: 0.25rem; }
h2  { font-size: 1.3rem; color: #8b949e; margin: 2rem 0 0.5rem; border-bottom: 1px solid #30363d; padding-bottom: 0.4rem; }
h3  { font-size: 1rem; color: #58a6ff; margin: 1.2rem 0 0.3rem; }
p   { margin: 0.5rem 0; }
ul  { padding-left: 1.5rem; margin: 0.5rem 0; }
li  { margin: 0.3rem 0; }
code, pre { background: #161b22; border: 1px solid #30363d; border-radius: 6px; }
code { padding: 0.1em 0.4em; font-size: 0.9em; color: #79c0ff; }
pre  { padding: 1rem; overflow-x: auto; margin: 0.8rem 0; }
pre code { background: none; border: none; padding: 0; color: #e3b341; }
.badge { display: inline-block; padding: 0.2em 0.7em; border-radius: 20px; font-size: 0.78rem; font-weight: 600; }
.badge-ok  { background: #0d4429; color: #3fb950; border: 1px solid #196c2e; }
.badge-warn{ background: #3d2c00; color: #e3b341; border: 1px solid #6e4700; }
.tip   { background: #051d3c; border-left: 3px solid #58a6ff; padding: 0.7rem 1rem; margin: 1rem 0; border-radius: 0 8px 8px 0; }
.warn  { background: #2d1700; border-left: 3px solid #e3b341; padding: 0.7rem 1rem; margin: 1rem 0; border-radius: 0 8px 8px 0; }
.danger{ background: #300; border-left: 3px solid #f85149; padding: 0.7rem 1rem; margin: 1rem 0; border-radius: 0 8px 8px 0; }
footer { margin-top: 4rem; font-size: 0.8rem; color: #484f58; text-align: center; }
a { color: #58a6ff; text-decoration: none; }
a:hover { text-decoration: underline; }
</style>
"""

def page(title: str, os_name: str, body: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} — Camellia Shield</title>{CSS}</head>
<body>
<h1>🛡️ Camellia Shield</h1>
<p style="color:#8b949e;margin-bottom:2rem">Guia do Usuário — <strong style="color:#c9d1d9">{os_name}</strong></p>
{body}
<footer>Camellia Shield v2.1 · AES-256-GCM · Argon2id · Ed25519 · MIT License</footer>
</body></html>"""

# ── Shared sections ───────────────────────────────────────────────────────────
INTRO = """
<h2>Introdução</h2>
<p>O <strong>Camellia Shield</strong> é uma plataforma de criptografia local com arquitetura Zero-Trust.
Todos os arquivos são cifrados com <strong>AES-256-GCM</strong> antes de tocarem o disco,
e a chave-mestra nunca é gravada em plaintext.</p>
<div class="tip"><strong>Dica:</strong> Para maior segurança, ative o 2FA (TOTP) após o primeiro login.</div>

<h2>Início Rápido</h2>
<ol>
  <li>Crie uma conta em <strong>Registrar</strong> com e-mail e senha forte (≥ 12 caracteres).</li>
  <li>Faça login. Na tela de Dashboard, navegue até a pasta desejada.</li>
  <li>Selecione os arquivos → clique em <strong>Executar</strong> → escolha <em>Criptografar</em>.</li>
  <li>Para descriptografar, selecione os arquivos cifrados (ícone 🔒) e escolha <em>Descriptografar</em>.</li>
</ol>
"""

SECURITY = """
<h2>Segurança</h2>
<h3>Hierarquia de Chaves</h3>
<pre><code>Senha → Argon2id → KEK → AES-GCM → Chave Mestra → Subchaves por arquivo</code></pre>
<ul>
  <li>A <strong>Chave Mestra</strong> existe apenas em RAM durante a sessão.</li>
  <li>O <strong>Manifesto do cofre</strong> é assinado com Ed25519 — qualquer adulteração é detectada.</li>
  <li>O botão <strong>Panic Wipe</strong> (Configurações) apaga as chaves da memória imediatamente.</li>
</ul>
<div class="warn"><strong>Atenção:</strong> Não há backdoor. Se perder a senha <em>e</em> não tiver backup, os dados são irrecuperáveis.</div>

<h3>Deep Integrity Inspection (DII)</h3>
<p>Clique no ícone 🛡 ao lado de qualquer arquivo para verificar:</p>
<ul>
  <li><strong>SHA-256 + BLAKE2b</strong> — integridade criptográfica</li>
  <li><strong>Magic Bytes</strong> — detecta extensão falsificada</li>
  <li><strong>Entropia Shannon</strong> — identifica scripts ofuscados/empacotados</li>
</ul>
"""

FAQ = """
<h2>FAQ</h2>
<h3>Posso usar em rede local?</h3>
<p>Em modo servidor (<code>DESKTOP_MODE=0</code>) o backend Flask aceita conexões na LAN.
Recomendamos TLS com nginx ou Caddy na frente.</p>

<h3>O app funciona offline?</h3>
<p>Sim — criptografia e descriptografia funcionam 100% offline. Nenhum dado sai do dispositivo.</p>

<h3>KMS em produção?</h3>
<p>Configure <code>KMS_PROVIDER=aws</code> e <code>AWS_KMS_KEY_ID</code> para usar AWS KMS para envelope encryption.</p>
"""

# ── Linux guide ───────────────────────────────────────────────────────────────
LINUX_INSTALL = """
<h2>Instalação — Linux</h2>
<h3>Opção 1 — AppImage (recomendado)</h3>
<pre><code>chmod +x CamelliaShield_2.1.0_amd64.AppImage
./CamelliaShield_2.1.0_amd64.AppImage</code></pre>

<h3>Opção 2 — Debian / Ubuntu</h3>
<pre><code>sudo dpkg -i camellia-shield_2.1.0_amd64.deb</code></pre>

<h3>Opção 3 — RPM (Fedora / RHEL)</h3>
<pre><code>sudo rpm -i camellia-shield-2.1.0.x86_64.rpm</code></pre>

<h3>Opção 4 — Modo servidor (headless)</h3>
<pre><code>python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
FLASK_ENV=production SECRET_KEY=$(python3 -c "import secrets;print(secrets.token_hex(32))") \\
  PORT=5000 python3 app.py</code></pre>
<div class="tip">Use <code>systemd</code> ou <code>supervisor</code> para manter o processo em execução.</div>

<h2>Desinstalação</h2>
<pre><code># Debian / Ubuntu
sudo dpkg -r camellia-shield

# RPM
sudo rpm -e camellia-shield

# Dados do usuário (opcional — IRREVERSÍVEL se houver arquivos cifrados)
rm -rf ~/.camellia_enterprise.db ~/.camellia/</code></pre>
"""

# ── Windows guide ─────────────────────────────────────────────────────────────
WIN_INSTALL = """
<h2>Instalação — Windows</h2>
<h3>Instalador MSI (recomendado)</h3>
<ol>
  <li>Execute <code>CamelliaShield_2.1.0_x64_en-US.msi</code>.</li>
  <li>Siga o assistente de instalação.</li>
  <li>Um atalho será criado na Área de Trabalho e no Menu Iniciar.</li>
</ol>
<div class="tip">Windows SmartScreen pode exibir aviso na primeira execução — clique em <em>"Mais informações" → "Executar assim mesmo"</em>.</div>

<h3>Requisitos</h3>
<ul>
  <li>Windows 10 1903+ ou Windows 11</li>
  <li>WebView2 Runtime (instalado automaticamente pelo MSI)</li>
  <li>64-bit (x86_64)</li>
</ul>

<h2>Desinstalação</h2>
<p>Painel de Controle → Programas → Desinstalar <strong>Camellia Shield</strong>.</p>
<div class="warn">Dados cifrados em <code>%APPDATA%\\CamelliaShield</code> NÃO são removidos automaticamente.</div>
"""

# ── macOS guide ───────────────────────────────────────────────────────────────
MAC_INSTALL = """
<h2>Instalação — macOS</h2>
<h3>Disk Image (.dmg)</h3>
<ol>
  <li>Abra <code>CamelliaShield_2.1.0_universal.dmg</code>.</li>
  <li>Arraste <strong>Camellia Shield.app</strong> para a pasta <em>Applications</em>.</li>
  <li>Na primeira execução: <em>Finder → Applications → Control+clique → Abrir</em>.</li>
</ol>
<div class="tip">O app usa a <strong>Keychain</strong> do macOS para armazenar o SECRET_KEY de sessão de forma segura.</div>

<h3>Requisitos</h3>
<ul>
  <li>macOS 11 Big Sur ou superior</li>
  <li>Apple Silicon (M1+) ou Intel x86_64 — build universal inclui ambos</li>
</ul>

<h2>Desinstalação</h2>
<pre><code>rm -rf /Applications/CamelliaShield.app
rm -rf ~/Library/Application\\ Support/com.camellia.shield</code></pre>
"""

# ── Render & save ─────────────────────────────────────────────────────────────
GUIDES = [
    ("linux",   "Linux",   LINUX_INSTALL + INTRO + SECURITY + FAQ),
    ("windows", "Windows", WIN_INSTALL   + INTRO + SECURITY + FAQ),
    ("macos",   "macOS",   MAC_INSTALL   + INTRO + SECURITY + FAQ),
    ("readme",  "Geral",   INTRO + SECURITY + FAQ),
]

for slug, os_name, body in GUIDES:
    path = os.path.join(OUT, f"{slug}.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(page(f"Guia {os_name}", os_name, textwrap.dedent(body)))
    print(f"  ✓  {path}")

# Index page
index = f"""<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="UTF-8"><title>Camellia Shield — Documentação</title>{CSS}</head>
<body>
<h1>🛡️ Camellia Shield — Documentação</h1>
<p style="color:#8b949e;margin-bottom:2rem">v2.1 · Escolha o guia para o seu sistema operacional</p>
<ul>
  <li><a href="linux.html">🐧 Linux</a></li>
  <li><a href="windows.html">🪟 Windows</a></li>
  <li><a href="macos.html">🍎 macOS</a></li>
  <li><a href="readme.html">📄 Geral / Servidor</a></li>
</ul>
<footer>Camellia Shield v2.1 · MIT License</footer>
</body></html>"""

with open(os.path.join(OUT, "index.html"), "w", encoding="utf-8") as f:
    f.write(index)

print(f"  ✓  {os.path.join(OUT, 'index.html')}")
print("\nGuias gerados com sucesso!")
