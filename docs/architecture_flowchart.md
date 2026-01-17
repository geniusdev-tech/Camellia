## Fluxograma de arquitetura do sistema

Abaixo segue um fluxograma em Mermaid que descreve os componentes principais, pontos de entrada e integrações externas do sistema.

```mermaid
graph TD
  subgraph Desktop
    DL[Desktop Launcher\n(webview)]
  end

  subgraph AppProcess
    MAIN[`main.py`] -->|inicia| FLASK[Flask App\n(`create_app()` in `app.py`)]
    FLASK --> UI[Frontend (templates + static)]
    UI -->|AJAX / form| FLASK
    FLASK -->|register_blueprint| AUTH_BP[/api/auth]
    FLASK -->|register_blueprint| VAULT_BP[/api/*]
  end

  subgraph API
    AUTH_BP -->|calls| AUTH_SVC[AuthManager (services.auth_manager)\nDB: SQLite]
    VAULT_BP -->|calls| VAULT_SVC[VaultManager (services.vault_manager)]
    VAULT_BP -->|queuing| TASKS[TaskManager (services.task_manager)]
    VAULT_BP -->|device info| DEV[DeviceManager]
  end

  subgraph Core
    TASKS -->|worker| WORKER[Task Worker]
    WORKER --> CRYPTO[Crypto Engine]
    WORKER --> KMS[Configured KMS Provider\n(FileKMS or AWSKMS)]
    WORKER --> FS[Filesystem (local files)]
    AUTH_SVC --> DB[(SQLite DB)]
    FLASK -->|init| LOG[Structured Logging]
    FLASK -->|init| AUDIT[Audit Logger (local file)]
    LOG --> SIEM[(Optional SIEM endpoint)]
    AUDIT -->|writes| AUDIT_FILE[audit.log]
  end

  subgraph External
    AWS[KMS AWS (optional)]
  end

  KMS -->|if AWS provider| AWS
  DL --> MAIN

  style FLASK fill:#f9f,stroke:#333,stroke-width:1px
  style WORKER fill:#ff9,stroke:#333,stroke-width:1px

  %% Legend
  classDef comp fill:#eef,stroke:#333;
  class FLASK,AUTH_SVC,VAULT_SVC,CRYPTO comp;

``` 

Observações rápidas:
- Entradas: `main.py` (desktop) e `app.py` (pode rodar standalone/WSGI).
- Rotas principais: `api/auth.py` (autenticação/2FA), `api/vault.py` (operações de ficheiro/processos).
- `services.py` possui instâncias de `auth_manager`, `vault_manager`, `task_manager` referenciadas pelas blueprints.
- KMS configurável: `core.kms.file_kms.FileKMS` (local) ou `core.kms.aws_kms.AWSKMSProvider` (AWS).

Próximo passo: exportar para SVG/PNG. Posso gerar um SVG localmente (usando `mmdc` / `mermaid-cli`) ou fornecer o arquivo Markdown para você visualizar no VS Code.

```bash
# instalar mermaid-cli (node) e gerar SVG:
npm install -g @mermaid-js/mermaid-cli
mmdc -i docs/architecture_flowchart.md -o docs/architecture_flowchart.svg
```

Ou abrir o arquivo `docs/architecture_flowchart.md` no VS Code com extensão Mermaid Preview.
