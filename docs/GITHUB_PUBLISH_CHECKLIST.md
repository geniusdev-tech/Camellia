# Checklist: Preparar o repositório para publicar no GitHub sem vazar segredos

Antes de criar o repositório remoto e enviar (push), siga estes passos:

1. Verifique `.gitignore`
   - Confirme que arquivos sensíveis estão ignorados: `.env`, `kms.key`, `audit.log`, `.venv/`, etc.

2. Gerar `requirements-pinned.txt`
   - Rode `./scripts/pin_requirements.sh` em um ambiente limpo e revise `requirements-pinned.txt` antes de commitar.

3. Escaneie por segredos localmente
   - Execute `./scripts/check_secrets.sh`
   - Instale e rode `detect-secrets` para um scan mais aprofundado:

```bash
pip install detect-secrets pre-commit
detect-secrets scan > .secrets.baseline
detect-secrets audit .secrets.baseline
```

4. Instale hooks de pre-commit

```bash
pip install pre-commit
pre-commit install
pre-commit run --all-files
```

5. Remover arquivos sensíveis já comitados (se houver)
   - Se você já comitou segredos, remova-os do histórico usando `git filter-repo` ou `BFG Repo-Cleaner`.
   - Exemplo com git-filter-repo (instalar manualmente):

```bash
# remover file(s) do histórico
git filter-repo --path kms.key --invert-paths
```

6. Criar repositório no GitHub
   - Crie o repo via UI ou `gh repo create`.
   - Configure GitHub Secrets (Settings → Secrets) para: `SECRET_KEY`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `SNYK_TOKEN`, etc.

7. Proteja branches e ative CI
   - Ative branch protection em `main` e exija checks de CI (Actions).
   - Verifique se a workflow `.github/workflows/ci.yml` usa `requirements-pinned.txt` quando presente.

8. Commit final e push

```bash
git add .
git commit -m "chore: prepare repo for public GitHub (ignore secrets, pre-commit hooks)"
git push origin main
```

9. Pós-push
   - Verifique no GitHub Actions se os workflows passaram.
   - Se detectou segredos após o push, revogue as chaves imediatamente e remova do histórico.

Observações
- Nunca armazene chaves privadas, tokens ou certificados em commits.
- Use GitHub Secrets / Vaults para armazenar variáveis sensíveis para CI/CD.
- Este checklist reduz riscos, mas não garante 100% — recomendamos pentest/scan de SCA.
