# Vault Transit On VPS

Este diretório sobe um Vault com storage em disco local, exposto por HTTPS via Caddy.

## Estrutura

- `docker-compose.yml`: Vault + Caddy
- `config/vault.hcl`: config do Vault
- `Caddyfile`: TLS automático e reverse proxy
- `bootstrap-transit.sh`: habilita Transit, cria a key e gera policy/token
- `.env.example`: variáveis mínimas do stack

## Pré-requisitos

- VPS Linux com Docker e Docker Compose
- DNS apontando para o VPS
- domínio ou subdomínio, por exemplo `vault.seudominio.com`

## Uso

1. Copie esta pasta para o VPS.
2. Crie `.env` a partir de `.env.example`.
3. Ajuste `DOMAIN` e `VAULT_API_ADDR`.
4. Suba a stack:

```bash
docker compose up -d
```

5. Inicialize o Vault:

```bash
docker compose exec vault vault operator init
```

6. Guarde as unseal keys e o root token.
7. Faça unseal:

```bash
docker compose exec vault vault operator unseal
```

Repita até atingir o threshold configurado.

8. Rode o bootstrap do Transit:

```bash
./bootstrap-transit.sh
```

O script vai:
- habilitar `transit/` se necessário
- criar a key `camellia`
- criar a policy mínima `camellia-transit`
- gerar um token restrito para a aplicação

## Vercel

Depois do bootstrap, configure estas envs no projeto:

- `KMS_PROVIDER=transit`
- `VAULT_ADDR=https://vault.seudominio.com`
- `VAULT_TOKEN=<token-gerado-pelo-script>`
- `VAULT_TRANSIT_KEY_NAME=camellia`
- `VAULT_TRANSIT_MOUNT=transit`

## Observações

- O Vault não deve ser exposto sem HTTPS.
- O root token não deve ser usado pela aplicação.
- Troque o storage para Raft ou backend gerenciado se quiser alta disponibilidade.
