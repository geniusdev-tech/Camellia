# Integração OIDC + Enforce MFA (guia rápido)

1. Escolher provedor OIDC (Auth0, Keycloak, Azure AD, etc.)
2. Registrar aplicação e obter `CLIENT_ID` / `CLIENT_SECRET`.
3. Configurar `redirect_uri` para `/auth/callback`.
4. Exigir `amr` claim com métodos de MFA (ex: `mfa`), ou usar `acr` para políticas.
5. No backend, validar `id_token`, checar `email_verified` e `amr`.
6. Provisionar roles via claims e reforçar administração via SSO + MFA.

Exemplo: adicionar variáveis env `OIDC_CLIENT_ID`, `OIDC_ISSUER`, `OIDC_CLIENT_SECRET`.
