# Sentinel Journal - Camellia Shield 🛡️

## 2026-01-30 - Hardening Authentication & Preventing Information Leakage

**Vulnerability:**
1. **MFA Oracle / Probing:** The `/api/auth/login/mfa` endpoint allowed passing `user_id` in the request body, which could be used to probe if a user has MFA enabled or attempt to brute-force MFA codes without a valid session from the first factor (password).
2. **Information Leakage via Error Messages:** Authentication endpoints revealed account state (e.g., "Conta desativada") or internal key management errors. Vault API endpoints leaked internal system details via `str(e)` in JSON responses.

**Learning:**
The application was in a transition phase between two authentication systems, and the newer IAM implementation had some "convenience" fallbacks (like allowing `user_id` in the body for debugging/testing) that became security liabilities. Also, standard Flask error handling often defaults to being too verbose if not explicitly hardened.

**Prevention:**
- **Session-Bound Multi-Factor Authentication:** Always strictly bind the second factor to a session identifier established after the first factor is successfully verified. Never allow identifying the user via the request body in subsequent authentication steps.
- **Fail Securely with Generic Messages:** Authentication failures should always return a generic message (e.g., "Credenciais inválidas") and a 401 status code, regardless of whether the user exists, is deactivated, or if the failure was due to an internal cryptographic error.
- **Sanitize API Exceptions:** Never return raw exception strings to the client. Log detailed errors internally and return a generic "Operation failed" message to the user.
