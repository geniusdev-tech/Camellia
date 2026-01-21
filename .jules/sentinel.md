## 2025-05-14 - MFA Oracle Vulnerability
**Vulnerability:** The `/api/auth/login/mfa` endpoint allowed `user_id` to be passed via JSON, bypassing session-bound pre-authentication. It also returned different error messages for correct vs. incorrect TOTP codes even when the session was missing, creating a TOTP oracle.
**Learning:** Decoupling user identification from the session state in multi-factor authentication flows can introduce oracles and bypasses.
**Prevention:** Always enforce that subsequent authentication factors are tied to the same session that successfully completed the initial factor. Use generic error messages for all failures in the authentication flow.
