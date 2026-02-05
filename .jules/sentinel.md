# Sentinel Journal - Critical Security Learnings

## 2026-02-05 - [Critical] Private Key Exposure in Git
**Vulnerability:** The private key `.audit_signing_key` used for signing audit logs was tracked by Git and not ignored by `.gitignore`.
**Learning:** Standard ignore patterns like `*.key` may not match hidden files or files without a traditional extension (e.g., `.audit_signing_key`).
**Prevention:** Explicitly list sensitive files in `.gitignore` and use `git ls-files` to periodically check for accidentally tracked secrets.

## 2026-02-05 - [High] Account Enumeration and MFA Probing
**Vulnerability:** Authentication endpoints returned different status codes and messages for different failure states (e.g., 403 for deactivated users, 400 vs 401 in MFA).
**Learning:** Inconsistent responses allow attackers to enumerate valid usernames and probe which accounts have MFA enabled.
**Prevention:** Normalize authentication responses to use a consistent status code (401 Unauthorized) and generic error messages regardless of the specific reason for failure (user not found, deactivated, wrong password, etc.).

## 2026-02-05 - [High] Broken MFA Session Isolation
**Vulnerability:** The `/api/auth/login/mfa` endpoint allowed providing a `user_id` in the request body as a fallback to the session-based ID.
**Learning:** Allowing request parameters to override session state in multi-step authentication flows can lead to security bypasses or information leaks.
**Prevention:** Strictly use session state (e.g., `pre_auth_user_id`) to track progress in multi-step flows and ignore any corresponding identifiers provided in the request body.
