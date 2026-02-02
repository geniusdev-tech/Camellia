# Sentinel Journal - Critical Security Learnings

## 2026-02-02 - MFA Probing Vulnerability in login_mfa
**Vulnerability:** The MFA verification endpoint `/api/auth/login/mfa` allowed `user_id` to be passed in the request body, which took precedence over the session. Additionally, it returned different error messages for correct vs incorrect TOTP codes even when no valid session/pending key was present.
**Learning:** This combination allowed an attacker to probe the system to discover valid TOTP codes for any user ID without knowing their password.
**Prevention:** Always strictly use session-bound identifiers for multi-step authentication. Ensure that authentication failure messages are generic and that resource-intensive or sensitive checks (like TOTP verification) are only performed after verifying that the session is in the correct state (e.g., pending MFA after successful password check).
