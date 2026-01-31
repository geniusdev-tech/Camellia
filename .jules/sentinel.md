## 2026-01-10 - [MFA Session Binding Vulnerability]
**Vulnerability:** The MFA endpoint (`/api/auth/login/mfa`) allowed providing a `user_id` in the request body, which took precedence over or supplemented the session-based `pre_auth_user_id`. This allowed an attacker to attempt MFA verification for any user without a valid pre-authentication session.
**Learning:** Authenticated multi-step flows (like MFA) must strictly bind the entire process to a single session. Allowing user-provided identifiers to override session state creates a probing and brute-force vector.
**Prevention:** Always retrieve stateful identifiers (like `user_id`) directly from the session or a signed token during multi-step authentication. Avoid falling back to request parameters for sensitive context.
