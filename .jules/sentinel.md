## 2026-01-10 - Enforced Strict MFA Session Binding
**Vulnerability:** The MFA verification endpoint (`/api/auth/login/mfa`) allowed providing a `user_id` in the request body as a fallback. This allowed attackers to probe for valid MFA codes for arbitrary users without a valid pre-authentication session.
**Learning:** Fallback mechanisms in security-critical paths can introduce unexpected vulnerabilities by allowing user-controlled input to override trusted session state.
**Prevention:** Strictly enforce session binding in multi-step authentication flows by exclusively using session-stored identifiers.
