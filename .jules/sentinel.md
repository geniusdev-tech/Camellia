## 2025-05-14 - [MFA Session Bypass and Probing]
**Vulnerability:** The MFA verification endpoint accepted `user_id` from the request body as a fallback when not present in the session. This allowed attackers to probe MFA status of any user and potentially brute-force MFA codes without having completed the first authentication factor in the same session.
**Learning:** Even when using sessions, providing fallbacks to request parameters for sensitive identifiers can introduce bypasses. The state of authentication must be strictly tied to the server-side session.
**Prevention:** Always retrieve user identity from a trusted server-side session after the first factor is verified. Never allow the client to specify the user identity during subsequent authentication steps (like MFA).
