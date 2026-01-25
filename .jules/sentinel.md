## 2026-01-25 - [MFA Session Bypass]
**Vulnerability:** The MFA verification endpoint (`/api/auth/login/mfa`) allowed the `user_id` to be specified in the request body, bypassing the requirement that the first factor must have been completed in the same session.
**Learning:** Even if a global key manager is used to store temporary authentication state, the identity of the user must be strictly tied to the session (e.g., via signed cookies) to prevent attackers from "hijacking" the pre-authenticated state of another user by providing their user ID.
**Prevention:** Always retrieve user identity from the session or a validated JWT, never from untrusted request parameters in multi-step authentication flows.
