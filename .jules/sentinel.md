## 2025-05-22 - [MFA Session Isolation]
**Vulnerability:** The MFA verification endpoint (`/api/auth/login/mfa`) allowed providing a `user_id` in the request body, which could bypass session isolation if a user guessed another user's ID while they were in a pending authentication state.
**Learning:** Authenticated state transitions (like MFA completion) must strictly rely on server-side session state established in the first factor to prevent session fixation or brute-force probing of other users' MFA codes.
**Prevention:** Never allow client-provided identifiers to specify the subject of a multi-step authentication process once the process has started; use secure, server-side session cookies to track the "pre-auth" user.

## 2025-05-22 - [Generic Security Errors]
**Vulnerability:** API endpoints were returning raw exception messages to the client, potentially leaking filesystem paths, database structure, or cryptographic failures.
**Learning:** Information leakage via verbose error messages (MFA Oracles) can aid attackers in reconnaissance.
**Prevention:** Log detailed errors to secure server-side logs and return generic, non-descriptive error messages to the user.
