## 2024-05-22 - MFA Oracle Vulnerability
**Vulnerability:** MFA endpoints allowing `user_id` in the request body can lead to MFA probing/oracles if they distinguish between 'user not found/no MFA' and 'incorrect code'.
**Learning:** Even with a second factor, if the first factor's state (which user is authenticating) isn't strictly tied to the session/token, attackers can probe the second factor independently.
**Prevention:** Strictly retrieve the authenticated user's ID from a secure session or temporary pre-auth token, never from client-provided request bodies.
