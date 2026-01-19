## 2026-01-10 - [2FA Pending State Race Condition]
**Vulnerability:** A race condition in the 2FA login flow where a single `_temp_login_state` variable was shared across all login attempts.
**Learning:** The `AuthManager` is a singleton shared across all Flask requests. Storing user-specific state in instance variables without proper indexing (e.g., by email or session ID) leads to state corruption and potential account takeover when multiple users log in concurrently.
**Prevention:** Always use dictionaries keyed by a unique user identifier (like email) or store temporary state in the user's session (e.g., Flask session) when dealing with multi-step authentication in shared service instances.
