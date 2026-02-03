## 2025-01-31 - [CRITICAL] StreamEngine Integrity Bypass Regression
**Vulnerability:** The `StreamEngine.decrypt_stream` method was only verifying the whole-file Blake2b integrity hash for CAM2 files, completely skipping the check for the newer CAM3 (v3) format.
**Learning:** Cryptographic version upgrades often introduce regressions if the logic relies on hardcoded version checks (like `if is_v2:`) instead of feature-based checks.
**Prevention:** Use feature-based or capability-based checks (e.g., `if expected_hash:`) to ensure security controls are applied consistently across all versions that support them.
