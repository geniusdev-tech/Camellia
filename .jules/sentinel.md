## 2026-01-24 - Missing Integrity Verification in CAM3 format
**Vulnerability:** The `StreamEngine.decrypt_stream` method failed to update and verify the Blake2b integrity hash for the latest `CAM3` format, although it was correctly implemented for the older `CAM2` format.
**Learning:** Security regressions can occur when introducing new format versions if the validation logic is hardcoded to specific version flags instead of being feature-based or inclusive of newer versions.
**Prevention:** Use inclusive checks (e.g., `is_v3 or is_v2`) or, better, define format capabilities (e.g., `has_integrity_hash = True`) in a version-to-metadata mapping to ensure all relevant versions receive the same security treatments.
