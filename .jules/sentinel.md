# Sentinel Security & Architecture Log

## 2026-04-03: Render Deployment & Makefile Fix

### Findings
- Render deployment was failing due to PyInstaller attempting to run on a Python environment without `--enable-shared`.
- The root `package.json` was triggering a full Tauri build (`make build`) which is not suitable for a web-only Render deployment.
- The CI benchmark job was failing due to a missing `scripts/argon2_bench.py` file.

### Actions
- Implemented a `build-web` target in the `Makefile` to prepare Next.js assets for Flask.
- Modified the `bundle-backend` target to skip execution on Render, avoiding PyInstaller errors.
- Updated the root `package.json` to use `make build-web` for Render deployments.
- Restored `scripts/argon2_bench.py` to fix the CI failure.
- Updated `app.py` to serve the frontend from `static/dist` and added catch-all routing.
- Hardened production session cookies and automated `SECRET_KEY` generation in `render.yaml`.

### Security Note
- Local `flask_session/` artifacts have been removed and should be ignored.
- The application now correctly binds to `0.0.0.0` in production to receive traffic.
