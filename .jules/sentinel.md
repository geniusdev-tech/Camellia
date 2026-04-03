# Sentinel Security & Architecture Log

## 2026-04-03: Backend Migration to Node.js / TypeScript

### Findings
- The Python backend (Flask) was replaced with a Node.js (Express) backend for better frontend/backend stack alignment.
- SQLAlchemy models were migrated to Prisma to leverage its strong typing and modern developer experience.
- The original security requirements (JWT with family-based rotation, MFA, RBAC) were ported to the new Express architecture.

### Actions
- Initialized Node.js environment in `backend/` directory.
- Created `prisma/schema.prisma` mapping the existing database structure.
- Implemented Express routes for `auth`, `access`, `projects`, `audit`, and `ops`.
- Ported security middlewares: `requireAuth`, `requirePermission`, and `requestObservability`.
- Updated `Dockerfile` to use a Node.js runtime and handle multi-stage builds for both frontend and backend.
- Set up a clean database initialization script in TypeScript (`src/scripts/init-db.ts`).

### Architecture Changes
- **Database:** Shift from SQLAlchemy (Python) to Prisma (TypeScript).
- **Server:** Shift from Flask to Express.
- **Security:** Standardized on JWT for session management, maintaining functional parity with the previous implementation's rotation and revocation logic.
- **Deployment:** Render and Docker configurations updated to serve the Node.js application.

### Security Note
- CORS and Helmet were configured to maintain the same hardening standards as the Flask version.
- MFA logic ported using `otplib` to ensure continued support for 2FA.
