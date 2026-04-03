# ── Stage 1: Build Next.js frontend ─────────────────────────────────────────
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci --frozen-lockfile
COPY frontend/ ./
RUN npm run build

# ── Stage 2: Python runtime with shared libs ─────────────────────────────────
FROM python:3.12-slim-bullseye AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_ENV=production \
    DESKTOP_MODE=0 \
    PORT=5000

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev gcc build-essential curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=root:root . .

COPY --from=frontend-builder /app/frontend/out ./static/dist

RUN python scripts/init_iam_db.py || true

EXPOSE 5000

CMD ["./scripts/start-server.sh"]
