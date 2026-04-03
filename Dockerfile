# ── Stage 1: Build Next.js frontend ─────────────────────────────────────────
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci --frozen-lockfile
COPY frontend/ ./
RUN npm run build

# ── Stage 2: Python runtime ──────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_ENV=production \
    DESKTOP_MODE=0

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev gcc && \
    rm -rf /var/lib/apt/lists/*

# Non-root user
RUN groupadd -r gatestack && useradd -r -g gatestack gatestack

WORKDIR /app

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY --chown=gatestack:gatestack . .

# Copy built frontend into static dir (Flask serves it)
COPY --from=frontend-builder --chown=gatestack:gatestack /app/frontend/out ./static/dist

# Initialise IAM DB
RUN python scripts/init_iam_db.py || true

USER gatestack
EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')"

CMD ["python", "app.py"]
