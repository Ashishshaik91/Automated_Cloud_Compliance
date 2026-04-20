# ============================================================
#  Backend Dockerfile — Cloud Compliance Platform
#  Security-hardened, non-root, multi-stage build
# ============================================================

# --- Stage 1: Build deps ---
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

# Install build deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install --prefix=/install --no-cache-dir -r requirements.txt

# --- Stage 2: Runtime ---
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/install/bin:$PATH" \
    PYTHONPATH="/install/lib/python3.11/site-packages:$PYTHONPATH"

# Runtime system libs only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r appgroup \
    && useradd -r -g appgroup -d /app -s /sbin/nologin appuser

COPY --from=builder /install /install
WORKDIR /app
COPY app/ ./app/
# Create policies dir first so COPY doesn't fail if the folder is empty
RUN mkdir -p ./policies
COPY policies/ ./policies/

# Copy remediation runbooks
RUN mkdir -p ./runbooks
COPY runbooks/ ./runbooks/

# Copy Alembic files
COPY alembic.ini .
COPY alembic/ ./alembic/

# Copy JWT RSA keys (private key for signing, public key for verification)
RUN mkdir -p ./keys
COPY keys/ ./keys/

# Set correct ownership
RUN chown -R appuser:appgroup /app

USER appuser
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
