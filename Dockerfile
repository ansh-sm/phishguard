# syntax=docker/dockerfile:1
# -----------------------------------------------------------------------------
# PhishGuard SOC: Hardened Multi-Stage Production Container
# -----------------------------------------------------------------------------

# Stage 1: Build & Dependency Wheel Cache
FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir build && \
    pip wheel --no-cache-dir --wheel-dir /build/wheels .

# Stage 2: Minimal Distroless/Slim Production Runtime
FROM python:3.12-slim AS runner

LABEL maintainer="PhishGuard Security Engineering Team"
LABEL org.opencontainers.image.title="PhishGuard SOC"
LABEL org.opencontainers.image.description="Enterprise Automated Phishing Detection & Threat Intelligence Platform"

# Security: Create dedicated unprivileged system user & group
RUN groupadd -g 10001 phishguard && \
    useradd -u 10001 -g phishguard -s /usr/sbin/nologin -M phishguard

WORKDIR /app

# Install compiled wheels from builder
COPY --from=builder /build/wheels /wheels
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir /wheels/* && \
    rm -rf /wheels

# Copy application assets and enterprise detection rules
COPY rules/ /app/rules/
COPY samples/ /app/samples/

# Setup persistent data directories with non-root ownership
RUN mkdir -p /app/data /app/quarantine /app/alerts && \
    chown -R phishguard:phishguard /app

USER phishguard:phishguard

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/home/phishguard/.local/bin:${PATH}"

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')" || exit 1

ENTRYPOINT ["phishguard"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
