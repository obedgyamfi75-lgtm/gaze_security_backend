# =============================================================================
# STAGE 1: Build dependencies
# =============================================================================
FROM python:3.12-slim-bookworm AS builder

WORKDIR /build

# Install build dependencies (including for WeasyPrint)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    libffi-dev \
    libpango1.0-dev \
    libgdk-pixbuf2.0-dev \
    libcairo2-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY requirements/base.txt requirements/security.txt ./
RUN pip install --no-cache-dir --upgrade pip wheel \
    && pip install --no-cache-dir -r base.txt -r security.txt

# =============================================================================
# STAGE 2: Production image
# =============================================================================
FROM python:3.12-slim-bookworm AS production

# Security: Create non-root user
RUN groupadd -r secops && useradd -r -g secops -d /app -s /sbin/nologin secops

# Install runtime dependencies only (including WeasyPrint deps)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 \
    libffi8 \
    shared-mime-info \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean \
    && rm -rf /var/cache/apt/archives/*

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONHASHSEED=random

WORKDIR /app

# Copy application code
COPY --chown=secops:secops app/ ./app/
COPY --chown=secops:secops migrations/ ./migrations/
COPY --chown=secops:secops run.py config.py ./

# Create necessary directories with correct permissions
RUN mkdir -p /app/evidence /app/logs \
    && chown -R secops:secops /app

# Security: Set restrictive permissions
RUN chmod -R 500 /app/app \
    && chmod 700 /app/evidence /app/logs

# Switch to non-root user
USER secops

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

# Run with gunicorn
CMD ["gunicorn", \
     "--bind", "0.0.0.0:8000", \
     "--workers", "4", \
     "--worker-class", "gthread", \
     "--threads", "2", \
     "--worker-tmp-dir", "/dev/shm", \
     "--timeout", "30", \
     "--keep-alive", "5", \
     "--max-requests", "1000", \
     "--max-requests-jitter", "50", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "--capture-output", \
     "--enable-stdio-inheritance", \
     "app:create_app()"]
