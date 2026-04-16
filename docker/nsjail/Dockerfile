# =============================================================================
# PDF Sandbox - Secure WeasyPrint Container
# Isolated environment for PDF generation
# =============================================================================
FROM python:3.12-slim-bookworm

# Install WeasyPrint dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 \
    libffi8 \
    shared-mime-info \
    fonts-dejavu-core \
    fonts-liberation \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create sandbox user (unprivileged)
RUN groupadd -r sandbox && useradd -r -g sandbox -d /sandbox -s /sbin/nologin sandbox

# Install WeasyPrint (latest stable)
RUN pip install --no-cache-dir weasyprint>=60.0

# Create working directories with restrictive permissions
RUN mkdir -p /sandbox/input /sandbox/output \
    && chown -R sandbox:sandbox /sandbox \
    && chmod 700 /sandbox/input /sandbox/output

WORKDIR /sandbox

# Copy PDF generation script
COPY --chown=sandbox:sandbox docker/nsjail/generate_pdf.py /sandbox/

# Security: Drop all capabilities, run as unprivileged user
USER sandbox

# Expose internal port
EXPOSE 8001

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import weasyprint; print('ok')" || exit 1

# Simple HTTP server for receiving PDF generation requests
CMD ["python", "generate_pdf.py"]
