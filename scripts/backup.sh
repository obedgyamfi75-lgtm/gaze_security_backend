#!/bin/bash
# =============================================================================
# GAZE Security Platform - Database Backup Script
# Runs daily via Docker container
# =============================================================================

set -euo pipefail

BACKUP_DIR="/backups"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="secops_backup_${DATE}.sql.gz.enc"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"

echo "[$(date)] Starting backup..."

# Create backup directory if not exists
mkdir -p "${BACKUP_DIR}"

# Dump database with compression
pg_dump --no-password --clean --if-exists | gzip | \
    openssl enc -aes-256-cbc -salt -pbkdf2 -pass "pass:${BACKUP_ENCRYPTION_KEY}" \
    > "${BACKUP_DIR}/${BACKUP_FILE}"

# Verify backup was created
if [ -f "${BACKUP_DIR}/${BACKUP_FILE}" ]; then
    SIZE=$(du -h "${BACKUP_DIR}/${BACKUP_FILE}" | cut -f1)
    echo "[$(date)] Backup created: ${BACKUP_FILE} (${SIZE})"
else
    echo "[$(date)] ERROR: Backup failed!"
    exit 1
fi

# Clean old backups
echo "[$(date)] Cleaning backups older than ${RETENTION_DAYS} days..."
find "${BACKUP_DIR}" -name "secops_backup_*.sql.gz.enc" -mtime +${RETENTION_DAYS} -delete

# Count remaining backups
COUNT=$(find "${BACKUP_DIR}" -name "secops_backup_*.sql.gz.enc" | wc -l)
echo "[$(date)] Backup complete. ${COUNT} backups retained."

# Verify backup integrity (optional - decrypt and check header)
echo "[$(date)] Verifying backup integrity..."
if openssl enc -d -aes-256-cbc -pbkdf2 -pass "pass:${BACKUP_ENCRYPTION_KEY}" \
    -in "${BACKUP_DIR}/${BACKUP_FILE}" 2>/dev/null | gzip -t 2>/dev/null; then
    echo "[$(date)] Backup verification: OK"
else
    echo "[$(date)] WARNING: Backup verification failed!"
fi
