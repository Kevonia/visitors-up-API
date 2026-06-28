#!/usr/bin/env bash
# Nightly Postgres backup for the VMS stack.
#
# Runs on the EC2 host: dumps the `db` compose container to a timestamped,
# gzipped file, prunes dumps older than RETENTION_DAYS, and (optionally) uploads
# to S3 if BACKUP_S3_BUCKET is set and the AWS CLI is available.
#
# Usage (cron, on the box):
#   0 3 * * *  /opt/vms/api/scripts/backup_db.sh >> /var/log/vms-backup.log 2>&1
#
# IMPORTANT: a dump is only restorable with the SAME PII_ENCRYPTION_KEY the app
# used to write it — PII columns are encrypted at rest. Back that key up too
# (it lives in api/.env), and NEVER rotate it. See BACKUP_RESTORE.md.
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/opt/vms/backups}"
RETENTION_DAYS="${RETENTION_DAYS:-14}"
DB_CONTAINER="${DB_CONTAINER:-api-db-1}"     # `docker compose` default name; override if different
PGUSER="${POSTGRES_USER:-vms}"
PGDB="${POSTGRES_DB:-vms}"

mkdir -p "$BACKUP_DIR"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="$BACKUP_DIR/vms-${PGDB}-${STAMP}.sql.gz"

echo "[$(date -Is)] Dumping $PGDB from $DB_CONTAINER -> $OUT"
# pg_dump inside the db container; stream straight to a gzip on the host.
docker exec -i "$DB_CONTAINER" pg_dump -U "$PGUSER" -d "$PGDB" --no-owner --clean --if-exists \
  | gzip -9 > "$OUT"

SIZE="$(du -h "$OUT" | cut -f1)"
echo "[$(date -Is)] Backup complete ($SIZE)"

# Prune old local dumps.
find "$BACKUP_DIR" -name 'vms-*.sql.gz' -mtime "+${RETENTION_DAYS}" -delete 2>/dev/null || true

# Optional off-box copy to S3 (durable; survives an instance/volume loss).
if [ -n "${BACKUP_S3_BUCKET:-}" ] && command -v aws >/dev/null 2>&1; then
  echo "[$(date -Is)] Uploading to s3://${BACKUP_S3_BUCKET}/vms/"
  aws s3 cp "$OUT" "s3://${BACKUP_S3_BUCKET}/vms/$(basename "$OUT")"
fi

echo "[$(date -Is)] Done."
