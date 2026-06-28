# Backups & disaster recovery (EC2 single-box stack)

The whole stack runs on **one EC2 instance** (Postgres + Redis in Docker volumes,
behind Caddy). That's a single point of failure — a lost instance/volume = lost
data unless there are off-box backups. This is the minimum runbook.

> ⚠️ **PII is encrypted at rest.** Resident names/emails/phones/plates are stored
> encrypted with `PII_ENCRYPTION_KEY` (in `api/.env`). A database dump is only
> readable by an app configured with **the same key**. Back the key up somewhere
> safe (a password manager / secrets vault) and **never rotate it** — rotating it
> makes all existing encrypted data unreadable.

## What to back up
1. **The database** — nightly logical dump (below).
2. **`api/.env`** — holds `PII_ENCRYPTION_KEY`, `SECRET_KEY`, Zoho/payment secrets.
   Store it in a vault, not just on the box.
3. (Optional) **EBS volume snapshots** — a cheap whole-disk safety net (see below).

## 1. Automated nightly dump
`api/scripts/backup_db.sh` dumps the `db` container to a gzipped file, prunes old
ones, and optionally uploads to S3.

Install the cron on the box:
```bash
sudo cp /opt/vms/api/scripts/backup_db.sh /opt/vms/api/scripts/backup_db.sh   # (shipped by deploy)
chmod +x /opt/vms/api/scripts/backup_db.sh
( crontab -l 2>/dev/null; echo "0 3 * * * BACKUP_S3_BUCKET=your-bucket /opt/vms/api/scripts/backup_db.sh >> /var/log/vms-backup.log 2>&1" ) | crontab -
```
Confirm the db container name first: `docker ps --format '{{.Names}}' | grep db`
(set `DB_CONTAINER=` in the cron line if it isn't `api-db-1`).

Off-box copies need an S3 bucket + an instance IAM role (or `aws configure`) with
`s3:PutObject` on it. Without `BACKUP_S3_BUCKET` the dump stays local only — which
does **not** survive an instance loss, so set the bucket for real protection.

## 2. Restore
```bash
# pick a dump (local or `aws s3 cp s3://bucket/vms/<file> .`)
gunzip -c vms-vms-YYYYMMDD-HHMMSS.sql.gz | docker exec -i api-db-1 psql -U vms -d vms
```
The dump is created with `--clean --if-exists`, so it drops & recreates objects.
Restore into a stack whose `api/.env` has the **same `PII_ENCRYPTION_KEY`**, or
encrypted columns will be unreadable.

Smoke-check after restore: `curl -sk https://<host>/api/v1/payments/config` (401 = up),
sign in on the admin, confirm residents/payments look right.

## 3. EBS volume snapshots (whole-disk safety net)
In the AWS console (or CLI), enable a **Data Lifecycle Manager** policy on the
instance's EBS volume — e.g. a daily snapshot kept for 7 days. This captures the
Docker volumes (`postgres_data`, `redis_data`) and the code, so a destroyed
instance can be rebuilt from a snapshot. Snapshots complement (don't replace) the
logical dumps — dumps are smaller, portable, and restore selectively.

## Recovery drills
Test a restore into a throwaway DB at least once so the runbook is known-good
before you actually need it. An untested backup is a hope, not a backup.
