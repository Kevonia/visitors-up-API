#!/usr/bin/env bash
#
# deploy.sh — one-shot demo deployment for the Visitor Management System.
#
# Target: a fresh AWS EC2 instance (Amazon Linux 2/2023 or Ubuntu). Idempotent —
# safe to re-run.
#
# Stack (defined in api/docker-compose.yml):
#   web      FastAPI API            → host port ${API_PORT:-8000}
#   admin    Vue admin app (nginx)  → host port 80   (ADMIN_PORT)
#   db       Postgres 15
#   redis    Redis 7
#   mailpit  Dev email/SMS catcher  → UI on 8025, SMTP on 1025
#
# What it does:
#   1. Installs Docker + the compose plugin if they aren't already present.
#   2. Starts/enables the Docker daemon.
#   3. Creates a 2 GB swapfile (small instances OOM while building the Vite app).
#   4. Detects the instance's public IP so the admin bundle + CORS use it.
#   5. Builds and starts the full stack with the admin served on port 80.
#   6. Waits for the API to become healthy.
#
# Migrations (`alembic upgrade head`) and the bootstrap seed (`seed_prod.py`,
# which creates the ADMIN + SECURITY accounts) run automatically from the web
# container's start command — no manual seeding step needed.
#
# Usage:
#   ./deploy.sh                 # build, start the stack; seed demo data only if the DB is empty
#   ./deploy.sh --no-reseed     # build, start, but never seed (KEEP existing data)
#   ./deploy.sh --down          # stop and remove the stack
#   ./deploy.sh --reseed        # WIPE + re-seed an already-running stack (forced)
#   ./deploy.sh --logs          # follow the stack logs
#
#   ADMIN_PORT=8080 ./deploy.sh    # serve the admin on a different host port
#   API_PORT=8001   ./deploy.sh    # serve the API on a different host port
#
# NOTE: a deploy seeds the demo dataset only when the database is empty, so
# re-running it never destroys existing data. Use --reseed to force a wipe +
# re-seed, or --no-reseed to skip seeding entirely.
#
set -euo pipefail

cd "$(dirname "$0")"

# ── project layout ───────────────────────────────────────────────────────────
# The compose file lives in api/; the admin build context (../admin) is resolved
# relative to it, so we always point compose at the file explicitly.
PROJECT_DIR="api"
COMPOSE_FILE="$PROJECT_DIR/docker-compose.yml"

# Host ports. Admin defaults to 80 here (the whole point of a public demo);
# override with ADMIN_PORT / API_PORT in the environment.
export ADMIN_PORT="${ADMIN_PORT:-80}"
export API_PORT="${API_PORT:-8000}"

# A normal deploy seeds demo data only when the DB is empty (never wiping real
# data on re-runs). --no-reseed skips seeding entirely.
RESEED=true
for arg in "$@"; do [ "$arg" = "--no-reseed" ] && RESEED=false; done

# ── helpers ──────────────────────────────────────────────────────────────────
log()  { printf '\033[1;36m▸ %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m✓ %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m! %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

# Use sudo only when we aren't already root.
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null 2>&1 || die "Need root or sudo to install Docker."
  SUDO="sudo"
fi

# `docker compose` (v2 plugin) vs legacy `docker-compose` — resolved by caller.
COMPOSE=""
resolve_compose() {
  if docker compose version >/dev/null 2>&1; then COMPOSE="docker compose"
  elif command -v docker-compose >/dev/null 2>&1; then COMPOSE="docker-compose"
  else return 1; fi
}
# Wrapper: every compose call targets the api/ stack file.
dc() { $SUDO $COMPOSE -f "$COMPOSE_FILE" "$@"; }

# ── teardown / logs / reseed shortcuts ───────────────────────────────────────
case "${1:-}" in
  --down)
    resolve_compose || die "Docker compose not found."
    log "Stopping the stack…"
    dc down
    ok "Stack stopped."
    exit 0
    ;;
  --logs)
    resolve_compose || die "Docker compose not found."
    dc logs -f
    exit 0
    ;;
  --reseed)
    resolve_compose || die "Docker compose not found."
    warn "This WIPES the database and re-seeds it. Ctrl-C within 5s to abort…"
    sleep 5
    log "Re-seeding (reset_and_seed.py)…"
    dc exec -T web python scripts/reset_and_seed.py
    # reset_and_seed truncates users (incl. ADMIN); recreate the admin/security logins.
    dc exec -T web python scripts/seed_prod.py
    ok "Database re-seeded."
    exit 0
    ;;
esac

# ── 0. unpack the project archive (if a .zip was uploaded alongside) ─────────
# Common demo flow: scp just the project .zip to the box. If one is sitting next
# to this script, install unzip and extract it in place so the rest of the
# script (api/, admin/, .env handling, the build) sees the project tree.
ARCHIVE="$(ls -1 ./*.zip 2>/dev/null | head -n1 || true)"
if [ -n "$ARCHIVE" ]; then
  if ! command -v unzip >/dev/null 2>&1; then
    log "Installing unzip…"
    if command -v dnf >/dev/null 2>&1; then $SUDO dnf install -y unzip
    elif command -v yum >/dev/null 2>&1; then $SUDO yum install -y unzip
    elif command -v apt-get >/dev/null 2>&1; then $SUDO apt-get update -y && $SUDO apt-get install -y unzip
    else die "No supported package manager (dnf/yum/apt-get) to install unzip."
    fi
  fi
  command -v unzip >/dev/null 2>&1 || die "unzip is required to extract $ARCHIVE but could not be installed."
  log "Extracting $ARCHIVE…"
  unzip -o "$ARCHIVE" >/dev/null
  ok "Extracted $ARCHIVE."
else
  ok "No .zip archive to unpack — using the project files already present."
fi

# ── 1. install Docker ────────────────────────────────────────────────────────
if command -v docker >/dev/null 2>&1; then
  ok "Docker already installed ($(docker --version))."
else
  log "Installing Docker via get.docker.com convenience script…"
  curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
  $SUDO sh /tmp/get-docker.sh
  rm -f /tmp/get-docker.sh
  ok "Docker installed."
fi

# ── 2. start the daemon + add current user to the docker group ───────────────
log "Ensuring the Docker daemon is running…"
$SUDO systemctl enable --now docker 2>/dev/null || $SUDO service docker start || true
for _ in $(seq 1 10); do docker info >/dev/null 2>&1 && break || sleep 1; done

if [ -n "$SUDO" ] && ! groups "$USER" 2>/dev/null | grep -q docker; then
  $SUDO usermod -aG docker "$USER" || true
  warn "Added $USER to the 'docker' group — log out/in to use docker without sudo."
fi

# Resolve the compose command (plugin preferred, then legacy binary).
if ! resolve_compose; then
  log "Installing the docker compose plugin…"
  if command -v dnf >/dev/null 2>&1; then $SUDO dnf install -y docker-compose-plugin || true
  elif command -v yum >/dev/null 2>&1; then $SUDO yum install -y docker-compose-plugin || true
  elif command -v apt-get >/dev/null 2>&1; then $SUDO apt-get update -y && $SUDO apt-get install -y docker-compose-plugin || true
  fi
  resolve_compose || die "Could not install docker compose."
fi
ok "Using: $COMPOSE"

# ── 3. swap (small instances OOM building the Vite admin bundle) ─────────────
if [ "$(swapon --show 2>/dev/null | wc -l)" -eq 0 ] && [ ! -f /swapfile ]; then
  log "Creating a 2 GB swapfile (build headroom)…"
  $SUDO fallocate -l 2G /swapfile 2>/dev/null || $SUDO dd if=/dev/zero of=/swapfile bs=1M count=2048
  $SUDO chmod 600 /swapfile
  $SUDO mkswap /swapfile
  $SUDO swapon /swapfile
  grep -q '/swapfile' /etc/fstab 2>/dev/null || echo '/swapfile none swap sw 0 0' | $SUDO tee -a /etc/fstab >/dev/null
  ok "Swap enabled."
else
  ok "Swap already present."
fi

# ── 3b. grow the root filesystem onto a resized EBS volume ───────────────────
# After expanding the EBS volume in the AWS console, the partition + filesystem
# still have to be grown to actually use the new space. Idempotent: when there's
# nothing to grow, growpart exits non-zero (NOCHANGE) — we ignore it.
#
# Set SKIP_GROWPART=1 to skip this section entirely. Use it when the root device
# can't be grown here (e.g. growpart aborts with exit 1) but the disk is already
# the size you need and you just want the deploy to proceed.
if [ "${SKIP_GROWPART:-0}" = "1" ]; then
  ok "Skipping root-disk grow (SKIP_GROWPART=1)."
else
log "Ensuring the root filesystem uses all available disk…"
# growpart ships in cloud-guest-utils (Debian/Ubuntu) / cloud-utils-growpart (RHEL).
if ! command -v growpart >/dev/null 2>&1; then
  if command -v dnf >/dev/null 2>&1; then $SUDO dnf install -y cloud-utils-growpart
  elif command -v yum >/dev/null 2>&1; then $SUDO yum install -y cloud-utils-growpart
  elif command -v apt-get >/dev/null 2>&1; then $SUDO apt-get update -y && $SUDO apt-get install -y cloud-guest-utils
  else die "No supported package manager (dnf/yum/apt-get) to install growpart."
  fi
fi
# Detect the root device so this works on nvme (/dev/nvme0n1p1) or xvd
# (/dev/xvda1) instances — on this box it resolves to /dev/nvme0n1 + partition 1.
ROOT_SRC="$(findmnt -no SOURCE / 2>/dev/null || echo /dev/nvme0n1p1)"
ROOT_FS="$(findmnt -no FSTYPE / 2>/dev/null || echo ext4)"
if printf '%s' "$ROOT_SRC" | grep -q 'p[0-9]\+$'; then   # nvme: nvme0n1p1
  ROOT_DISK="$(printf '%s' "$ROOT_SRC" | sed -E 's/p[0-9]+$//')"
  ROOT_PART="$(printf '%s' "$ROOT_SRC" | sed -E 's/.*p([0-9]+)$/\1/')"
else                                                      # xvd/sd: xvda1
  ROOT_DISK="$(printf '%s' "$ROOT_SRC" | sed -E 's/[0-9]+$//')"
  ROOT_PART="$(printf '%s' "$ROOT_SRC" | sed -E 's/.*[^0-9]([0-9]+)$/\1/')"
fi
command -v growpart >/dev/null 2>&1 || die "growpart is required to grow the root disk but is not available."
[ -n "$ROOT_DISK" ] || die "Could not determine the root disk device from '$ROOT_SRC'."
# growpart exit code: 0 = grown, 2 = already at max (NOCHANGE — fine on re-runs).
# Any other code means growpart couldn't grow the partition. That's NOT fatal to
# a deploy — the disk is usually already the size we need (a genuinely full disk
# surfaces later in the build), so we warn and carry on rather than aborting.
grow_rc=0
$SUDO growpart "$ROOT_DISK" "$ROOT_PART" || grow_rc=$?
if [ "$grow_rc" -eq 0 ] || [ "$grow_rc" -eq 2 ]; then
  if [ "$ROOT_FS" = xfs ]; then
    $SUDO xfs_growfs / || warn "xfs_growfs failed — continuing."   # Amazon Linux 2023 default
  else
    $SUDO resize2fs "$ROOT_SRC" || warn "resize2fs failed — continuing."  # ext2/3/4 (Ubuntu default)
  fi
  ok "Root filesystem resized."
else
  warn "growpart $ROOT_DISK $ROOT_PART could not grow the disk (exit $grow_rc) — skipping resize and continuing."
fi
$SUDO lsblk || true
df -h || true
fi

# ── 4. detect public IP (EC2 IMDSv2, with fallbacks) ─────────────────────────
log "Detecting public IP…"
PUBLIC_IP=""
TOKEN=$(curl -s --max-time 2 -X PUT "http://169.254.169.254/latest/api/token" \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 300" 2>/dev/null || true)
if [ -n "$TOKEN" ]; then
  PUBLIC_IP=$(curl -s --max-time 2 -H "X-aws-ec2-metadata-token: $TOKEN" \
              http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || true)
fi
[ -z "$PUBLIC_IP" ] && PUBLIC_IP=$(curl -s --max-time 4 https://checkip.amazonaws.com 2>/dev/null | tr -d '[:space:]' || true)
[ -z "$PUBLIC_IP" ] && PUBLIC_IP="localhost"
ok "Public IP: $PUBLIC_IP"

# ── 5. wire the public host into the build + CORS ────────────────────────────
# These env vars are interpolated by compose into api/docker-compose.yml:
#   PUBLIC_HOST       → baked into the admin bundle's VITE_API_BASE_URL
#   CORS_ALLOW_ORIGINS→ origins the API accepts (admin is on :80, no port suffix)
export PUBLIC_HOST="$PUBLIC_IP"
ADMIN_ORIGIN="http://${PUBLIC_IP}"
[ "$ADMIN_PORT" != "80" ] && ADMIN_ORIGIN="http://${PUBLIC_IP}:${ADMIN_PORT}"
export CORS_ALLOW_ORIGINS="${ADMIN_ORIGIN},http://localhost,http://localhost:8080,http://localhost:5173"
log "Admin origin: $ADMIN_ORIGIN  •  API: http://${PUBLIC_IP}:${API_PORT}"

# api/.env is required by the compose env_file; bootstrap it from the example.
if [ ! -f "$PROJECT_DIR/.env" ]; then
  if [ -f "$PROJECT_DIR/.env.example" ]; then
    cp "$PROJECT_DIR/.env.example" "$PROJECT_DIR/.env"
    warn "Created api/.env from api/.env.example — set strong secrets before real use."
  else
    die "api/.env is missing and there is no api/.env.example to copy."
  fi
fi

# ── 6. build + start ─────────────────────────────────────────────────────────
log "Building images (first run is slow — be patient)…"
dc build
log "Starting the stack (admin on port ${ADMIN_PORT})…"
dc up -d

# ── 7. wait for the API to become healthy ────────────────────────────────────
log "Waiting for the API to become healthy…"
for i in $(seq 1 60); do
  if curl -fs --max-time 2 "http://localhost:${API_PORT}/health" >/dev/null 2>&1; then
    ok "API is up."
    break
  fi
  [ "$i" -eq 60 ] && die "API did not come up in time. Check: $COMPOSE -f $COMPOSE_FILE logs web"
  sleep 3
done

# ── 8. seed the demo dataset, but only when the DB is empty ───────────────────
# A redeploy must never silently wipe real data, so we probe the database first
# and only run the (destructive) reset_and_seed when it's empty. Force a wipe
# with --reseed; skip seeding altogether with --no-reseed.
if [ "$RESEED" = false ]; then
  warn "Skipping seed (--no-reseed) — existing data preserved."
else
  log "Checking whether the database is already seeded…"
  seed_state="$(dc exec -T web python - <<'PY' 2>/dev/null || true
from app.database import SessionLocal
from app import models
db = SessionLocal()
try:
    n = db.query(models.Resident).count() + db.query(models.Visitor).count()
    print("SEEDED" if n > 0 else "EMPTY")
except Exception:
    print("UNKNOWN")
finally:
    try:
        db.close()
    except Exception:
        pass
PY
)"
  seed_state="$(printf '%s' "$seed_state" | tr -d '[:space:]')"
  case "$seed_state" in
    EMPTY)
      log "Database empty — seeding the demo dataset (reset_and_seed.py)…"
      dc exec -T web python scripts/reset_and_seed.py
      # reset_and_seed truncates users (incl. ADMIN); recreate the admin/security logins.
      dc exec -T web python scripts/seed_prod.py
      ok "Demo data seeded."
      ;;
    SEEDED)
      ok "Database already seeded — skipping re-seed (data preserved). Run ./deploy.sh --reseed to force."
      ;;
    *)
      warn "Could not determine seed state — skipping seed to avoid data loss. Run ./deploy.sh --reseed to force."
      ;;
  esac
fi

# ── done ─────────────────────────────────────────────────────────────────────
cat <<DONE

────────────────────────────────────────────────────────────
$(ok "Visitor Management System demo is live!")

  Admin app  →  ${ADMIN_ORIGIN}
  API docs   →  http://${PUBLIC_IP}:${API_PORT}/docs
  Mailpit    →  http://${PUBLIC_IP}:8025   (captured emails/SMS)

  Default logins (override via ADMIN_*/SECURITY_* in api/.env):
    • admin@twickenham.com     / admin123      (ADMIN)
    • security@twickenham.com  / security123   (SECURITY)

  Open EC2 security-group inbound ports 80 and ${API_PORT} to your IP.
  Manage:  ./deploy.sh --logs | --down       Keep data on re-deploy: ./deploy.sh --no-reseed
────────────────────────────────────────────────────────────
DONE
