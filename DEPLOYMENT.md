# CI/CD — Deploy to EC2

Push to `master` on **`visitors-up-API`** → GitHub Actions builds and deploys the
full stack (API + admin + Postgres + Redis + Mailpit) to your EC2 box, then prunes
unused Docker containers/images/cache.

Workflow file: [.github/workflows/deploy.yml](.github/workflows/deploy.yml)

---

## How it works

The stack spans **two repos** that must sit side-by-side on the server:

| Repo                | Lands in   | Role                                            |
| ------------------- | ---------- | ----------------------------------------------- |
| `visitors-up-API`   | `api/`     | This repo — owns `deploy.sh` + `docker-compose.yml` |
| `visitors-up-admin` | `admin/`   | Vue admin app, built by compose from `../admin` |

Each deploy:

1. The GitHub runner checks out **both** repos and drops `deploy.sh` at the parent.
2. `rsync` ships the tree to `EC2:/opt/vms` (the server keeps its own `api/.env`
   and Docker volumes — those are never overwritten or deleted).
3. `deploy.sh` runs on the box: installs Docker if missing, builds images, brings
   the stack up on ports **80** (admin) and **8000** (API). It seeds demo data
   **only when the DB is empty**, so redeploys never wipe real data.
4. `docker system prune -af` removes stopped containers, dangling/unused images,
   and build cache. The running stack and named volumes (`postgres_data`,
   `redis_data`) stay — prune runs without `--volumes`, so **DB data is safe**.

---

## One-time setup

### 1. EC2 box

- Amazon Linux 2023 / Ubuntu instance with SSH access.
- Security group inbound: **22** (SSH, your IP), **80** (admin), **8000** (API).
  Optionally **8025** for Mailpit.
- `deploy.sh` installs Docker + the compose plugin automatically — no manual
  Docker install needed.
- The deploy user needs **passwordless sudo** (default for `ec2-user`/`ubuntu`).

### 2. SSH key for the pipeline

Generate a dedicated key (don't reuse your personal `.pem`):

```bash
ssh-keygen -t ed25519 -f vms_deploy -N "" -C "github-actions-deploy"
# add the PUBLIC key to the box:
ssh-copy-id -i vms_deploy.pub ec2-user@YOUR_EC2_IP
#   (or paste vms_deploy.pub into ~/.ssh/authorized_keys on the box)
```

### 3. GitHub repo secrets

In **`visitors-up-API` → Settings → Secrets and variables → Actions → New repository secret**:

| Secret             | Value                                                                 |
| ------------------ | --------------------------------------------------------------------- |
| `EC2_HOST`         | EC2 public IP or DNS, e.g. `54.x.x.x`                                  |
| `EC2_USER`         | SSH user, e.g. `ec2-user` (Amazon Linux) or `ubuntu`                  |
| `EC2_SSH_KEY`      | **Full contents** of the private key `vms_deploy` (incl. BEGIN/END)   |
| `ADMIN_REPO_TOKEN` | A GitHub PAT/fine-grained token with **read** access to `visitors-up-admin` |
| `EC2_SSH_PORT`     | *(optional)* SSH port — defaults to `22` if omitted                   |

> **`ADMIN_REPO_TOKEN`** is needed because the runner checks out a *second* repo.
> Fine-grained token: scope it to `visitors-up-admin`, `Contents: Read-only`.

### 4. First deploy

- Push to `master`, **or** run it manually:
  **Actions → Deploy to EC2 → Run workflow**.
- First run is slow (Docker install + full image build). Subsequent runs are faster
  unless the prune cleared the build cache.

When it finishes:

- Admin app → `http://YOUR_EC2_IP`
- API docs  → `http://YOUR_EC2_IP:8000/docs`
- Mailpit   → `http://YOUR_EC2_IP:8025`

---

## Server-side secrets (`api/.env`)

On the **first** deploy, `deploy.sh` creates `/opt/vms/api/.env` from
`.env.example` if it's missing. **SSH in and set strong secrets** (`SECRET_KEY`,
Zoho creds, admin/security passwords), then redeploy:

```bash
ssh ec2-user@YOUR_EC2_IP
sudo nano /opt/vms/api/.env
cd /opt/vms && ./deploy.sh --no-reseed   # restart without touching data
```

`api/.env` is excluded from rsync, so the pipeline **never overwrites** your
server-side secrets.

---

## Docker — what's already in place

No extra Docker files are needed; the stack is fully containerized:

- [`api/Dockerfile`](Dockerfile) — FastAPI on `python:3.9-slim`.
- `admin/Dockerfile` — multi-stage Vite build → served by `nginx:alpine`.
- [`api/docker-compose.yml`](docker-compose.yml) — orchestrates `web`, `admin`,
  `db` (Postgres 15), `redis`, `mailpit`.

---

## Manual ops on the box

```bash
cd /opt/vms
./deploy.sh                 # build + start (seeds only if DB empty)
./deploy.sh --no-reseed     # restart, keep all data
./deploy.sh --logs          # follow stack logs
./deploy.sh --down          # stop + remove the stack
./deploy.sh --reseed        # WIPE the DB and re-seed (destructive)

# manual cleanup (same as the pipeline's final step):
sudo docker system prune -af
```

---

## Troubleshooting

- **`Permission denied (publickey)`** — `EC2_SSH_KEY` must be the **private** key
  (full text), and its public half must be in the box's `~/.ssh/authorized_keys`.
- **Admin checkout fails / 404** — `ADMIN_REPO_TOKEN` missing or lacks read access
  to `visitors-up-admin`.
- **API never becomes healthy** — `ssh` in and run `cd /opt/vms && ./deploy.sh --logs`.
- **rsync: command not found** — the prepare step installs it; if your distro uses
  a different package manager, install `rsync` on the box once.
