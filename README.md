# FastAPI Backend Application

A robust backend API built with FastAPI for managing users, residents, visitors, roles, permissions, and more.

## Features

- **User Management**: Create, read, update, and delete user accounts
- **Role-Based Access Control**: Manage roles and permissions
- **Resident Management**: Handle resident information (incl. name + lot number)
- **Visitor Tracking**: Manage visitor records and allowlists
- **Payment lists**: Residents classified White / Yellow / Red from Zoho and
  surfaced across all apps; Red (delinquent) visitors blocked at the gate
- **Authentication**: JWT access/refresh tokens with rotation, Redis rate
  limiting, and a password policy
- **PII encryption at rest**: deterministic AES-SIV on sensitive columns
- **Security hardening**: locked CORS, security headers, prod fail-closed config
- **Performance Monitoring**: Process time tracking middleware
- **Logging**: Comprehensive logging configuration (request-tagged, PII-scrubbed)
- **Zoho Integration**: live contact/invoice sync with DB caching

## API Endpoints

The API is organized into the following routes:

- `/api/v1/auth` - Authentication endpoints
- `/api/v1/user` - User management
- `/api/v1/resident` - Resident management
- `/api/v1/allow-list` - Allowlist management
- `/api/v1/role` - Role management
- `/api/v1/permission` - Permission management
- `/api/v1/visitor` - Visitor management
- `/api/v1/user/visitor` - User-visitor relationships

## Getting Started

### Prerequisites

- Python 3.7+
- Pipenv or pip
- (List any other dependencies your project might have)

### Installation

1. Clone the repository:
   ```bash
   git clone [repository-url]
   cd [project-directory]
   ```

## Local stack with Docker

`api/docker-compose.yml` brings up the whole stack for local testing — FastAPI,
Postgres, Redis, and the admin web app:

```bash
cd api
docker compose up --build
```

- API: http://localhost:8000 (Swagger at `/docs`; liveness at `/health`)
- Admin: http://localhost:8080
- Postgres: localhost:5432, Redis: localhost:6379

> In production (`APP_ENV=production`) the interactive docs (`/docs`, `/redoc`,
> `/openapi.json`) are disabled; `/health` stays available for the load balancer.

Postgres/Redis credentials default to `vms`/`vms`/`vms` if not set in `api/.env`,
and the compose file overrides `DATABASE_URL`/`REDIS_URL` to point at the `db` and
`redis` services automatically (so you don't have to edit `.env` for local runs).
Zoho/JWT secrets are still read from `api/.env`. Migrations run on startup
(`alembic upgrade head`).

## Role-Based Access Control

Roles (`ADMIN`, `MANAGER`, `USER`/resident, `SECURITY`) are seeded automatically
on startup (`seed_roles()` in `app/main.py`). Authorization is enforced with the
`require_roles(*names)` dependency in `app/config/auth.py`:

- `ADMIN` only: `/api/v1/roles`, `/api/v1/permissions`, `/api/v1/admin/*`
- `ADMIN`/`MANAGER`: `/api/v1/users`, `/api/v1/residents`, `/api/v1/allowlist`,
  `/api/v1/visitors` (admin visitor management), `/api/v1/guards`
- `SECURITY`/`ADMIN`/`MANAGER`: `/api/v1/gate/*`
- Any authenticated resident: `/api/v1/user/visitors/*` (ownership enforced)

Logged-out tokens are rejected via the Redis blacklist (`get_current_user`).

## Security

- **JWT auth** — short-lived access tokens + refresh tokens. `/api/v1/refresh`
  enforces the token `type`, verifies the account still exists, and **rotates**
  the refresh token (the presented one is blacklisted; reuse → 401). `/logout`
  blacklists the access token and, if supplied, the refresh token.
- **Password policy** — account/guard creation requires ≥ 8 chars with at least
  one letter and one number (`validate_password_strength` in `app/schemas.py`),
  enforced on the backend and mirrored in the admin + resident apps.
- **Rate limiting** — Redis-backed: 5 login attempts/username/hour, 20/IP/hour.
- **CORS** — locked to `CORS_ALLOW_ORIGINS` (comma-separated); no wildcard.
- **Security headers** — `X-Content-Type-Options`, `X-Frame-Options: DENY`,
  `Referrer-Policy`, `Permissions-Policy`, and HSTS over HTTPS.
- **PII at rest** — sensitive columns (name, phone, lot, street) use a
  deterministic AES-SIV type (`app/security/pii.py`) keyed by
  `PII_ENCRYPTION_KEY`; equality lookups still work, substring search does not.
- **Log hygiene** — request bodies are never echoed into logs (validation-error
  `input` is scrubbed); tokens are never logged.
- **Fail closed in production** — with `APP_ENV=production` the app refuses to
  start on insecure defaults (dev PII key, weak `ADMIN_PASSWORD`/
  `SECURITY_PASSWORD`, short `SECRET_KEY`, or `DEV_SKIP_ZOHO=true`).

## Payment lists (White / Yellow / Red)

Residents are classified from their Zoho contact (`app/services/lists.py`):

- **Yellow** — on a payment plan (`cf_on_payment_plan == "Y"`).
- **Red** — outstanding balance over `RED_BALANCE_THRESHOLD` (default 18000);
  treated as delinquent and (when `GATE_BLOCK_DELINQUENT=true`) their visitors
  are blocked at `POST /api/v1/gate/entries`.
- **White** — everyone else.

The category, balance, and invoices are **cached on the resident** and in
`cached_invoices`, refreshed lazily on `/users/me` past `ZOHO_CACHE_TTL` and in
bulk by `POST /api/v1/admin/zoho/sync`, so request paths rarely hit Zoho. The
resident's real lot number comes from the `cf_lot_number` custom field and the
name from `contact_name` (the Zoho address `attention` line is the name, not the
lot).

## Gate & Visitor Lifecycle

- Visitors have a `visit_type` (`ONE_TIME` | `PERMANENT`), a lifecycle `status`
  (`ACTIVE`/`USED`/`EXPIRED`/`REVOKED`), and an optional validity window
  (`valid_from`/`valid_until`), plus optional `phone` and `vehicle_plate`.
- Guards use `/api/v1/gate/visitors/search` (manual lookup) then
  `POST /api/v1/gate/entries` to log an arrival (one-time passes become `USED`)
  and `PUT /api/v1/gate/entries/{id}/exit` to log departure.
- `GET /api/v1/gate/entries` is the audited gate log (filter by `lot_no`,
  `from`, `to`, `open`).

## Zoho Integration (caching & limited queries)

The client (`app/zoho_integration/zoho_client.py`) shares its access token across
workers via Redis and uses **filtered** Zoho endpoints (`?email=`,
`?customer_id=`) with per-resource Redis caching instead of pulling whole lists.
Resident `delinquency_status` is stored in the DB and refreshed in bulk by
`POST /api/v1/admin/zoho/sync` (run on a schedule), so request paths don't query
Zoho live. `GET /api/v1/admin/zoho/metrics` reports call/cache-hit counts and
`POST /api/v1/admin/zoho/cache/bust` clears the cache.

**Redis keys:** `zoho:access_token` (shared token), `zoho:cache:*` (cached
contacts/addresses/invoices), `zoho:metrics:*` (counters), `token_blacklist:*`,
`login_attempt:*`, `login_ip:*`.

## Configuration (env vars)

See `app/config/config.py` for defaults. Key variables (`.env` locally):

| Variable | Purpose |
| --- | --- |
| `APP_ENV` | `development` (default) or `production` (enables fail-closed checks + hides docs) |
| `DATABASE_URL`, `POSTGRES_*` | Postgres connection |
| `REDIS_URL` | Redis/Key Value connection |
| `SECRET_KEY`, `ALGORITHM` | JWT signing |
| `ACCESS_TOKEN_EXPIRE_MINUTES`, `REFRESH_TOKEN_EXPIRE_DAYS` | Token lifetimes |
| `PII_ENCRYPTION_KEY` | Key for AES-SIV PII encryption — **stable, never change after first use** |
| `CORS_ALLOW_ORIGINS` | Comma-separated allowed browser origins (the admin app) |
| `PUBLIC_BASE_URL` | Absolute base for links in emails |
| `DEV_SKIP_ZOHO` | Local only: skip Zoho on signup/`/users/me` (must be `false` in prod) |
| `CLIENT_ID`, `CLIENT_SECRET`, `REFRESH_TOKEN`, `ACCESS_TOKEN` | Zoho OAuth |
| `ZOHO_API_URL`, `ZOHO_ORG_ID` | Zoho Invoice endpoint + org (sent on every call) |
| `RED_BALANCE_THRESHOLD`, `ZOHO_CACHE_TTL`, `GATE_BLOCK_DELINQUENT` | Payment-list rules + cache TTL + gate enforcement |
| `NOTIFICATIONS_ENABLED`, `NOTIFICATIONS_TRANSPORT`, `BREVO_*`, `SMTP_*` | Email/SMS notifications |
| `ADMIN_*`, `SECURITY_*` | Bootstrap accounts created by `scripts/seed_prod.py` |

## Deployment (Render)

The repos ship Render Blueprints:

- `api/render.yaml` — FastAPI (Docker) + Postgres + Key Value (Redis). Sets
  `APP_ENV=production`, wires DB/Redis automatically, generates `SECRET_KEY` /
  `PII_ENCRYPTION_KEY`, runs `alembic upgrade head && python scripts/seed_prod.py`
  before each release, and health-checks `/health`.
- `admin/render.yaml` — the Vue admin as a static site.

After the first deploy, set the secrets marked `sync: false`, cross-set
`CORS_ALLOW_ORIGINS` (api) ↔ `VITE_API_BASE_URL` (admin) to each other's URLs,
and seed the allowlist once: `python scripts/seed_allowlist_from_zoho.py`.
