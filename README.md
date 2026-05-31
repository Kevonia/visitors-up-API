# FastAPI Backend Application

A robust backend API built with FastAPI for managing users, residents, visitors, roles, permissions, and more.

## Features

- **User Management**: Create, read, update, and delete user accounts
- **Role-Based Access Control**: Manage roles and permissions
- **Resident Management**: Handle resident information
- **Visitor Tracking**: Manage visitor records and allowlists
- **Authentication**: Secure API endpoints
- **Performance Monitoring**: Process time tracking middleware
- **CORS Support**: Configured for cross-origin requests
- **Logging**: Comprehensive logging configuration
- **Zoho Integration**: (Commented out but available for extension)

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

- API: http://localhost:8000 (Swagger at `/docs`)
- Admin: http://localhost:8080
- Postgres: localhost:5432, Redis: localhost:6379

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

**Env vars:** `CLIENT_ID`, `CLIENT_SECRET`, `REFRESH_TOKEN`, `ACCESS_TOKEN`,
`ZOHO_API_URL`, `REDIS_URL`, plus the JWT/DB vars.

**Redis keys:** `zoho:access_token` (shared token), `zoho:cache:*` (cached
contacts/addresses/invoices), `zoho:metrics:*` (counters), `token_blacklist:*`,
`login_attempt:*`, `login_ip:*`.