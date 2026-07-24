# MBS.SC

**Smart Security. Fast Results.**

Architecture, data model, and build order live in [docs/architecture/blueprint.md](docs/architecture/blueprint.md) — read that first.

## Status

Phase 0, step 1 of the implementation order: repo scaffold + Docker Compose. Auth, RBAC, and the authorization-scope gate (step 2–3) are not built yet — only a health-check round trip between `web` and `api`.

## Prerequisites

- Docker Desktop (with Compose v2)
- Node.js 20+ and Python 3.12+ are only needed for running things outside Docker; the containers install their own dependencies.

## Running locally

```
copy .env.example .env
docker compose -f infra/docker-compose.yml up --build
```

- Web: http://localhost:3000 (also reachable via nginx at http://localhost/)
- API: http://localhost:8000/health
- MinIO console: http://localhost:9001 (minioadmin / minioadmin)

## Layout

See §4 of the blueprint for the full folder structure and reasoning. Top level:

- `apps/web` — Next.js + TypeScript + Tailwind dashboard
- `apps/api` — FastAPI backend (modular monolith: `modules/`, `ai_agent/`, `scanner_engine/`, `celery_app/`)
- `infra/` — Dockerfiles, nginx, docker-compose
- `db/` — Alembic migrations and seed data
- `docs/architecture/blueprint.md` — source of truth for architecture decisions
