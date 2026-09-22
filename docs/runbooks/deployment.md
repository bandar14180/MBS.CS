# Runbook: Deployment, Rolling Restart & Graceful Shutdown

How to deploy MBS.CS without losing in-flight scans or corrupting state. The system is built to
tolerate abrupt worker loss (acks_late redelivery + orphan reaper), but a *clean* rollout avoids
unnecessary scan restarts and downtime.

## Components
| Service | Role | Shutdown behavior |
|---|---|---|
| `api` | FastAPI/uvicorn HTTP | drains in-flight requests on SIGTERM |
| `worker` | Celery `-Q scans` (heavy scans) | warm shutdown: finishes in-flight scan, `stop_grace_period=60s` |
| `worker-default` | Celery `-Q default` (reaper, relay, schedule, backup, retention, email) | warm shutdown, `stop_grace_period=60s` |
| `beat` | scheduler (emits periodic ticks) | stateless emitter, `stop_grace_period=30s`; missed tick re-emits next interval |
| `mysql` / `redis` / `minio` | stateful | see DR runbook; not restarted casually |

## Reliability guarantees you can rely on during a deploy
- **acks_late + reject_on_worker_lost + prefetch=1:** a scan is acknowledged only after it
  finishes; a worker killed mid-scan → the broker redelivers it. Scans are idempotent (the
  orchestrator skips an already-terminal scan), so redelivery is safe.
- **Per-task soft/hard time limits:** a hung scan self-terminates (marked `failed`, reclaimable)
  before the hard SIGKILL, so it never blocks warm shutdown forever.
- **Orphan reaper:** any scan stuck `running` past `SCAN_ORPHAN_TIMEOUT_SECONDS` (2h) is recovered
  by `scans.reap_orphans` (beat, every 5m). It marks state; it never re-dispatches (no dup runs).

## Migration ordering (schema changes)
Always apply migrations **before** rolling the app/worker image that expects the new schema:
```bash
# 1) apply migrations (idempotent; safe to run repeatedly)
docker compose -f infra/docker-compose.yml -f infra/docker-compose.prod.yml run --rm api \
  sh -lc 'cd /srv/db && alembic upgrade head'
# 2) then roll the services (below)
```
Migrations in this repo are additive; a brief window where old code runs against the new schema is
tolerated. Never roll app code that requires a migration that hasn't been applied yet.


## Production secrets (required before the first `up`)

Every production credential is a Docker Secret read from `infra/secrets/*.txt`. That directory
is gitignored — generate the files on the host and never commit them. The API refuses to start
if a declared `*_FILE` cannot be read, so a missing file fails fast rather than silently falling
back to a development default.

```bash
mkdir -p infra/secrets && chmod 700 infra/secrets
cd infra/secrets

# --- application secrets -------------------------------------------------------------
openssl rand -hex 32  > jwt_secret_key.txt
openssl rand -hex 32  > metrics_token.txt
openssl rand -base64 32 | tr -d '\n' > ../../.mfa_key && mv ../../.mfa_key mfa_encryption_key.txt
printf '%s' "$YOUR_OPENROUTER_KEY" > openrouter_api_key.txt

# --- datastore credentials -----------------------------------------------------------
openssl rand -hex 24 > mysql_root_password.txt    # MySQL root password (first start only)
openssl rand -hex 24 > mysql_password.txt         # the `mbs` application user's password
openssl rand -hex 24 > redis_password.txt         # Redis requirepass
printf 'mbs_s3'      > minio_root_user.txt
openssl rand -hex 24 > minio_root_password.txt
printf 'mbs_s3'      > s3_access_key.txt          # must match minio_root_user
cp minio_root_password.txt s3_secret_key.txt      # must match minio_root_password

# --- derived URLs (must embed the passwords generated above) -------------------------
printf 'redis://:%s@redis:6379/0' "$(cat redis_password.txt)" > redis_url.txt
printf 'mysql+aiomysql://mbs:%s@mysql:3306/mbs' "$(cat mysql_password.txt)" > database_url.txt

chmod 600 *.txt
```

**Consistency rules the tests cannot check for you** (they live in files that are never
committed, so keep them right by hand):

| These must match | Why |
|---|---|
| `redis_password.txt` ↔ password inside `redis_url.txt` | one is the server's `requirepass`, the other is how every client authenticates; drift breaks the broker, cache, rate limiter and MFA lockouts at once |
| `minio_root_user/password.txt` ↔ `s3_access_key/s3_secret_key.txt` | MinIO root credentials *are* the S3 credentials the app uses |
| `mysql_password.txt` ↔ password inside `database_url.txt` | two views of ONE credential: the first is what the `mysql` image provisions for the `mbs` user at first start, the second is how the app authenticates. Drift means the app cannot connect at all |
| the user in `database_url.txt` ↔ `MYSQL_USER` (`mbs`) | the image provisions exactly this one non-root user; see least-privilege below |

> Verifying Redis by hand: `redis-cli -u redis://:PASS@host` reports `WRONGPASS` because it
> sends a two-argument `AUTH` with an empty username. That is a redis-cli quirk, not a
> misconfiguration — the URL form is correct for `redis-py`/Celery. Use
> `REDISCLI_AUTH="$(cat /run/secrets/redis_password)" redis-cli ping` instead.

## Least-privileged application database role

`DATABASE_URL` must **not** point at `root`. The official `mysql:8.0` image already provisions a
dedicated non-root user from `MYSQL_USER`/`MYSQL_PASSWORD` (`mbs`, password from
`mysql_password.txt`) and grants it full rights on the `mbs` database only — so the default
compose is already least-privileged for the application, and `database_url.txt` should name that
user, never `root`.

> Workspace isolation does **not** depend on the database role. Under PostgreSQL it relied on
> FORCE Row-Level Security, which a superuser bypassed; MySQL has no RLS, so isolation is
> enforced in the application by `apps/api/core/tenancy.py`. Using a non-root user remains good
> practice (it bounds the blast radius of an application compromise), but it is no longer the
> mechanism that keeps tenants apart.

To tighten further — e.g. deny DDL to the runtime user so only migrations can alter the schema:

```sql
-- as root, against the mbs database
REVOKE ALL PRIVILEGES ON mbs.* FROM 'mbs'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON mbs.* TO 'mbs'@'%';
FLUSH PRIVILEGES;
```

If you do this, run migrations as `root` instead (`alembic upgrade head` needs DDL):

```bash
docker compose $COMPOSE run --rm \
  -e DATABASE_URL="mysql+aiomysql://root:$(cat infra/secrets/mysql_root_password.txt)@mysql:3306/mbs" \
  api alembic upgrade head
```

## ⚠️ Rotating credentials on an EXISTING deployment

**Changing a password in compose does not rotate anything on a volume that already exists.**
The MySQL image's `MYSQL_USER`/`MYSQL_PASSWORD` provisioning and MinIO's first-start
provisioning run only against an *empty* data directory, so on a live `mysql_data` / `minio_data`
volume the new secret file is simply ignored and the services keep their original credentials —
while the application starts using the new value and fails to connect. Rotate deliberately:

**MySQL**
```bash
# 1) change the user's password IN the database (root session)
docker compose $COMPOSE exec mysql \
  mysql -u root -p"$(cat infra/secrets/mysql_root_password.txt)" \
  -e "ALTER USER 'mbs'@'%' IDENTIFIED BY 'new-password'; FLUSH PRIVILEGES;"
# 2) update BOTH views of the credential to match, then restart the consumers
printf 'new-password' > infra/secrets/mysql_password.txt
printf 'mysql+aiomysql://mbs:new-password@mysql:3306/mbs' > infra/secrets/database_url.txt
docker compose $COMPOSE up -d --no-deps api worker worker-default beat
```

**Redis** — `requirepass` is read at start, so update the secret and restart the server *with* its
clients (a mismatch between `redis_password.txt` and `redis_url.txt` locks every consumer out):
```bash
printf 'new-password' > infra/secrets/redis_password.txt
printf 'redis://:new-password@redis:6379/0' > infra/secrets/redis_url.txt
docker compose $COMPOSE up -d redis && docker compose $COMPOSE up -d --no-deps api worker worker-default beat
```
In-flight Celery messages survive (AOF persistence, R1a), but expect a brief window where workers
reconnect.

**MinIO** — root credentials on an existing volume are changed through MinIO itself (`mc admin
user svcacct` / root rotation), then mirrored into `minio_root_password.txt` and `s3_secret_key.txt`.
Never delete `minio_data` to force new credentials: it holds scan evidence and generated reports.

## Network exposure (production)

The production merge publishes **one** routable port. Everything else talks over the compose
network by service name.

| Service | Host publication | Reachable from |
|---|---|---|
| `nginx` | `80` | anywhere — the only public entrypoint |
| `api` | `127.0.0.1:8000` | the host only (`curl http://127.0.0.1:8000/ready`) |
| `prometheus` / `alertmanager` | `127.0.0.1:9090` / `127.0.0.1:9093` | the host only |
| `mysql` / `redis` / `minio` / `web` | **none** | in-network only (`mysql:3306`, `redis:6379`, `minio:9000`, `web:3000`) |

Dev keeps direct access to all of them via `docker-compose.override.yml`, which compose
auto-merges for a bare `docker compose up` and which the production `-f` list excludes.
`apps/api/tests/test_deployment_config.py` fails the build if any service other than nginx
becomes reachable from off-host.

## TLS trust at build time
Production builds require **no** local CA file: the images verify PyPI / GitHub / npm
against the public root store shipped in their base image, and no interception root is
baked into any layer. The optional `extra_ca` BuildKit secret is a **developer-machine
convenience** for networks that intercept TLS (see the README); it is supplied by a
gitignored `infra/docker-compose.local-ca.yml` overlay that is never applied here. If a
build on a production host fails TLS verification, treat it as a network/proxy problem
to fix at the network layer — do not disable verification and do not add the overlay.

## Rolling restart (no scan loss)
Order matters: drain scan workers first, then the rest.
```bash
COMPOSE="-f infra/docker-compose.yml -f infra/docker-compose.prod.yml"

# 1) Scan workers: SIGTERM triggers warm shutdown -> current scan finishes (up to 60s),
#    then the container stops. New image starts and picks up the queue.
docker compose $COMPOSE up -d --no-deps --build worker

# 2) Default worker (reaper/relay/schedule/backup/retention/email).
docker compose $COMPOSE up -d --no-deps --build worker-default

# 3) Beat (stateless; a missed tick re-emits next interval).
docker compose $COMPOSE up -d --no-deps --build beat

# 4) API (uvicorn drains in-flight requests on SIGTERM).
docker compose $COMPOSE up -d --no-deps --build api

# 5) Web/nginx if changed.
#    `--build` is REQUIRED for web, not optional: infra/docker/Dockerfile.web is multi-stage
#    and runs `next build` inside the image, so the deployed bundle is produced at build time.
#    There is no source bind-mount in production -- the container serves only what the image
#    contains, so shipping a frontend change without rebuilding deploys the OLD bundle.
docker compose $COMPOSE up -d --no-deps --build web nginx
```
Notes:
- **The production `web` service runs `next start`, not `next dev`.** Dockerfile.web's final
  (`runtime`) stage carries the built `.next` output plus production dependencies only -- no
  sources, no eslint/typescript/vitest -- runs as the unprivileged `appuser`, and sets
  `NODE_ENV=production`. `docker-compose.prod.yml` resets the dev stack's `target: builder`
  and its `command: ["npm","run","dev"]`, and resets `volumes` to drop the base file's
  `../apps/web:/srv` bind-mount. Verify after a deploy with:
  `docker compose $COMPOSE exec web sh -c 'cat /proc/1/cmdline | tr " " " "'` (expect
  `npm run start ...`) and `docker inspect <web container> --format '{{json .Mounts}}'`
  (expect `[]`).
- A scan longer than `stop_grace_period` (60s) at shutdown is SIGKILLed and **redelivered**
  (acks_late) or recovered by the reaper — no data loss, just a restart of that scan.
- Only **one** `beat` must run (it's the scheduler). Do not scale it to >1.
- To scale scan throughput, scale `worker` replicas; keep `worker-default` and `beat` singular.

## Graceful shutdown / drain (single service)
```bash
# Stop accepting new work and let in-flight finish (warm shutdown), then stop:
docker compose $COMPOSE stop -t 60 worker           # -t >= stop_grace_period
```
`beat` can be stopped anytime (`-t 30`); the schedule resumes when it restarts.

## Health / readiness
- API liveness: `GET /health` (process up). Readiness: `GET /ready` (probes MySQL + Redis; 503
  if either is down) — gate load-balancer traffic on `/ready`.
- Workers expose Prometheus metrics on `:9100` (scraped by Prometheus). There is no per-container
  compose healthcheck on workers yet (tracked as a reliability follow-up); `restart: unless-stopped`
  covers process crashes.

## Production configuration: `TRUSTED_PROXY_COUNT`

**The API refuses to start in production unless this is set explicitly.** There is no safe
default to inherit, so the guard forces a decision rather than assuming your topology.

**The shipped overlay declares `TRUSTED_PROXY_COUNT: "1"`** — correct for the bundled topology
and nothing else. Set it in `infra/docker-compose.prod.yml`, **not in `.env`**: that service's
`environment:` mapping overrides the base file's `env_file: ../.env`, so a value placed in
`.env` is silently ignored for the API. `apps/api/tests/test_deployment_config.py` asserts the
overlay keeps satisfying `validate_production()`, so a future guard cannot regress unnoticed.

**What it is.** The number of proxies in front of this app that **append** to `X-Forwarded-For`.
The client's own address is then read as the **Nth entry from the right** — everything further
left is caller-supplied and forgeable. It is used for one thing: the rate-limit bucket key for
*anonymous* requests (authenticated requests bucket by user id and are unaffected).

- `0` — nothing appends in front. `X-Forwarded-For` is ignored entirely and the direct socket
  peer is used. **This is a valid and safe answer**; it just has to be chosen deliberately.
- `1` — one appending proxy (e.g. only the bundled `nginx`).
- `2` — two, e.g. an external load balancer or CDN in front of `nginx`.

**How to determine it — never guess.** From a client whose public IP you know, send a request to
production and read the raw `X-Forwarded-For` the API receives. Count the entries: if the header
holds exactly one entry equal to your real client IP, the answer is `1`; if two, `2`. Count only
proxies that *append* — a CDN that sets its own header (e.g. `CF-Connecting-IP`) but also appends
to `X-Forwarded-For` still counts as a hop.

**Why guessing is unsafe in both directions.**
- Too **low**: every anonymous client collapses into the proxy's single bucket, so the limiter
  throttles all unauthenticated traffic together — or effectively not at all.
- Too **high**: the Nth-from-right read reaches into caller-controlled entries, so any client can
  mint a fresh bucket per request by varying the header. This is worse than having no limiter.

**Prerequisite before using any non-zero value.** The API must be unreachable except *through*
the proxy chain. If a client can reach `:8000` directly, it supplies the whole
`X-Forwarded-For` header and any `N > 0` becomes attacker-controlled.

The shipped files already satisfy this, and the arrangement is deliberate: a compose `ports`
list is **appended** across `-f` files, never replaced, so a publication in the base file could
not be withdrawn by an overlay. Therefore:

| File | API host port | Applies to |
|---|---|---|
| `docker-compose.yml` (base) | none | always — in-network `api:8000` only |
| `docker-compose.override.yml` | `8000:8000` | dev only; auto-merged by a bare `docker compose up`, excluded from any explicit `-f` list |
| `docker-compose.prod.yml` | `127.0.0.1:8000:8000` | production — host-local ops (`curl http://127.0.0.1:8000/ready`) |

In production the only externally reachable entrypoint is `nginx` on `:80`. **If you publish
the API port yourself, put it back behind a firewall or return `TRUSTED_PROXY_COUNT` to `0`** —
`apps/api/tests/test_deployment_config.py` fails the build if any file in the production merge
publishes the API on a routable interface while the hop count is non-zero.

### TLS (F-01)

The production merge terminates TLS **at nginx**. `docker-compose.prod.yml` mounts
`infra/nginx/nginx.tls.conf` over `/etc/nginx/nginx.conf` and publishes `:443`; the inherited
`:80` publication serves nothing but a `308` to `https://` (plus `/.well-known/acme-challenge/`
so renewal keeps working). TLS 1.2/1.3 only, ECDHE+AEAD suites only, and HSTS is asserted on
the 443 listener — never over plaintext.

**Before the first production `up`, provide both files (never commit them; `infra/secrets/`
is gitignored):**

```bash
# CA-issued — Let's Encrypt or your internal PKI. A self-signed pair is NOT a production answer.
cp /path/to/fullchain.pem infra/secrets/tls_cert.pem   # leaf + intermediates
cp /path/to/privkey.pem   infra/secrets/tls_key.pem    # unencrypted (nginx cannot prompt)
chmod 600 infra/secrets/tls_key.pem
```

nginx **fails closed**: if either file is missing or empty the container prints a FATAL
message naming the problem and exits instead of falling back to plaintext. Do not "fix" that
crash loop by reverting to `nginx.conf` — `apps/api/tests/test_deployment_config.py` fails the
build if the production overlay mounts the plaintext config.

`ENABLE_HSTS: "true"` in the overlay is now truthful: there is a real https:// origin for a
browser to pin to.

**If you terminate TLS upstream instead** (ALB / CloudFront / Cloudflare / an ingress
controller), that is supported but is *not* the bundled path: keep the plaintext `nginx.conf`,
put the terminator in front, and **raise `TRUSTED_PROXY_COUNT`** — that terminator appends
another `X-Forwarded-For` hop, so the correct value becomes 2 or more.

## Post-deploy verification
- `GET /ready` → `ready`.
- Prometheus targets `mbs-api`, `mbs-worker` (worker:9100 + worker-default:9100) all `up`.
- No new `MbsWorkerDown` / `MbsApiDown` / `MbsDlqBacklog` alerts.
- A test scan completes end-to-end; `mbs_scan_success_total` increments.

## Rollback
- Re-deploy the previous image tag with the same rolling order above.
- If a migration must be undone, use the matching `alembic downgrade` **before** rolling back code
  — but prefer forward fixes; downgrades are a last resort.

## Related runbooks
- Disaster recovery / backups: `disaster-recovery.md`
- DLQ replay: `dlq-replay.md` (planned) — inspect/replay dead-lettered scans
- Retention enablement: `retention.md`
- Email alerts: `email-alerts.md`
