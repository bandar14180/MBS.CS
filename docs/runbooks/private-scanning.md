# Runbook — Private Scanning, Scanner Workers and Emergency Controls

Companion to `docs/architecture/scanner-isolation.md`. This is the operational half: how
to onboard a private site, and what to do when something is wrong.

---

## 1. Onboarding a private site

Order matters. A site is only scannable in `active`, and every earlier state is a gate.

### 1.1 Create the site (control plane)

```sql
-- authorized_cidrs is the ONLY source of private authorization for this tenant.
-- Be precise: everything inside these ranges becomes scannable for this workspace,
-- and nothing outside them ever is.
INSERT INTO private_sites (id, workspace_id, name, authorized_cidrs, dns_servers,
                           dns_search_domains, status, scanner_pool_id)
VALUES (UUID(), :workspace_id, 'acme-dc1',
        JSON_ARRAY('10.20.0.0/16'),      -- authorized CIDRs
        JSON_ARRAY('10.20.0.53'),        -- the customer's own resolver(s)
        JSON_ARRAY('internal.acme.corp'),
        'pending', 'private-acme-dc1');
```

### 1.2 Register the worker

```python
from apps.api.modules.scanner_workers import service as workers

token = workers.generate_worker_token()   # shown ONCE; only its hash is stored
print(token)                              # put in infra/secrets/scanner_worker_token_<slug>.txt
```

Insert a `scanner_workers` row with `site_id` set, `workspace_id` matching the site's,
`pool_id` = the site's `scanner_pool_id`, `status='pending'`, and
`token_hash = workers.hash_worker_token(token)`.

### 1.3 Key exchange — **the worker generates its own private key**

```bash
# INSIDE the private worker container. The private key must never leave it.
docker compose exec worker-site-acme-dc1 sh -c \
  'umask 077; wg genkey > /run/wireguard/private.key; wg pubkey < /run/wireguard/private.key'
```

Send **only the printed public key** to the customer, and record it as
`private_sites.worker_public_key`. Record the customer's public key as `peer_public_key`,
their endpoint as `wg_endpoint_host`/`wg_endpoint_port`. Move the site to
`key_exchanged`.

> **Never** paste a private key into the database, a ticket, a chat message, or a manager
> API call. If one is ever disclosed, treat it as a full compromise of that tunnel:
> generate a new keypair, re-exchange, and revoke the old worker.

### 1.4 Verify, then activate

Bring the tunnel up and confirm preflight passes (handshake fresh, a route present for
**every** authorized CIDR, DNS canary resolving). Move `verified` → `active`.

Only now will scans run. Until then every private scan is refused with a specific reason.

---

## 2. Reason codes

Every refusal carries a stable code — the same string appears in the log, the metric label
and the scan's failure reason.

| Code | Meaning | First action |
|---|---|---|
| `SITE_NOT_FOUND` / `SITE_WRONG_WORKSPACE` | Site missing, or belongs to another tenant | Verify the target's `site_id`. **A wrong-workspace code is a cross-tenant attempt — investigate, don't just fix the row.** |
| `SITE_SUSPENDED` / `SITE_REVOKED` / `SITE_NOT_ACTIVE` | Lifecycle state | Intentional? If not, finish onboarding or lift the suspension. |
| `NO_AUTHORIZED_CIDRS` | Empty/invalid CIDR list | Fix `authorized_cidrs`. Empty means *refuse*, never *unrestricted*. |
| `TARGET_OUTSIDE_AUTHORIZED_CIDRS` | Target outside what the customer authorized | Confirm with the customer, then widen the site's CIDRs — **never** the global allowlist. |
| `WORKER_REVOKED` / `WORKER_SUSPENDED` / `WORKER_NOT_ACTIVE` | Worker cannot lease | Check whether revocation was deliberate. |
| `WORKER_WRONG_SITE` / `WORKER_WRONG_WORKSPACE` | Worker asked for another tenant's work | **Treat as possible compromise.** See §4. |
| `PUBLIC_WORKER_CANNOT_TAKE_PRIVATE_JOB` | Routing/config error | A public worker has no tunnel; check the queue and `SCANNER_SITE_ID`. |
| `TUNNEL_UNHEALTHY` / `NO_HANDSHAKE` / `HANDSHAKE_STALE` / `PEER_UNREACHABLE` | Tunnel down | See §3. |
| `ROUTE_MISSING` | A CIDR has no route | Scan refused deliberately — a partial tunnel would make "no findings" indistinguishable from "not scanned". |
| `DNS_UNAVAILABLE` | Site resolver not answering | See §3.2. |
| `EGRESS_CONTROL_PLANE_DENIED` | A scanner tried to reach the control plane | **Investigate as a possible compromise.** No scanner has a legitimate reason. |

---

## 3. Tunnel troubleshooting

### 3.1 `HANDSHAKE_STALE` / `PEER_UNREACHABLE`

```bash
docker compose exec worker-site-<slug> wg show          # handshake age, transfer counters
docker compose exec worker-site-<slug> ip route         # one route per authorized CIDR
```

WireGuard rekeys ~every 2 minutes while traffic flows, so >180s of silence is real. Usual
causes: customer endpoint moved, customer firewall change, NAT idle timeout (set
`wg_persistent_keepalive = 25`).

### 3.2 `DNS_UNAVAILABLE`

The site's resolver is unreachable **through the tunnel**. Note that a private lookup will
**never** fall back to a public resolver — that is deliberate (it would leak the
customer's internal naming and could return an attacker-influenced answer). Fix the
resolver or the route; do not "work around" it by adding a public resolver to the site.

---

## 3a. The worker will not start / is not picking up work

The execution worker runs `python -m apps.api.scanner_worker.main` (NOT `celery worker` —
it cannot reach Redis, by design). Failure modes, in the order they occur at startup:

| Symptom in the logs | Cause | Fix |
|---|---|---|
| `scanner_worker.refusing_to_start ... holds control-plane credential(s): X` | A control-plane secret leaked into the scanner's environment | Remove it. It most likely arrived via `env_file: ../.env` — the worker must load `../.env.scanner`. A compose overlay **cannot** unset an env_file variable. |
| `cannot start without a complete identity; missing: ...` | One of `SCANNER_WORKER_ID` / `SCANNER_POOL_ID` / `SCANNER_MANAGER_URL` / `SCANNER_WORKER_TOKEN` is unset | Set it. A worker that cannot say who it is cannot be authorized for anything. |
| `lease_loop.auth_failed ... stopping` | The credential is refused: worker unknown, revoked, suspended, or not yet `active` | Check `SELECT status, revoked_at FROM scanner_workers WHERE worker_id=...`. Retrying is deliberately NOT attempted — a dead credential cannot succeed. |
| `lease_loop.manager_unavailable` repeating | The manager is down or unreachable on `mbs-dispatch` | Check the manager container. The worker backs off with jitter and recovers on its own; it will **never** fall back to Redis. |
| Leases return 0 jobs forever | Nothing queued *for this worker* | The manager only leases jobs matching this worker's own pool/site/workspace. For a private worker, confirm the site is `active`. |
| `lease_loop.job_rejected ... reason=SITE_MISMATCH` (or POOL/CIDR/TUNNEL) | The worker refused a job the manager offered | This is the worker re-validating against its own identity. Investigate the mismatch — do not "fix" it by relaxing the worker's config. |
| `lease_loop.complete_superseded` | This execution lost the fencing race (requeued, reclaimed, or cancelled) | Normal. Another executor owns the scan now; this one correctly did not overwrite it. |
| `lease_loop.heartbeat_failed` (debug) | A liveness beat did not reach the manager | Best-effort by design; a few missed beats are harmless (`scan_stale_heartbeat_seconds` is many beats wide). Persistent failures mean the manager is unreachable — the scan will eventually be reaped and re-leased. |

### A PRIVATE worker will not start

A private worker brings its tunnel up **before** it leases anything, and refuses to start if
it cannot prove the tunnel is healthy. That is deliberate: a worker that came up anyway
would reject every job it was offered, reporting a deployment fault as a stream of runtime
refusals. Startup failures name a reason:

| `reason=` | Meaning | Fix |
|---|---|---|
| `WG_TOOLING_MISSING` | The image lacks `wg` and/or `ip` | Use an image built from `Dockerfile.worker` at or after the wireguard-tools layer. |
| `WG_PRIVATE_KEY_MISSING` | `SCANNER_WIREGUARD_PRIVATE_KEY_FILE` unset, or the file is missing/empty | Mount the key secret. **Generate it inside the container** (below) — never accept one from the control plane. |
| `WG_INTERFACE_SETUP_FAILED` | `wg0` could not be created or configured | The container needs `CAP_NET_ADMIN` and a host kernel with WireGuard support. Check `cap_add` in the site's compose file. |
| `WG_ROUTE_SETUP_FAILED` | An authorized CIDR could not be routed | Usually a malformed CIDR on the site row, or a conflicting existing route. |
| `WG_MTU_SETUP_FAILED` | The configured MTU could not be applied to `wg0` | See §3c. Failing to *set* the MTU is fatal rather than ignored, because an unset MTU black-holes large packets silently. |
| `WG_DEFAULT_ROUTE_REFUSED` | A default route points at `wg0` | Refused deliberately: it would capture **all** worker egress — other tenants' scans and the manager connection — into one customer's network. |
| `NO_HANDSHAKE` / `HANDSHAKE_STALE` / `ROUTE_MISSING` / `DNS_UNAVAILABLE` | The tunnel came up but is not usable | See §3 — this is the same preflight the lease loop runs per job. |
| `site … is 'suspended', not 'active'` | Site lifecycle | Intentional? If not, see §1.4. |

**Generating the key (once, per site, inside the worker):**

```bash
docker compose exec worker-site-<slug> sh -c \
  'umask 077; wg genkey | tee /run/wireguard/private.key | wg pubkey'
```

Store the **printed public key** as `private_sites.worker_public_key` and place the private
half in `infra/secrets/wg_private_key_<slug>.txt` (mode 0600, owned by uid 10001). The
control plane must never hold the private half.

### A worker died mid-scan — what happens

Nothing needs doing; this is the orphan reaper's job. The sequence:

1. The worker stops beating, so `scans.last_heartbeat_at` goes stale.
2. `scans.reap_orphaned_scans` (on `worker-default`) marks the scan `failed`, **clears
   `execution_token`**, and records why in `config.recovery.reason` —
   `SELECT JSON_EXTRACT(config,'$.recovery.reason') FROM scans WHERE id=…`.
3. Another authorized worker re-leases it and gets a **new** token.
4. If the "dead" worker was merely slow and comes back, its terminal write is refused
   (`accepted: false`, `reclaimed_by_new_owner`) — it cannot overwrite the replacement.

Only reaper-recovered failures are re-leased. A scan that failed on its own merits (bad
target, tool crash, exhausted retries) is **not** picked up again — that path is bounded by
Celery's retry chain and the DLQ (`python -m apps.api.celery_app.dlq list`).

If a scan is stuck `running` with no worker alive, check that `worker-default` is up: it
runs the reaper. Do **not** clear `execution_token` by hand — that is the reaper's atomic
job, and doing it manually removes the fencing that stops two executors colliding.

To verify a worker end to end, exec into it and call the manager with its own credential
(the container has no database access — that is the point). Post to
`$SCANNER_MANAGER_URL/v1/heartbeat` and then `/v1/lease` with the headers
`X-Worker-Id: $SCANNER_WORKER_ID` and `Authorization: Bearer $SCANNER_WORKER_TOKEN`.
A healthy worker returns `{"ok": true, ...}` and then a job list (possibly empty).

---

## 3b. WireGuard key rotation

Rotation is **deliberately manual**. Automating it would mean the control plane holding or
transporting a private key, which is precisely the property this architecture refuses — one
database compromise would otherwise yield authenticated access inside every customer network
at once. The procedure below keeps the private half inside the worker at every step.

**Zero-downtime order (add the new key before removing the old one):**

1. **Generate the replacement inside the worker.** Never on a laptop, never in CI:
   ```bash
   docker compose exec worker-site-<slug> sh -c \
     'umask 077; wg genkey | tee /run/wireguard/private.key.new | wg pubkey'
   ```
2. **Send the printed PUBLIC key to the customer** and have them add it as a second peer
   alongside the existing one, with the *same* AllowedIPs. Both keys work during the overlap.
3. **Verify the customer has applied it** before touching the worker.
4. **Install the new key** — replace `infra/secrets/wg_private_key_<slug>.txt` (mode 0600,
   owned by uid 10001) and restart the worker. Startup brings the tunnel up and refuses to
   proceed unless preflight passes, so a bad rotation fails closed at boot rather than
   mid-scan.
5. **Confirm the handshake** (`wg show wg0 latest-handshakes`), then update
   `private_sites.worker_public_key` to the new public key.
6. **Have the customer remove the OLD peer.** Rotation is not complete until this happens —
   until then the old key still authenticates.
7. **Destroy the old private key** (`rm -f /run/wireguard/private.key`). It lives on tmpfs,
   so a container restart also clears it.

**Invariants to check after any rotation** (asserted by
`test_phase8_vpn_operations.py`):

- `AllowedIPs` is unchanged — rotation must never widen the authorized set.
- The site binding is unchanged — the worker still serves exactly one site.
- No private key appears in the database, in a log line, or on a command line.
- The old key no longer authenticates once the customer removes the peer.

**If a key is suspected compromised**, do not rotate gracefully — revoke first (§4.1),
then rotate. Revocation is control-plane side and does not depend on reaching the worker.

---

## 3c. Tunnel MTU

The tunnel MTU is set **explicitly** at bring-up from `SCANNER_WIREGUARD_MTU`
(default **1420** — WireGuard's own value for IPv4-over-IPv4 on a 1500-byte path). It is
applied *before* the link comes up, so there is no window at the wrong size.

**This is a reachability control, not an isolation one.** An oversized packet is dropped or
fragmented, never re-routed, so a wrong MTU cannot move traffic outside the authorized
CIDRs. That is why the MTU is deliberately **not** part of the tunnel health verdict — a
scan is never failed closed over it. It is reported instead: `tunnel.probe` and
`scanner_worker.tunnel_ready` log the live value for drift detection.

**Symptom that means "lower the MTU":** the handshake succeeds and small probes work
(a host answers ping / a port shows open), but anything carrying a full-size payload
stalls — HTTP responses hang or truncate, and a scan reports "no response" from a host
that is demonstrably up. This is a black-hole, not an error; nothing logs a failure.

Typical causes and values, for the site's path — **not** the worker's:

| Customer path | Try |
|---|---|
| Plain Ethernet / 1500-byte path | `1420` (default) |
| PPPoE (1492-byte path) | `1412` |
| Tunnelled/nested transport (GRE, IPsec, another VPN) | `1380` or lower |

Set it per site, in that site's compose file:

```yaml
environment:
  SCANNER_WIREGUARD_MTU: "1412"
```

Restart the worker. Confirm it took effect — the value below must match what you set:

```bash
docker compose exec worker-site-<slug> ip -o link show wg0   # -> "... mtu 1412 ..."
```

Then re-run the scan that was black-holing. If lowering the MTU does not fix it, the
problem is not MTU — check the route and the handshake (§3, §3.1) before lowering further.
Do **not** lower it below 1280 (the IPv6 minimum) to chase a symptom.

---

## 4. Emergency controls

Ordered least → most disruptive. All are enforced **control-plane side**, so none require
reaching the scanner host — which matters precisely when the host is compromised.

### 4.1 Revoke one worker (suspected compromise)

Run from inside any control-plane container (`api`, `scanner-manager`, `worker-default`) —
it needs the control-plane database credentials, which is the same access required to restart
the service. There is deliberately no HTTP endpoint for this.

```bash
docker compose exec scanner-manager   python -m apps.api.ops.revoke_worker     --worker-id worker-site-acme-dc1     --reason "suspected compromise"
```

Both arguments are **mandatory**. `--reason` is persisted to `revoked_reason` and logged; it
is the only record of *why* a worker was cut off, so it is never defaulted.

Expected output:

```
REVOKED worker_id=worker-site-acme-dc1
  status            = revoked
  revoked_at        = 2026-09-12 00:14:07.123456+00:00
  revoked_reason    = suspected compromise
  token_hash        = CLEARED
  cert_fingerprint  = CLEARED
```

Exit code `0` means the change was **committed**. Exit code `2` means nothing was written
(most commonly an unknown `--worker-id` — check the spelling and try again).

**What revocation does:**

- `status` → `revoked`, with `revoked_at` and `revoked_reason` stamped.
- **Both stored credentials are destroyed** (`token_hash` and `cert_fingerprint` → NULL), so
  there is no hash left for a future bug to re-accept.
- The worker is refused at authentication *and* at every authorization gate from its next
  manager call onward — new leases and in-flight work alike.
- A `mbs_scanner_worker_revoked_total` increment fires the **MbsScannerWorkerRevoked** alert.

**What revocation does NOT do:**

- **It does not tear down WireGuard.** Revocation is control-plane side: the worker can no
  longer lease work or submit results, but a compromised *host* keeps its tunnel into the
  customer network until its container is stopped. To remove network reach, also do §4.4.

**Recovery:** a revoked worker is **terminally revoked and must never be reactivated**.
Recovery means provisioning/registering a **replacement worker with fresh credentials** —
there is no un-revoke, by design.

### 4.2 Suspend one site

```sql
UPDATE private_sites SET status='suspended', status_reason='<why>' WHERE id=:site_id;
```

Blocks new scans **and** in-flight submissions — the manager re-checks the site on every
scan-scoped request, so suspension takes effect for work already running.

### 4.3 Stop ALL private scanning platform-wide

**Use this (no restart, effective within ~5s):**

```bash
touch infra/runtime/EMERGENCY_DISABLE_PRIVATE_SCANNING     # ON  -- stop all private scanning
rm    infra/runtime/EMERGENCY_DISABLE_PRIVATE_SCANNING     # OFF -- all clear
```

`infra/runtime/` is bind-mounted read-only into the scanner-manager at `/run/mbs`. The
manager re-reads the sentinel at most every 5 seconds, so creating or removing the file takes
effect on the RUNNING process -- no restart, no redeploy. It blocks new leases **and**
in-flight private work (results, evidence, lease completion), because the check sits in the
gate every scan-scoped request passes through.

Public scanning is unaffected in both directions.

**Removing the file re-enables private scanning.** It is a deliberate "all clear" -- do not
delete it to tidy up.

The environment variable still works and is the right form for a deployment that should come
up with private scanning off permanently:

```bash
PRIVATE_SCANNING_EMERGENCY_DISABLE=true   # requires a scanner-manager restart to take effect
```

The effective value is the **logical OR** of the two: the sentinel can only ever ADD
restriction. If the environment disables private scanning, removing the sentinel cannot
re-enable it -- change the environment (and restart) to undo that.

If the manager cannot read the sentinel directory at all, it **fails closed**: it keeps the
last known value, or -- if it has never read successfully -- refuses private scanning.

### 4.4 Drain a queue

```bash
docker compose stop worker-site-<slug>
```

Work stays queued (`acks_late`); the orphan reaper recovers anything that was mid-flight.
No other worker is permitted to drain a private site's queue, so nothing else picks it up.

---

## 4a. Monitoring, health and the audit trail (Phase 8)

### What reports what

| Signal | Source | Where to look |
|---|---|---|
| Tunnel up/down, handshake age | Private worker probes its own `wg0` (P8-A) | `mbs_tunnel_up`, `mbs_tunnel_handshake_age_seconds` |
| Worker liveness + tunnel health | Worker heartbeat every 30s, **including while idle** (P8-B) | `scanner_workers.health_state`, `last_seen_at`, `last_handshake_age_s` |
| Those metrics, centrally | scanner-manager `/metrics`, token-gated (P8-C) | Prometheus job `mbs-scanner-manager` |

A private worker is **never scraped directly** — it has no metrics port and lives on its own
site network. It reports health to the manager, and the manager exposes the projection. The
metric labels carry `pool_id` only; site and workspace ids are deliberately not published.

A worker that has stopped reporting shows a climbing
`mbs_scanner_worker_heartbeat_age_seconds` and fires **MbsScannerWorkerHeartbeatStale** at
300s. If silence continues past 600s the stale reaper suspends it (below).

### Stale-worker reaper (P8-F)

A beat task sweeps every 300s and moves any worker silent for more than **600s** from
`active` to `suspended`. It is fail-closed and one-directional:

- it only ever removes lease eligibility — there is no path that sets `active`;
- `revoked` is terminal and is never touched;
- `pending`, `draining` and already-`suspended` workers are left alone;
- a worker that registered but never reported is measured from `created_at`.

**Suspension is reversible but NOT automatic.** A worker that starts reporting again stays
suspended until an operator reactivates it deliberately — silence is a thing to investigate,
not to forgive silently.

### Durable audit trail (P8-G)

Operator and system actions are written to `platform_audit_events`, which is **append-only
and non-cascading** — a record outlives the worker, site or workspace it describes. Container
logs are not a substitute: they are not shipped, not rotated, and are destroyed when a
container is recreated.

| Event | Trigger | Actor recorded | Workspace |
|---|---|---|---|
| `scanner.worker.revoked` | Operator, via the §4.1 CLI | `--actor` value, or `unattributed` | The worker's own — **NULL** for a shared public worker |
| `scanner.worker.reaped_stale` | **System** (the reaper) | `system` | The worker's own |
| `scanner.private_scanning.emergency` | **System-observed** transition | `system` | **NULL** (platform-wide) |

**Read the actor field honestly:**

- **Operator-attributed** — only where `--actor` was explicitly supplied on the revocation
  CLI. Even then it is **operator-supplied attribution, not authenticated identity**: a CLI
  has no authenticated principal, so the record stores a *claim*, corroborated only by the
  fact that the person had control-plane container access. `actor_user_id` is deliberately
  left NULL, because that column means a verified user.
- **Unattributed** — a revocation where `--actor` was omitted. The absence is recorded
  explicitly rather than being filled in with a guess.
- **System** — the stale reaper and the emergency-flag transitions. No human is involved, so
  no human is named.

**P8-D entries are application-observed transitions, not filesystem attribution.** The
sentinel is created or removed on the host; the application cannot see who did it. What is
recorded is that the manager *observed* the effective state change, marked
`source=observed_runtime_transition`. One row is written per manager process per transition —
with several replicas, each records its own observation.

Audit details are secret-free by construction: ids, states and reasons only. No token, token
hash, certificate fingerprint, filesystem path or environment value is ever stored.

**Auditing is best-effort and never blocks enforcement.** If the audit write fails, the
revocation still cuts the worker off, the reaper still suspends, and the emergency switch is
still enforced — the failure is logged instead.

Querying the trail:

```sql
SELECT created_at, event, detail
FROM platform_audit_events
WHERE event LIKE 'scanner.%'
ORDER BY created_at DESC
LIMIT 50;
```

**Two things the reaper does NOT audit:** a sweep that suspends zero workers writes no row
(an audit trail of non-events hides the real ones), and it records the suspension only — not
the silence that preceded it, which is what the metrics and alerts are for.

---

## 5. Verifying isolation after a change

```bash
# 1. The scanner shares no network with any datastore or the API.
python -m pytest apps/api/tests/test_scanner_credential_isolation.py -q

# 2. Global config alone authorizes nobody; tenants stay isolated.
python -m pytest apps/api/tests/test_private_site_authz.py -q

# 3. The manager refuses cross-tenant leases/evidence.
python -m pytest apps/api/tests/test_scanner_manager_authz.py -q

# 4. Egress, DNS and WireGuard safety.
python -m pytest apps/api/tests/test_scanner_egress_wireguard.py -q
```

Live network check (a compromised-scanner simulation):

```bash
# Each of these MUST fail — the worker has no route to the control plane.
docker compose exec worker sh -c 'timeout 5 nc -vz mysql 3306; echo "exit=$?"'
docker compose exec worker sh -c 'timeout 5 nc -vz redis 6379; echo "exit=$?"'
docker compose exec worker sh -c 'timeout 5 nc -vz minio 9000; echo "exit=$?"'
docker compose exec worker sh -c 'timeout 5 nc -vz api   8000; echo "exit=$?"'
# This one MUST succeed — the single permitted control-plane endpoint.
docker compose exec worker sh -c 'timeout 5 nc -vz scanner-manager 8100; echo "exit=$?"'
```

---

## 6. Rollback

The change is additive; rolling back is ordered but undramatic.

1. **Application only** (keep the schema): revert the code. `targets.network_zone`
   defaults to `'public'`, so every existing target keeps its current behaviour and the
   extra tables are simply unused.
2. **Queues / dispatch:** the scan queue was renamed `scans` → `scans.public`, and the
   isolated worker no longer consumes any queue at all (it leases from the manager).
   Rolling back to `celery worker -Q ...` REQUIRES restoring the worker's Redis access —
   i.e. putting it back on `mbs-core`, which undoes the isolation. Do that only as a
   deliberate, temporary step, and drain in-flight leases first (stop the worker and let
   the orphan reaper recover anything mid-flight).
3. **Credentials:** restoring `env_file: ../.env` on the worker restores the old
   (over-credentialled) behaviour. Do this only as a deliberate, temporary step.
4. **Schema:** `alembic downgrade -1` from `d5e6f7a8b9c0`. The downgrade is idempotent —
   MySQL has no transactional DDL, so a partially-applied downgrade re-runs safely.
   Any `targets` row with `network_zone='private'` loses its site linkage, so re-check
   private targets before downgrading.
