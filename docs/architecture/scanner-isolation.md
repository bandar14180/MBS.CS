# MBS.SC — Scanner Isolation, Tenant Boundaries and Private Network Scanning

Status: implemented (see `apps/api/tests/test_scanner_*.py`, `test_private_site_authz.py`).

This document describes the control-plane / execution-plane split, why each boundary
exists, and what each one does *not* protect against.

---

## 1. The problem this replaces

The scanner used to be a Celery worker sitting on the same Docker network as every other
service, holding the same credentials as the API, and deciding whether it could scan a
private address from two **process-wide** settings.

Three consequences followed, and each is a separate class of failure:

| Before | Consequence |
|---|---|
| No `networks:` in compose — every service on the default bridge | A compromised scanner could open a TCP connection to `mysql:3306`, `redis:6379`, `minio:9000`, `api:8000`. Application checks were the *only* boundary. |
| `env_file: ../.env` on the scan worker | The process running untrusted tool binaries held the DB DSN, the Redis URL, MinIO root credentials, **the JWT signing key**, and the OpenRouter key. Scanner RCE ⇒ mint a token for any user in any workspace. |
| `scan_allow_private_targets` + `scan_allowed_cidrs` | Global. Enabling private scanning for one on-prem customer enabled it for **every tenant**, for every listed CIDR. `is_ip_allowed(ip)` took no workspace argument, so per-tenant private authorization was not merely absent — it was **unrepresentable**. |

---

## 2. The authorization chain

Every private scan is validated against this chain, and **refused at the first broken
link**. There is no step that can be satisfied by configuration alone.

```
Workspace
  └─ Private Site            owned by exactly one workspace; must be ACTIVE
       └─ Authorized CIDRs   non-empty; the only source of private authorization
            └─ Scan          target's network_zone + site_id (from the TARGET row)
                 └─ Pool     per-site queue: scans.private.<site-id>
                      └─ Worker Identity   bound to that one site; individually revocable
                           └─ Tunnel       preflight: handshake, routes, DNS canary
                                └─ Destination   inside the authorized CIDRs
```

Implemented in `modules/private_sites/service.py::build_scan_network_policy`, which is the
only supported way to obtain a private policy.

---

## 3. Network segmentation

```
        ┌────────── mbs-edge ──────────┐
        │  nginx ── web ── api         │   (only plane with a published port)
        └──────────────┬───────────────┘
                       │
        ┌────────── mbs-core (internal: true) ──────────┐
        │  api · beat · worker-default                  │
        │  mysql · redis · minio · ollama               │
        │  scanner-manager ◄── bridges the two planes   │
        └──────────────┬────────────────────────────────┘
                       │ mbs-dispatch (internal: true)
                       │   manager API only
        ┌──────────────┴────────────────────────────────┐
        │  worker (scans.public)                        │
        │  worker-site-<slug> (scans.private.<site-id>) │
        │       └─ mbs-scan-egress / mbs-site-<slug>    │
        └───────────────────────────────────────────────┘
```

The scanner worker is attached to `mbs-dispatch` + an egress network **only**. It shares
no network with any datastore or the API, so Property A holds at the IP layer regardless
of what the scanner's code does. Asserted by
`test_scanner_credential_isolation.py::test_worker_is_not_on_any_control_plane_network`.

---

## 4. The two-key rule (per-scan network policy)

`net_guard` still answers *"is this address safe?"* exactly as before. What is new is a
second, independent key answering *"is this address **this tenant's** to scan?"*

A non-public address is permitted only when **both** agree:

1. **Global** (`scan_allow_private_targets` + `scan_allowed_cidrs`) — the outer safety
   boundary, semantics unchanged.
2. **Per-scan** (`ScanNetworkPolicy`) — derived from persisted workspace → site → CIDR
   authorization.

Global config is therefore a **ceiling, never a grant**. With the flag fully on and no
policy bound, every private address is still refused —
`test_global_flag_alone_does_not_authorize_any_tenant`.

**Fail-closed by construction:** an unbound context yields `PUBLIC_ONLY`. Forgetting to
bind a policy *loses* private access rather than gaining it. There is no constructible
"allow everything" policy.

**Public scanning is untouched.** A public address never consults the policy at all, so
every existing engagement behaves exactly as before.

---

## 5. Overlapping RFC1918 space

Tenant A and tenant B may both use `10.0.0.0/8`, and both may have a host at `10.0.0.5`.
Isolation therefore **cannot** come from the addresses. It comes from two places:

* **Authorization** — the CIDR check is against *this site's* list, and a site belongs to
  exactly one workspace (`test_overlapping_rfc1918_ranges_stay_isolated`).
* **Routing** — each private site gets its own worker, network namespace, WireGuard
  interface and queue (`infra/docker-compose.private-site.yml`). Two tunnels never share a
  routing table, so the kernel is never asked to disambiguate identical destinations.

---

## 6. WireGuard

* **Terminates inside the private worker namespace**, never on the control-plane host.
* **AllowedIPs = exactly the authorized CIDRs.** `0.0.0.0/0` is refused by construction
  (`build_allowed_ips` raises) — as an AllowedIPs value it would route *all* worker
  traffic, including other tenants' scans and the manager connection, into one customer's
  network.
* **No `DNS =` in wg0.conf.** wg-quick's `DNS=` rewrites the whole namespace resolver,
  which would send public lookups and the manager's own name to the customer. Site DNS is
  applied **per lookup** instead (`site_dns.py`).
* **Private keys are never persisted centrally.** `private_sites` holds `peer_public_key`
  and `worker_public_key` only. The worker's private key is generated in the namespace and
  lives on tmpfs. Asserted at the schema level by
  `test_private_key_is_never_a_persisted_site_column`.

**Why:** if the control plane stored every customer's tunnel private key, one database
compromise would yield simultaneous authenticated access *inside* every customer network.

### Verified in a disposable lab

A throwaway kernel-WireGuard topology (a peer container standing in for the customer, a
private docker network, and an nginx target at `10.80.0.50`; keys generated in-lab and
destroyed afterwards) exercised the whole private path end to end:

| Property | Evidence |
|---|---|
| Config from the production generator | `AllowedIPs = 10.80.0.0/16`, `Table = off`, **no** `DNS=` line, no default route |
| Real tunnel | handshake observed; `wg` transfer counters rose 92/180 → 1692/900 during the scan |
| Probe reads it | `interface_up=True`, `routes=('10.80.0.0/16',)`, preflight **PASS** |
| Private scan | leased → validated → HTTP 200 from `10.80.0.50` → results + evidence via the manager → fenced completion; duplicate refused |
| Evidence | 896 B stored in MinIO **by the manager** — the worker holds no MinIO credential and has no route to it |
| Kernel-level containment | `10.80.0.50` reachable; `10.90.0.50` and `10.0.0.1` **not routed** over the tunnel |
| Tunnel loss mid-flight | target became unreachable, route still `dev wg0` — **no silent reroute**; after 287 s preflight refused `HANDSHAKE_STALE` |
| DNS | private name → `SiteDNSUnavailable` with no public fallback; with the site resolver → queried `10.80.0.53`; worker `/etc/resolv.conf` untouched |

### The tunnel probe

`SystemTunnelProbe` reads the live tunnel inside the private worker's own namespace —
`wg show <iface> latest-handshakes` for handshake age, `ip -o route show dev <iface>` for
which prefixes are actually routed. It is **read-only**: it never brings an interface up,
installs a route, or touches key material (the container entrypoint does that, and is the
only thing holding `CAP_NET_ADMIN` for the purpose).

Every failure path returns an *unhealthy* status rather than raising or guessing — missing
binary, permission error, unparsable line, timeout. A probe that cannot see the tunnel must
never be mistaken for one that saw a healthy tunnel. It also does no caching: a stale
"healthy" reading is exactly what would let a scan start on a dead tunnel.

A default route on the interface is recorded verbatim as `"default"` so it can never
silently satisfy a per-CIDR route requirement.

### Preflight (a scan never starts on a sick tunnel)

`TUNNEL_UNHEALTHY`, `NO_HANDSHAKE`, `HANDSHAKE_STALE`, `PEER_UNREACHABLE`,
`ROUTE_MISSING`, `DNS_UNAVAILABLE` — each refuses with a specific reason. A missing route
for *any* authorized CIDR blocks the scan, because a partially-routed tunnel makes "no
findings" indistinguishable from "never reached".

---

## 7. DNS

Public scanning keeps the OS resolver. A **private** lookup goes to the site's own
resolvers through the tunnel and **never falls back** to a public resolver — a fallback
would both disclose the customer's internal naming to a third party and risk scanning an
attacker-influenced public address. With no resolver configured, a private lookup raises
(`SiteDNSUnavailable`, a `socket.gaierror` subclass so existing callers degrade normally).

---

## 8. Credential matrix

| Credential | api | scanner-manager | worker-default / beat | **scan worker** | private worker |
|---|:--:|:--:|:--:|:--:|:--:|
| `DATABASE_URL` | ✅ | ✅ | ✅ | ❌ | ❌ |
| `REDIS_URL` | ✅ | ✅ | ✅ | ❌ | ❌ |
| `S3_ACCESS_KEY` / `S3_SECRET_KEY` | ✅ | ✅ | ✅ | ❌ | ❌ |
| `JWT_SECRET_KEY` | ✅ | ❌ | ❌ | ❌ | ❌ |
| `OPENROUTER_API_KEY` | ✅ | ❌ | ✅ | ❌ | ❌ |
| `SCANNER_WORKER_TOKEN` | ❌ | ❌ | ❌ | ✅ | ✅ |

The scan worker's production environment is three non-secret variables
(`ENVIRONMENT`, `SCANNER_EXECUTION_PLANE`, `SCANNER_MANAGER_URL`) plus its own worker
token.

**Why a separate `.env.scanner` file:** Docker Compose **cannot unset an `env_file`
variable from an overlay**. Omitting the `*_FILE` entries in the production overlay would
still leave `.env`'s values in the container. The only way to withhold a credential is to
never load the file — hence the separate file, asserted by
`test_scanner_worker_does_not_load_the_control_plane_env_file`.

---

## 9. The manager boundary

`apps/api/scanner_manager/app.py` — six endpoints, not a proxy.

The rule: **a request may identify which scan it is talking about; it may never supply the
workspace, site or pool that authorizes it.** Those come from the database rows for the
authenticated worker and the named scan, and the two must agree.

* `LeaseIn` accepts only `max_jobs`. No `workspace_id`, `site_id` or `pool_id` fields
  exist — asserted by AST inspection in `test_scanner_raw_sql_tenancy.py`.
* `/v1/site-config` takes **no site parameter**: the site is read from the worker's row,
  so no request can ask for another customer's tunnel configuration.
* Evidence is filed under the workspace of the **scan row**; `EvidenceIn` has no
  `workspace_id` field.

---

## 9a. How the execution worker gets work (the lease model)

A `celery worker` **must** reach Redis to consume tasks. Once the scanner left `mbs-core`,
Redis became unreachable by design — so the execution plane pulls work instead of having it
pushed:

```
worker ──POST /v1/lease──────────▶ manager   (mbs-dispatch, HTTP)
                                     │ authorizes against the WORKER'S OWN row
                                     │ CLAIMS the scan (orchestrator._claim_scan)
                                     │ issues an execution_token
       ◀── execution plan ───────────┘   target, modules, zone, CIDRs, resolvers
worker  re-validates the job against its own identity  (fail closed)
worker  binds the per-scan network policy, preflights the tunnel if private
worker  runs the TOOL RUNNERS (which are database-free)
worker ──POST /v1/tool-results, /v1/evidence ─▶ manager persists (validated)
worker ──POST /v1/lease/complete ────────────▶ manager finalises, fenced on the token
```

**The seam.** `orchestrator.run_scan` takes an `AsyncSession` and touches the database at
58 call sites — all legitimate control-plane work. The **tool runners touch it at zero**.
So the execution plane runs the runners; the orchestrator stays control-plane side.

**One fencing mechanism, not two.** The lease claims through the *same*
`orchestrator._claim_scan` conditional UPDATE that has always fenced Celery redelivery, and
completes through the *same* `_finalize_status`. A lease-model worker and a control-plane
Celery executor therefore contend on one mechanism — two mechanisms could disagree about
who owns a scan.

**The worker re-validates everything.** The manager is authoritative, but a job arrives over
a network, and "it was handed to me" is not "it is authorized for me". Every job is checked
against the worker's own configured identity (`SCANNER_WORKER_ID` / `POOL_ID` / `SITE_ID`,
which the manager cannot influence) and refused on any mismatch, with a stable reason:
`SITE_MISMATCH`, `POOL_MISMATCH`, `EXECUTION_TOKEN_INVALID`, `CIDR_NOT_AUTHORIZED`,
`TUNNEL_UNHEALTHY`, `WORKER_UNAUTHORIZED`.

**Celery is not removed.** It still runs the control plane: scheduling, orphan recovery,
DLQ, retention, backups, reports. Only *consumption by the isolated execution worker* moved.

**Orphan recovery of an abandoned lease.** A worker that dies mid-lease leaves the scan
`running` with nothing to finalise it. The existing reaper handles this — but it keys on
`scans.last_heartbeat_at`, which only the control-plane executor could stamp. A lease
worker has no database, so a leased scan would have looked heartbeat-less for its whole
life and the reaper would have fallen back to its cruder "runtime exceeded" rule: healthy
long scans reaped early, dead ones recovered late.

So `/v1/heartbeat` optionally carries `scan_id` + `execution_token`, and the lease worker
beats every 30s while a job runs (matching `TOOL_PROGRESS_INTERVAL_SECONDS`, so both
dispatch models produce the same cadence). The stamp goes through the *same* fenced
statement the Celery executor uses, so a worker can only refresh a scan it verifiably
owns — a revoked straggler stamps nothing.

The recovery itself is unchanged: the reaper marks the scan `failed` and **clears the
execution token in the same atomic statement**, which revokes the dead worker. Its
docstring already described this as "a REVOCATION, not an overwrite". Verified live:

| Step | Result |
|---|---|
| Worker A leases | `running`, token `9bbedd1e`, heartbeat stamped |
| Worker A dies | heartbeats stop |
| Reaper runs | `REAPED = 1` → `failed`, token `NULL`, `config.recovery.reason` set |
| Worker B re-leases | new token `adc0f229` |
| Worker A completes (old token) | `accepted: false` — `reclaimed_by_new_owner` |
| Worker B completes | `accepted: true` |
| Worker B completes again | `accepted: false` — `already_terminal` |

**Which failures are re-leasable.** `_claim_scan` treats `failed` as claimable (its retry
path), so the lease query has to choose. It selects `queued` plus **only** failures the
reaper recovered, identified by `config.recovery`. An ordinary failure — bad target, tool
crash, exhausted retries, dead-lettered — is deliberately *not* re-leased, because that
case is already bounded by Celery's autoretry chain and the DLQ, and an unconditional
re-lease would be an unbounded retry loop bypassing both.

**Failure behaviour.** Bounded exponential backoff with full jitter (a fleet that lost the
manager together must not return in lockstep). An auth refusal is terminal, not retried — a
revoked credential cannot succeed and retrying only loads the manager. And if the terminal
write is never accepted, the scan is **not** reported successful: the orphan reaper recovers
it, which is exactly its job.

---

## 10. What this does *not* protect against

Stated plainly, because a boundary you misunderstand is worse than one you don't have:

1. **External tool binaries.** nuclei/katana/ffuf open their own sockets and follow their
   own redirects in another process. `egress_guard` cannot intercept those. This is why
   network segmentation (layer 1) and the namespace firewall (layer 2) are the load-bearing
   controls, and the in-process guard is layer 3.
2. **A compromised manager.** The manager holds real credentials by design. It is
   hardened and small, but it is the next pivot target after the worker.
3. **Self-reported worker health.** A compromised worker can claim to be healthy.
   Heartbeat data is advisory — used for alerting, never as the authority for "may this
   scan run", which comes from a live preflight probe.
4. **`default-mysql-client` in the scanner image.** Present because the DR backup task
   (`worker-default`) needs it and both services share one image. Inert without a route or
   a credential; splitting the image is a recorded follow-up, not a claimed control.

---

## 11. Operational notes

* **Queues:** `scans.public` (renamed from `scans`) and `scans.private.<site-id>`. The
  *default* route is the public queue — the least-authority destination — so a dispatch
  that lost its routing information cannot land on a private site's queue. Every requeue
  path (DLQ replay, queued-relay, shutdown requeue) re-derives the queue from the scan row.
  Note that the isolated execution worker does **not** consume these queues (it cannot
  reach the broker); it leases from the manager, which only ever hands it jobs for its own
  site. Isolation no longer depends on a worker being pointed at the right queue name.
* **Worker entrypoint:** `python -m apps.api.scanner_worker.main`, not `celery worker`.
  It refuses to start without a complete identity (`SCANNER_WORKER_ID`, `SCANNER_POOL_ID`,
  `SCANNER_MANAGER_URL`, `SCANNER_WORKER_TOKEN`) — a worker that cannot say who it is
  cannot be authorized for anything, and guessing would be the wrong failure mode.
* **Revocation** is enforced control-plane side and destroys the stored credential, so it
  works without reaching a compromised or offline scanner host.
* **Emergency disable:** `private_scanning_emergency_disable` stops all private leasing at
  the manager.
* **Metrics** carry no workspace, site or worker identifier — a tenant's site count and
  internal addressing are customer data. Per-tenant detail lives in access-controlled logs.
