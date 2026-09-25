"""Container liveness probe for the API image (Dockerfile.api HEALTHCHECK).

WHY THIS FILE EXISTS -- THE DEFECT IT CLOSES
--------------------------------------------
The healthcheck used to be a one-liner:

    python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen(
        'http://localhost:8000/health').status==200 else 1)"

`urlopen('http://localhost:8000/...')` sends `Host: localhost:8000`.
`TrustedHostMiddleware` is the OUTERMOST middleware (apps/api/main.py), and production MUST
declare explicit hostnames -- `validate_production()` refuses to start with
`TRUSTED_HOSTS=["*"]`. So under a production `TRUSTED_HOSTS` of `["mbs.example.com"]` the
middleware rejected the probe with **400 "Invalid host header" BEFORE the route ran**, the
`status == 200` test failed, and Docker marked a perfectly healthy API `unhealthy`.

Measured against a production-shaped `allowed_hosts=["mbs.example.com"]`:

    Host: localhost:8000    -> 400 Invalid host header
    Host: 127.0.0.1:8000    -> 400 Invalid host header
    Host: api:8000          -> 400 Invalid host header
    Host: mbs.example.com   -> 200 {"status":"ok"}

That is a real deployment defect, not cosmetics: `depends_on: service_healthy` gates and
orchestrator restart policies act on the container's health status.

WHAT THIS DOES -- AND WHAT IT DELIBERATELY DOES NOT DO
------------------------------------------------------
It does NOT bypass or weaken TrustedHost. The request still traverses the FULL middleware
stack, TrustedHost included; it simply presents a Host the policy actually allows, taken from
the SAME `TRUSTED_HOSTS` value the application itself is configured with. Deriving the host
(instead of hardcoding one) means the probe cannot drift from the policy: change
`TRUSTED_HOSTS` and the probe follows automatically.

ENDPOINT CHOICE: /health, NOT /ready
------------------------------------
Docker's HEALTHCHECK drives restart and `service_healthy` semantics -- that is LIVENESS
("is this process still serving?"). `/health` is defined as exactly that: "Liveness: the
process is up. No dependency checks (never fails on a DB blip)."

`/ready` is READINESS and returns 503 when MySQL / schema / Redis are unavailable. Wiring that
into HEALTHCHECK would let a transient database blip restart an otherwise-fine API container,
escalating a dependency outage into an application outage. `/ready` stays the correct probe for
a load balancer or a Kubernetes readinessProbe -- a different question, deliberately answered
by a different endpoint.

PROPERTIES REQUIRED OF A CONTAINER PROBE
----------------------------------------
* No external service and no DNS: connects to 127.0.0.1 inside the container.
* Deterministic: no retries of its own (Docker's `--retries` owns that), bounded timeout.
* Fails loudly: any non-200, connection error, or timeout exits non-zero.
* Stdlib only: the runtime image ships no curl/wget.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

URL = "http://127.0.0.1:8000/health"
TIMEOUT_S = 4  # < the HEALTHCHECK --timeout=5s, so we fail before Docker kills us


def probe_host(raw: str | None) -> str:
    """The Host header to present, derived from the app's own TRUSTED_HOSTS.

    Accepts every form the setting realistically takes:
      '["mbs.example.com"]'              -> mbs.example.com   (JSON list, as compose sets it)
      '["a.example.com","b.example.com"]'-> a.example.com     (first entry is representative)
      'mbs.example.com'                  -> mbs.example.com   (bare string)
      'a.example.com,b.example.com'      -> a.example.com     (comma-separated)
      '["*"]' / '*' / '' / unset         -> localhost         (dev: the wildcard accepts it)

    A wildcard or empty value means the middleware is not restricting hosts, so `localhost` is
    accepted and the dev stack behaves exactly as it did before this file existed.
    """
    raw = (raw or "").strip()
    if not raw:
        return "localhost"

    host = ""
    if raw.startswith("["):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, list) and parsed:
                host = str(parsed[0]).strip()
        except (ValueError, TypeError):
            host = ""  # malformed JSON -> fall through to the plain-text parse below
    if not host:
        host = raw.split(",")[0].strip().strip("[]\"' ")

    return host if host and host != "*" else "localhost"


def main() -> int:
    host = probe_host(os.environ.get("TRUSTED_HOSTS"))
    request = urllib.request.Request(URL, headers={"Host": host})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_S) as response:
            if response.status == 200:
                return 0
            print(f"healthcheck: {URL} returned {response.status} (Host: {host})", file=sys.stderr)
            return 1
    except urllib.error.HTTPError as exc:
        # A 400 here almost certainly means TRUSTED_HOSTS and this probe disagree -- say so,
        # because that is precisely the failure this file was written to eliminate.
        hint = " -- Host rejected by TrustedHostMiddleware?" if exc.code == 400 else ""
        print(f"healthcheck: HTTP {exc.code} (Host: {host}){hint}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 -- any failure to reach the app means "unhealthy"
        print(f"healthcheck: {type(exc).__name__}: {exc} (Host: {host})", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
