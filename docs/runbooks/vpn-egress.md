# Runbook — Dedicated VPN Egress

Architecture: [`docs/architecture/vpn-egress.md`](../architecture/vpn-egress.md).

## Provision

1. **Get a WireGuard peer from the provider.** Generate the private key **inside the
   container** — it must never exist anywhere else:
   ```sh
   docker compose exec worker-vpn-egress sh -c \
     'umask 077; wg genkey | tee /run/wireguard/private.key | wg pubkey'
   ```
   Send **only** the printed public key to the provider. Put the private half in
   `infra/secrets/vpn_egress_private_key.txt` (mode 0600, owned by uid 10001).

2. **Register the worker**: a `scanner_workers` row with `site_id` NULL and
   `pool_id = public-vpn-egress`. Token → `infra/secrets/scanner_worker_token_vpn_egress.txt`.

3. **Find the dispatch subnet** — the kill-switch denies by default, so this must be right
   or the worker cannot reach its manager:
   ```sh
   docker network inspect infra_mbs-dispatch -f '{{(index .IPAM.Config 0).Subnet}}'
   ```
   → `SCANNER_VPN_EGRESS_DISPATCH_CIDRS`.

4. **Record the platform's own egress IP** → `SCANNER_VPN_EGRESS_FORBIDDEN_EXIT_IPS`.
   Observing it as the exit IP is positive proof of a bypass. Set this **even if** you
   leave `EXPECTED_EXIT_IP` empty — it is what makes the unpinned case meaningful:
   ```sh
   docker compose exec worker curl -s https://api.ipify.org
   ```

5. **Replace the four `REPLACE_WITH_*` values** in `infra/docker-compose.vpn-egress.yml`.

6. Bring it up:
   ```sh
   docker compose -f infra/docker-compose.yml -f infra/docker-compose.prod.yml \
                  -f infra/docker-compose.vpn-egress.yml up -d worker-vpn-egress
   ```

## Verify (run all six)

```sh
C=worker-vpn-egress

# 1. Worker says it is ready, and prints its exit IP.
docker compose logs $C | grep vpn_egress_ready

# 2. The tunnel is up with a recent handshake.
docker compose exec $C wg show wg-egress

# 3. The default route is in the DEDICATED table -- and NOT in main.
docker compose exec $C ip route show table 51820      # expect: default dev wg-egress
docker compose exec $C ip route show table main       # must NOT mention wg-egress
docker compose exec $C ip rule show                   # expect 9000/9100/9200

# 4. The kill-switch is present and ends in DROP.
docker compose exec $C iptables -S MBS_VPN_EGRESS
docker compose exec $C iptables -S OUTPUT | grep MBS_VPN_EGRESS

# 5. THE ONE THAT MATTERS: the observed exit IP is the VPN's, not ours.
docker compose exec $C curl -s https://api.ipify.org; echo
docker compose exec worker curl -s https://api.ipify.org; echo   # the direct worker
# These two MUST differ. If they match, target traffic is not on the VPN.

# 6. The manager is still reachable (control plane not captured by the VPN).
docker compose exec $C curl -sf http://scanner-manager:8100/health
```

## Prove it fails closed

Take the tunnel down and confirm targets become unreachable while the manager does not:

```sh
docker compose exec $C ip link set wg-egress down
docker compose exec $C curl -s --max-time 5 https://api.ipify.org   # MUST fail/timeout
docker compose exec $C curl -sf http://scanner-manager:8100/health  # MUST still succeed
docker compose exec $C ip link set wg-egress up
```

If the first `curl` **succeeds**, the kill-switch is not working — treat it as an incident
and stop the worker. That is the silent-leak condition this feature exists to prevent.

## Symptoms → cause

| Log / alert | Meaning | Fix |
|---|---|---|
| `VPN_EGRESS_EXIT_IP_MISMATCH` | tunnel up, traffic **not** on it | check `ip rule`, table 51820, the iptables chain |
| `VPN_EGRESS_EXIT_IP_UNKNOWN` | exit IP unobservable | provider down, or the check URL is blocked |
| `VPN_EGRESS_KILLSWITCH_MISSING` | chain absent/unhooked | `iptables` missing, or CAP_NET_ADMIN not granted |
| `VPN_EGRESS_LEAK` | main table's default **is** the tunnel | control-plane traffic would be in the VPN — restart; investigate who added it |
| `VPN_EGRESS_LOST_MIDSCAN` | tunnel died during a scan | scan was cancelled deliberately; fix tunnel stability |
| `WORKER_EGRESS_MODE_MISMATCH` | vpn-required scan, direct worker | worker's `pool_id` is not in `VPN_EGRESS_POOLS` |
| exits 2 at startup | config/secret gap | the message names the missing variable |

`MbsVpnEgressExitIpUnverified` is **critical**: a tunnel that is up while traffic bypasses
it means routing or the firewall was altered. Scans are refused fail-closed meanwhile.

## Routing a scan through the VPN

Set `required_egress_mode: "vpn"` in the scan's config. The manager will only lease it to a
worker whose persisted `pool_id` is in `VPN_EGRESS_POOLS`; a direct worker skips the row and
it stays `queued`. Scans with no requirement run anywhere, unchanged.

## Rotating the provider key

```sh
docker compose exec worker-vpn-egress sh -c \
  'umask 077; wg genkey | tee /run/wireguard/private.key | wg pubkey'   # new public half -> provider
# update infra/secrets/vpn_egress_private_key.txt, then:
docker compose up -d --force-recreate worker-vpn-egress
```
Startup verification re-runs, so a bad rotation fails to start rather than scanning direct.

## Do not

- Put the provider key in `.env.scanner` — shared with **tenant** site workers.
- Add `SCANNER_SITE_ID` to this worker — config validation refuses it; the roles are
  mutually exclusive.
- Widen `SCANNER_VPN_EGRESS_DISPATCH_CIDRS` to `10.0.0.0/8` — that re-opens private-range
  reachability the egress worker must not have. A `/0` is refused outright.
- Attach this worker to `mbs-core` or any `mbs-site-*` network.
