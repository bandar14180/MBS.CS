# Dedicated VPN Egress (public scanner traffic)

```
Public VPN Scanner  ->  Dedicated VPN/WireGuard Egress  ->  Internet Target
Private Site Worker ->  Existing Per-Site WireGuard     ->  Private Target      (unchanged)
```

A platform-wide **shared** VPN exit for public scans. One pool, one tunnel, no tenant state.

## Why this is a second tunnel and not a flag on the first

The two tunnels are opposites, which is why they are separate modules, separate workers and
separate networks.

| | Private site (`scanner_engine/wireguard.py`) | VPN egress (`scanner_engine/vpn_egress.py`) |
|---|---|---|
| Shape | **Split** tunnel | **Full** tunnel |
| AllowedIPs | exactly the site's authorized CIDRs | `0.0.0.0/0` |
| `0.0.0.0/0` | **refused by construction** | required |
| Interface | `wg0` | `wg-egress` |
| Default route | never | in a **dedicated table only** |
| Scope | one customer's network | the public Internet |

Sharing one code path and distinguishing with a flag was rejected: the flag would have to be
threaded through `build_allowed_ips`, and one bad call site would then re-open the *private*
path to a default route. Keeping them disjoint lets the private refusal stay unconditional.
`test_the_two_tunnel_modules_do_not_share_an_allowed_ips_builder` enforces this by AST.

## What makes a full tunnel safe here

1. **The default route is not in the main table.** It lives in table `51820`, selected by an
   `ip rule`. The main table is never modified, so manager/dispatch traffic keeps its
   ordinary path. `assert_main_table_untouched` re-verifies this independently after
   bring-up, and the worker refuses to start if the main default ever points at the tunnel.
2. **The worker holds no site state.** No `site_id`, no site secret, not on any
   `mbs-site-*` network. The manager refuses it every private job
   (`assert_worker_may_serve_site`), so the full tunnel cannot become a path into a
   customer network. Config validation refuses `SCANNER_EGRESS_MODE=vpn` combined with
   `SCANNER_SITE_ID` outright.
3. **`net_policy` is unchanged.** These scans still bind PUBLIC-ONLY, so `net_guard` and
   `egress_guard` refuse every private destination exactly as before. The VPN changes
   *which public IP* traffic leaves from — never *what may be reached*.

## Routing

Three rules, in priority order:

| Priority | Rule | Why |
|---|---|---|
| 9000 | `not fwmark 0x51820 lookup main` | WireGuard marks its **own** encrypted packets; without this the tunnel's transport is routed into the tunnel — the classic full-tunnel loop |
| 9100 | `lookup main suppress_prefixlength 0` | anything with a **more specific** route in main (on-link bridges: dispatch, loopback) keeps its ordinary path |
| 9200 | `lookup 51820` | the catch-all: traffic needing a *default* route — i.e. every Internet target — enters the tunnel |

## The kill-switch is a firewall, not a Python check

`egress_guard` is in-process and **cannot** intercept nuclei/katana/ffuf sockets — they do
their own socket work in another process. So fail-closed is enforced by iptables in the
`MBS_VPN_EGRESS` chain on `OUTPUT`:

```
-m conntrack --ctstate ESTABLISHED,RELATED   ACCEPT
-o lo                                       ACCEPT
-o wg-egress                                ACCEPT   <- the ONLY path to a target
-p udp -d <endpoint>/32 --dport <port>      ACCEPT
-d <dispatch cidr>                          ACCEPT   <- the manager, narrowly
                                            DROP     <- everything else
```

When the tunnel drops, `-o wg-egress` stops matching and target traffic is dropped **by the
kernel**. The rules are installed **before** the tunnel comes up, so the startup window is
closed rather than open (`test_killswitch_is_installed_before_the_tunnel_comes_up`).

DNS is deliberately **not** special-cased: target resolution traverses the tunnel like
everything else, so a leak cannot reveal the platform's address to the target's
authoritative server.

## Exit-IP verification

Interface-up plus a fresh handshake proves the **tunnel** lives. It does **not** prove
traffic **uses** it — a flushed table or a missing `ip rule` leaves a perfectly healthy
tunnel beside traffic still going out the host address. So health here means the *observed*
egress address is the VPN's:

- unknown exit IP → refuse (`VPN_EGRESS_EXIT_IP_UNKNOWN`)
- stale observation → refuse (`VPN_EGRESS_EXIT_IP_STALE`)
- ≠ pinned exit IP → refuse (`VPN_EGRESS_EXIT_IP_MISMATCH`)
- = a known platform address → refuse (positive proof of bypass)

A failed observation **invalidates** the cache; a stale-but-successful reading is exactly
what would hide a drop.

## Three gates, not one

| When | Gate | On failure |
|---|---|---|
| Startup | `egress_setup.setup_and_verify` | process refuses to start (exit 2) |
| Per job | `lease_loop.preflight_egress_job` | job rejected, scan handed back `failed` |
| Mid-scan | `lease_loop._watch_egress_while_running` | **scan cancelled** |

The mid-scan watchdog is the one that is *not* best-effort, unlike the heartbeat beside it.
A missed heartbeat costs liveness reporting; a missed egress check costs the guarantee the
scan is sold on. Unknown is never "fine" — an unreadable probe fails the scan.

## Lease authorization (no migration)

Egress mode is derived from the worker's **persisted `pool_id`** (`VPN_EGRESS_POOLS`), not a
new column. `pool_id` is already persisted, operator-controlled, non-nullable and enforced
at every authorization boundary, so it already has the properties an egress-mode column
would need — and a parallel column would be a second source of truth that could disagree.

A scan declares `config.required_egress_mode`. `assert_worker_egress_mode` refuses a
mismatch **before** the atomic claim, so a vpn-required scan stays `queued` for a VPN worker
rather than being claimed and failed. The worker independently re-checks the same rule
against its own `SCANNER_EGRESS_MODE`, because "it was handed to me" is not "it is
authorized for me". Both directions fail closed; a scan with no requirement runs anywhere
(unchanged behaviour for every pre-existing scan).

## Metrics

`mbs_vpn_egress_up`, `mbs_vpn_egress_handshake_age_seconds`,
`mbs_vpn_egress_exit_ip_verified`, `mbs_vpn_egress_blocked_total`,
`mbs_vpn_egress_midscan_loss_total` — all separate from `mbs_tunnel_up`, so neither alert
dilutes the other. `MbsVpnEgressExitIpUnverified` is the **critical** one: a tunnel that is
up while traffic bypasses it means the routing or the kill-switch was altered.
