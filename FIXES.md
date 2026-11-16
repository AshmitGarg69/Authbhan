# Smart Tunnel — Hardening & Scalability Fixes (Nov 16, 2026)

All 293 E2E tests + 58 unit tests + 19 adversarial tests pass.

## What was broken and what changed

### Root cause of "works only for me"
The system required each member to hold your SSH key. Now the daemon supports a
**shared HTTP escape-hatch** (`http://192.168.77.84:3128`, hardened Squid on the
club server) in addition to SSH SOCKS5 — no keys, no accounts, campus-only ACLs,
per-IP bandwidth/connection caps. See `deploy/server-setup.md`.

### Daemon (`src/smart-proxy.py`)
1. **Upstream abstraction** — `--upstream socks5://… | http://user:pass@host:3128 | direct`
   (config.env `UPSTREAM_PROXY`). Mates use the server proxy; you keep SSH mode.
2. **Cache TTLs** — blocked entries auto-expire (default 24h, `BLOCK_TTL_HOURS`);
   one transient Wi-Fi hiccup no longer pins a domain to your server forever.
3. **Direct cache persisted** (`direct_domains` in blocked.json) — no re-probe
   storm after every restart. Debounced flushes (no fsync per request).
4. **API hijack fix** — only requests addressed to the proxy itself are
   intercepted; external URLs containing `/_smart/` are proxied normally.
5. **Drive-by abuse guard** — mutating endpoints (`/_smart/override`,
   `/_smart/cache/clear`) reject web-page origins; optional shared token via
   `API_TOKEN` (header `X-Smart-Token`).
6. **Dead-tunnel failover** — domains cached for *transient* reasons
   (timeout/reset/DNS) fall back to direct when the tunnel is down; MITM/403
   detections stay strict (by design).
7. **Empty-host probe guard** — no more `""` entries in blocked.json
   (that bug was in your live cache; entry removed).
8. **Chunked request bodies** decoded with a 10 MB cap and correct
   Content-Length on the forwarded request.
9. Optional **crowd-list sync** — set `SYNC_URL=http://192.168.77.84:8081` and
   the daemon shares newly-discovered blocked domains with the club and pulls
   the shared list on start.

### CLI (`bin/smart-tunnel`)
1. **Real `test` command** — live 3-way matrix (direct / daemon / tunnel) with
   timings; known-blocked hints come from the club list, clearly labeled.
2. **SSH `-o PidFile` bug fixed** (client rejects that option → every fresh
   `start` failed). Real tunnel PID discovered via `ss`.
3. **No more fake ownership** — foreign port-1088 owners are reported, real
   ssh listeners adopted; orphan cleanup only ever kills genuine ssh tunnels.
4. **`unblock`** now removes the override (was leaving a stale "direct" entry).
5. **`install` refreshes** an outdated deployed daemon (was copy-once-forever).
6. **`--watchdog N`** — optional supervisor that restarts dead ssh/daemon.

### Extension (`AuthBahn/`, synced to the deployed copy)
1. **Firefox full-tunnel fixed** — `proxyDNS: true` (DNS was resolved locally,
   defeating the tunnel for blocked domains).
2. **Zero-Setup mode** — 4th mode; PAC-based routing of the shared blocked list
   through the club proxy. No daemon needed at all.
3. **Force Direct** button (parity with Force Tunnel).
4. Popup fallback stats bug fixed (`cache.blocked_domains_count`).
5. `content.js` null-guards (crashed on portal pages without the form).
6. Manifest: action icons, `192.168.77.84` host permission, version 1.2.

### Server (`deploy/`)
- `squid.conf` — campus-only ACLs, SSRF guard (no intranet pivots), per-IP
  maxconn + delay pools, optional single club token.
- `smart-list-service.py` + systemd unit — stdlib crowd-list service
  (rate-limited, campus-only, capped at 10k domains).
- `server-setup.md` — exact commands for the server, verification tests, and
  member onboarding (Option A: daemon; Option B: zero-setup browser-only).

## Test results
| Suite | Result |
|---|---|
| Unit (41 original + 17 new) | 58/58 |
| E2E Tier 1 (features) | 125/125 |
| E2E Tier 2 (boundaries) | 125/125 |
| E2E Tier 3 (combinations) | 28/28 (3 broken skip-tests repaired) |
| E2E Tier 4 (workloads) | 15/15 |
| Adversarial | 19/19 |

## To apply on your machine
```bash
smart-tunnel restart    # picks up the new daemon + CLI
```
Mates on campus: see `deploy/server-setup.md` §2.
