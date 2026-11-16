#!/usr/bin/env python3
"""
CRISPR Smart Tunnel — shared blocked-domain crowd-list service.

A tiny, dependency-free (Python stdlib only) HTTP service for the club server
(192.168.77.84). Members' smart-proxy daemons and AuthBahn extensions:

  GET  /smart/list    -> {"blocked_domains": {domain: {reason, last_seen}}}
  POST /smart/report  -> body {"domain": "...", "reason": "..."}  (merge, dedup)

Safety:
  - Only campus subnets may read/report.
  - Per-IP token bucket (default 30 requests/min) blocks abuse.
  - Domain names are validated strictly; list is capped (default 10000).
  - State is persisted atomically to /var/lib/smart-tunnel/shared_list.json.

Install: see deploy/server-setup.md (systemd unit provided).
"""

import ipaddress
import json
import os
import re
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

# ---------------------------------------------------------------- tuning ----
LISTEN_HOST = os.environ.get("SMART_LIST_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("SMART_LIST_PORT", "8081"))
STATE_FILE = os.environ.get("SMART_LIST_STATE", "/var/lib/smart-tunnel/shared_list.json")
MAX_DOMAINS = int(os.environ.get("SMART_LIST_MAX", "10000"))
RATE_LIMIT_PER_MIN = int(os.environ.get("SMART_LIST_RATE", "30"))
MAX_BODY = 4096

# Campus subnets allowed to read/report (mirror squid.conf)
ALLOWED_SRC = [ipaddress.ip_network(n) for n in (
    "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "127.0.0.0/8",
)]
# Destination guard for the proxy ports is in squid.conf; this service only
# stores labels — no fetching — so SSRF is not applicable here.

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")

_lock = threading.Lock()
_bucket: dict = {}  # ip -> [tokens, last_refill]


def _state_dir() -> str:
    return os.path.dirname(STATE_FILE)


def load_state() -> dict:
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data.get("blocked_domains"), dict):
            raise ValueError("bad shape")
        return data
    except Exception:
        return {"version": 1, "blocked_domains": {}}


def save_state(data: dict) -> None:
    os.makedirs(_state_dir(), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=_state_dir(), prefix="shared_", suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, STATE_FILE)


def rate_ok(ip: str) -> bool:
    now = time.time()
    with _lock:
        tokens, last = _bucket.get(ip, [float(RATE_LIMIT_PER_MIN), now])
        tokens = min(RATE_LIMIT_PER_MIN, tokens + (now - last) / 60.0 * RATE_LIMIT_PER_MIN)
        if tokens < 1:
            _bucket[ip] = [tokens, now]
            return False
        tokens -= 1
        _bucket[ip] = [tokens, now]
        return True


def src_allowed(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in ALLOWED_SRC)


class Handler(BaseHTTPRequestHandler):
    server_version = "SmartList/1.0"

    def log_message(self, fmt, *args):  # quiet default logging
        pass

    def _client_ip(self) -> str:
        return self.client_address[0]

    def _send(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        ip = self._client_ip()
        if not src_allowed(ip):
            self._send(403, {"error": "forbidden"})
            return
        if not rate_ok(ip):
            self._send(429, {"error": "rate limited"})
            return
        path = urlsplit(self.path).path
        if path == "/smart/list" or path == "/smart/list/":
            with _lock:
                data = load_state()
            self._send(200, {"blocked_domains": data.get("blocked_domains", {})})
            return
        if path == "/health":
            self._send(200, {"status": "ok"})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self):
        ip = self._client_ip()
        if not src_allowed(ip):
            self._send(403, {"error": "forbidden"})
            return
        if not rate_ok(ip):
            self._send(429, {"error": "rate limited"})
            return
        path = urlsplit(self.path).path
        if path != "/smart/report":
            self._send(404, {"error": "not found"})
            return
        try:
            length = min(int(self.headers.get("Content-Length", "0") or 0), MAX_BODY)
            body = self.rfile.read(length) if length > 0 else b"{}"
            data = json.loads(body.decode("utf-8"))
        except Exception:
            self._send(400, {"error": "invalid json"})
            return

        domain = str(data.get("domain", "")).strip().lower().rstrip(".")
        reason = str(data.get("reason", "reported"))[:64]
        if not domain or len(domain) > 253 or not DOMAIN_RE.match(domain):
            self._send(400, {"error": "invalid domain"})
            return

        with _lock:
            state = load_state()
            domains = state.setdefault("blocked_domains", {})
            now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            entry = domains.get(domain)
            if entry is None and len(domains) >= MAX_DOMAINS:
                self._send(409, {"error": "list full"})
                return
            if entry is None:
                domains[domain] = {"reason": reason, "first_seen": now, "last_seen": now, "reports": 1}
            else:
                entry["last_seen"] = now
                entry["reports"] = int(entry.get("reports", 1)) + 1
                if reason and reason != "manual_override":
                    entry["reason"] = reason
            save_state(state)
            total = len(domains)
        self._send(200, {"status": "ok", "domain": domain, "total": total})


def main() -> None:
    os.makedirs(_state_dir(), exist_ok=True)
    server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    server.daemon_threads = True
    print(f"Smart-list service listening on {LISTEN_HOST}:{LISTEN_PORT} (state: {STATE_FILE})")
    server.serve_forever()


if __name__ == "__main__":
    main()
