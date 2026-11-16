#!/usr/bin/env python3
"""
Unit tests for the scalability & hardening fixes:
  - Cache TTL expiry (blocked entries re-probe; no permanent tunnel pinning)
  - Direct-cache persistence across restarts
  - Upstream URL parsing (socks5/http/direct) + HTTP CONNECT upstream tunnel
  - REST API: foreign-host /_smart/ URLs are NOT hijacked
  - REST API: web origins rejected on mutating endpoints; extension origins OK
  - REST API: optional X-Smart-Token enforcement
  - Empty-host CONNECT guard (never probe/cache empty hosts)
  - Plain HTTP: chunked request body decoding
"""

import asyncio
import base64
import importlib.util
import json
import os
import socket
import struct
import tempfile
import time
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PROXY_SRC_PATH = Path(__file__).resolve().parent.parent.parent / "src" / "smart-proxy.py"
spec = importlib.util.spec_from_file_location("smart_proxy", str(PROXY_SRC_PATH))
proxy_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proxy_mod)

CacheManager = proxy_mod.CacheManager
SmartProxyDaemon = proxy_mod.SmartProxyDaemon
parse_upstream_url = proxy_mod.parse_upstream_url
HttpProxyTunnel = proxy_mod.HttpProxyTunnel
SOCKS5Error = proxy_mod.is_fortinet_cert.__globals__["SOCKS5Error"]


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestUpstreamParsing(unittest.TestCase):
    def test_socks5_url(self):
        cfg = parse_upstream_url("socks5://127.0.0.1:1088")
        self.assertEqual(cfg["type"], "socks5")
        self.assertEqual(cfg["port"], 1088)

    def test_http_url_with_auth(self):
        cfg = parse_upstream_url("http://club:secret@192.168.77.84:3128")
        self.assertEqual(cfg["type"], "http")
        self.assertEqual(cfg["host"], "192.168.77.84")
        self.assertEqual(cfg["port"], 3128)
        self.assertEqual(cfg["username"], "club")
        self.assertEqual(cfg["password"], "secret")

    def test_direct(self):
        cfg = parse_upstream_url("direct")
        self.assertEqual(cfg["type"], "direct")

    def test_legacy_args(self):
        cfg = parse_upstream_url(None, "127.0.0.1", 19999)
        self.assertEqual(cfg["type"], "socks5")
        self.assertEqual(cfg["port"], 19999)

    def test_invalid_scheme(self):
        with self.assertRaises(ValueError):
            parse_upstream_url("ftp://example.com")


class TestCacheTTL(unittest.TestCase):
    def _cm(self, tmp: str) -> CacheManager:
        return CacheManager(os.path.join(tmp, "blocked.json"), block_ttl_hours=0.02)  # ~72s

    def test_blocked_entry_expires(self):
        tmp = tempfile.mkdtemp()
        cm = self._cm(tmp)
        cm.mark_blocked("expired.test", "etimedout", 100)
        self.assertEqual(cm.get_route("expired.test"), "TUNNEL")

        # Backdate the entry beyond its TTL
        cm.blocked_domains["expired.test"]["last_seen"] = "2020-01-01T00:00:00Z"
        self.assertIsNone(cm.get_route("expired.test"))
        self.assertNotIn("expired.test", cm.blocked_domains)

    def test_high_confidence_reasons_expire_too(self):
        tmp = tempfile.mkdtemp()
        cm = self._cm(tmp)
        cm.mark_blocked("mitm.test", "fortinet_mitm", 100)
        self.assertEqual(cm.get_route("mitm.test"), "TUNNEL")
        cm.blocked_domains["mitm.test"]["last_seen"] = "2020-01-01T00:00:00Z"
        self.assertIsNone(cm.get_route("mitm.test"))

    def test_direct_cache_persists(self):
        tmp1 = tempfile.mkdtemp()
        path = os.path.join(tmp1, "blocked.json")
        cm1 = CacheManager(path)
        cm1.mark_direct("persist.test")
        # Flush the debounced write
        cm1.flush()
        self.assertTrue(cm1._dirty is False or os.path.exists(path))

        cm2 = CacheManager(path)
        self.assertIn("persist.test", cm2.direct_domains)
        self.assertEqual(cm2.get_route("persist.test"), "DIRECT")

    def test_empty_host_never_routed_to_probe(self):
        tmp = tempfile.mkdtemp()
        cm = self._cm(tmp)
        self.assertEqual(cm.get_route(""), "DIRECT")
        cm.mark_blocked("", "dns_failure")  # must be rejected
        self.assertNotIn("", cm.blocked_domains)


class _UpstreamEchoHandler(BaseHTTPRequestHandler):
    """HTTP proxy that accepts CONNECT and echoes a banner after tunneling."""

    def do_CONNECT(self):
        self.send_response(200)
        self.end_headers()
        # Tunnel: echo a line for the client
        try:
            self.connection.sendall(b"TUNNELED-OK\n")
            data = self.connection.recv(1024)
            if data:
                self.connection.sendall(data)
        except OSError:
            pass
        self.connection.close()

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"plain")

    def log_message(self, *a):
        pass


class TestHttpUpstreamTunnel(unittest.IsolatedAsyncioTestCase):
    async def test_http_connect_tunnel_with_auth(self):
        port = _free_port()
        server = ThreadingHTTPServer(("127.0.0.1", port), _UpstreamEchoHandler)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            tunnel = HttpProxyTunnel("127.0.0.1", port, username="club", password="secret")
            reader, writer = await tunnel.connect("store.steampowered.com", 443, timeout=3.0)
            banner = await asyncio.wait_for(reader.readline(), timeout=2.0)
            self.assertEqual(banner.strip(), b"TUNNELED-OK")
            writer.write(b"ping")
            await writer.drain()
            echo = await asyncio.wait_for(reader.readline(), timeout=2.0)
            self.assertEqual(echo.strip(), b"ping")
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        finally:
            server.shutdown()

    async def test_http_connect_offline_raises_offline(self):
        tunnel = HttpProxyTunnel("127.0.0.1", 1)  # nothing listens on port 1
        with self.assertRaises(SOCKS5Error) as ctx:
            await tunnel.connect("example.com", 443, timeout=2.0)
        self.assertTrue(ctx.exception.is_offline)


class TestApiHardening(unittest.IsolatedAsyncioTestCase):
    async def _daemon(self):
        d = SmartProxyDaemon(host="127.0.0.1", port=0, socks5_host="127.0.0.1",
                             socks5_port=_free_port(), config_dir=tempfile.mkdtemp())
        await d.start()
        port = d.server.sockets[0].getsockname()[1]
        return d, port

    @staticmethod
    async def _request(port: int, method: str, path: str, body: bytes = b"",
                       headers: dict = None) -> tuple:
        r, w = await asyncio.open_connection("127.0.0.1", port)
        hdrs = {"Host": f"127.0.0.1:{port}", "Connection": "close"}
        if body:
            hdrs["Content-Length"] = str(len(body))
        if headers:
            hdrs.update(headers)
        lines = [f"{method} {path} HTTP/1.1"] + [f"{k}: {v}" for k, v in hdrs.items()]
        w.write("\r\n".join(lines).encode() + b"\r\n\r\n" + body)
        await w.drain()
        resp = await r.read()
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass
        head, _, rbody = resp.partition(b"\r\n\r\n")
        status = int(head.split(b"\r\n")[0].split()[1])
        return status, rbody

    async def test_foreign_smart_url_not_hijacked(self):
        d, port = await self._daemon()
        try:
            # External site URL containing /_smart/ must be PROXIED, not intercepted.
            # Browsers send the TARGET's host header for absolute-form requests.
            r, w = await asyncio.open_connection("127.0.0.1", port)
            w.write(b"GET http://evil.example.com/_smart/status HTTP/1.1\r\n"
                    b"Host: evil.example.com\r\nConnection: close\r\n\r\n")
            await w.drain()
            resp = await asyncio.wait_for(r.read(), timeout=4.0)
            w.close()
            head = resp.partition(b"\r\n\r\n")[0].split(b"\r\n")[0]
            # Either a proxy error (5xx/4xx) or an upstream attempt — never the API's 200
            self.assertNotIn(b" 200 ", head)
        finally:
            await d.stop()

    async def test_web_origin_rejected_on_mutation(self):
        d, port = await self._daemon()
        try:
            status, body = await self._request(
                port, "POST", "/_smart/override",
                body=json.dumps({"domain": "x.com", "action": "tunnel"}).encode(),
                headers={"Origin": "https://evil.example.com", "Content-Type": "application/json"},
            )
            self.assertEqual(status, 403)
            # And nothing was overridden
            self.assertNotIn("x.com", d.cache_mgr.custom_overrides)
        finally:
            await d.stop()

    async def test_extension_origin_allowed_on_mutation(self):
        d, port = await self._daemon()
        try:
            status, body = await self._request(
                port, "POST", "/_smart/override",
                body=json.dumps({"domain": "ok.com", "action": "tunnel"}).encode(),
                headers={"Origin": "chrome-extension://abcdefg", "Content-Type": "application/json"},
            )
            self.assertEqual(status, 200)
            self.assertEqual(d.cache_mgr.custom_overrides.get("ok.com"), "tunnel")
        finally:
            await d.stop()

    async def test_token_enforced_when_configured(self):
        d, port = await self._daemon()
        d.api_token = "sekrit"
        try:
            # Missing token -> 403
            status, _ = await self._request(
                port, "POST", "/_smart/override",
                body=json.dumps({"domain": "a.com", "action": "tunnel"}).encode())
            self.assertEqual(status, 403)
            # With token -> 200
            status, _ = await self._request(
                port, "POST", "/_smart/override",
                body=json.dumps({"domain": "a.com", "action": "tunnel"}).encode(),
                headers={"X-Smart-Token": "sekrit"})
            self.assertEqual(status, 200)
        finally:
            await d.stop()


class TestConnectGuards(unittest.IsolatedAsyncioTestCase):
    async def test_empty_connect_target_rejected(self):
        d = SmartProxyDaemon(host="127.0.0.1", port=0, socks5_host="127.0.0.1",
                             socks5_port=_free_port(), config_dir=tempfile.mkdtemp())
        await d.start()
        port = d.server.sockets[0].getsockname()[1]
        try:
            r, w = await asyncio.open_connection("127.0.0.1", port)
            w.write(b"CONNECT :443 HTTP/1.1\r\n\r\n")
            await w.drain()
            resp = await asyncio.wait_for(r.read(), timeout=3.0)
            self.assertTrue(resp.startswith(b"HTTP/1.1 400"), resp[:40])
            w.close()
        finally:
            await d.stop()
            # Nothing must have been cached
            self.assertEqual(len(d.cache_mgr.blocked_domains), 0)


class TestChunkedRequestBody(unittest.IsolatedAsyncioTestCase):
    async def test_chunked_body_forwarded(self):
        target_port = _free_port()
        received = {}

        class Target(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0") or 0)
                received["body"] = self.rfile.read(length)
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *a):
                pass

        target = ThreadingHTTPServer(("127.0.0.1", target_port), Target)
        threading.Thread(target=target.serve_forever, daemon=True).start()

        d = SmartProxyDaemon(host="127.0.0.1", port=0, socks5_host="127.0.0.1",
                             socks5_port=_free_port(), config_dir=tempfile.mkdtemp())
        await d.start()
        proxy_port = d.server.sockets[0].getsockname()[1]
        try:
            chunk = b"hello chunked world"
            body = (hex(len(chunk))[2:].encode() + b"\r\n" + chunk +
                    b"\r\n0\r\n\r\n")
            r, w = await asyncio.open_connection("127.0.0.1", proxy_port)
            req = (f"POST http://127.0.0.1:{target_port}/submit HTTP/1.1\r\n"
                   f"Host: 127.0.0.1:{target_port}\r\n"
                   f"Transfer-Encoding: chunked\r\n"
                   f"Content-Type: text/plain\r\n\r\n").encode() + body
            w.write(req)
            await w.drain()
            resp = await asyncio.wait_for(r.read(), timeout=4.0)
            w.close()
            self.assertIn(b"200", resp.split(b"\r\n")[0])
            self.assertEqual(received.get("body"), chunk)
        finally:
            await d.stop()
            target.shutdown()


if __name__ == "__main__":
    unittest.main()
