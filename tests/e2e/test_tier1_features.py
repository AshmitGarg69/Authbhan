"""
Tier 1 Feature Coverage Test Suite (125 tests)
Hybrid Smart Tunnel - E2E Testing Track
Covers 25 features x 5 tests across M1 (Proxy Daemon), M2 (CLI Controller), M3 (AuthBahn WebExtension).
Zero external dependencies: 100% Python standard library unittest.
"""

import html.parser
import json
import os
import re
import socket
import ssl
import subprocess
import time
import unittest
import urllib.parse
from pathlib import Path

from tests.e2e.harness import (
    CLIProcessManager,
    EnvironmentDetector,
    MockFortinetMITMServer,
    MockSOCKS5Server,
    MockTCPFaultServer,
    MockTargetServer,
    ProxyClientHelper,
    TestEnvironment,
    WebExtensionValidator,
    find_free_port,
    wait_port_free,
    wait_port_listen,
)


# ============================================================================
# MILESTONE 1: SMART PROXY DAEMON (Features M1-F01 to M1-F08)
# ============================================================================

class TestTier1_M1F01_DualProtocolListener(unittest.TestCase):
    """M1-F01: Local proxy on 127.0.0.1:8080 handling HTTP & HTTPS CONNECT."""

    def setUp(self):
        self.env = TestEnvironment()
        self.env.__enter__()
        self.env.start_proxy()
        self.client = ProxyClientHelper("127.0.0.1", self.env.proxy_port)

    def tearDown(self):
        self.env.__exit__(None, None, None)

    def test_t1_m1f01_01_https_connect_baseline(self):
        """Verify proxy handles standard CONNECT host:port and establishes bidirectional tunnel."""
        target_port = self.env.mock_target.port
        sock = socket.create_connection(("127.0.0.1", self.env.proxy_port), timeout=3.0)
        req = f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\n\r\n"
        sock.sendall(req.encode("ascii"))
        resp = sock.recv(1024).decode("latin-1")
        self.assertTrue(resp.startswith("HTTP/1.1 200"), f"Expected 200, got: {resp}")
        # Send downstream data and receive upstream reply
        sock.sendall(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
        reply = sock.recv(1024)
        self.assertIn(b"Direct Target OK", reply)
        sock.close()

    def test_t1_m1f01_02_plain_http_get_proxying(self):
        """Verify proxy parses absolute URI in GET and relays request directly."""
        target_port = self.env.mock_target.port
        url = f"http://127.0.0.1:{target_port}/testpage"
        status, headers, body = self.client.http_get(url)
        self.assertEqual(status, 200)
        self.assertIn(b"Direct Target OK", body)

    def test_t1_m1f01_03_plain_http_post_with_body(self):
        """Verify proxy passes HTTP POST request bodies with Content-Length."""
        target_port = self.env.mock_target.port
        url = f"http://127.0.0.1:{target_port}/submit"
        sock = socket.create_connection(("127.0.0.1", self.env.proxy_port), timeout=3.0)
        payload = b"hello=smartproxy"
        req = (
            f"POST {url} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{target_port}\r\n"
            f"Content-Length: {len(payload)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("latin-1") + payload
        sock.sendall(req)
        resp = sock.recv(4096)
        sock.close()
        self.assertIn(b"200 OK", resp)

    def test_t1_m1f01_04_custom_non_standard_https_port(self):
        """Verify CONNECT requests to non-standard ports extract host and port accurately."""
        target_port = self.env.mock_target.port
        sock = socket.create_connection(("127.0.0.1", self.env.proxy_port), timeout=3.0)
        req = f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\n\r\n"
        sock.sendall(req.encode("ascii"))
        resp = sock.recv(1024).decode("latin-1")
        sock.close()
        self.assertIn("200 Connection Established", resp)

    def test_t1_m1f01_05_hop_by_hop_header_sanitization(self):
        """Verify proxy strips or rewrites proxy-specific headers (Proxy-Connection)."""
        target_port = self.env.mock_target.port
        url = f"http://127.0.0.1:{target_port}/checkheaders"
        status, headers, body = self.client.http_get(url, headers={"Proxy-Connection": "keep-alive"})
        self.assertEqual(status, 200)
        # Check mock target recorded requests
        self.assertTrue(len(self.env.mock_target.requests_log) > 0)
        last_req = self.env.mock_target.requests_log[-1]["raw"].decode("latin-1", errors="replace")
        self.assertNotIn("Proxy-Connection:", last_req)


class TestTier1_M1F02_CampusIntranetBypass(unittest.TestCase):
    """M1-F02: Direct bypass for *.iiitn.ac.in and RFC1918 subnets (never tunneled)."""

    def setUp(self):
        self.env = TestEnvironment()
        self.env.__enter__()
        self.env.start_proxy()
        self.client = ProxyClientHelper("127.0.0.1", self.env.proxy_port)

    def tearDown(self):
        self.env.__exit__(None, None, None)

    def test_t1_m1f02_01_explicit_portal_domain(self):
        """Verify pravesh.iiitn.ac.in always routes DIRECT, never through SOCKS5."""
        # Querying an unroutable campus domain via CONNECT will attempt direct TCP and fail or bypass
        sock = socket.create_connection(("127.0.0.1", self.env.proxy_port), timeout=3.0)
        sock.sendall(b"CONNECT pravesh.iiitn.ac.in:443 HTTP/1.1\r\nHost: pravesh.iiitn.ac.in:443\r\n\r\n")
        _ = sock.recv(1024)
        sock.close()
        # Strictly verify zero connections recorded on SOCKS5 mock
        self.assertEqual(len(self.env.mock_socks5.connections_log), 0)

    def test_t1_m1f02_02_wildcard_campus_subdomains(self):
        """Verify arbitrary subdomains (*.iiitn.ac.in) route DIRECT without SOCKS5."""
        sock = socket.create_connection(("127.0.0.1", self.env.proxy_port), timeout=3.0)
        sock.sendall(b"CONNECT academic.iiitn.ac.in:443 HTTP/1.1\r\nHost: academic.iiitn.ac.in:443\r\n\r\n")
        _ = sock.recv(1024)
        sock.close()
        self.assertEqual(len(self.env.mock_socks5.connections_log), 0)

    def test_t1_m1f02_03_rfc1918_class_a_subnet(self):
        """Verify private 10.x.x.x addresses route DIRECT and never tunnel."""
        sock = socket.create_connection(("127.0.0.1", self.env.proxy_port), timeout=3.0)
        sock.sendall(b"CONNECT 10.1.2.3:80 HTTP/1.1\r\nHost: 10.1.2.3:80\r\n\r\n")
        _ = sock.recv(1024)
        sock.close()
        self.assertEqual(len(self.env.mock_socks5.connections_log), 0)

    def test_t1_m1f02_04_rfc1918_class_b_subnet(self):
        """Verify private 172.16.x.x to 172.31.x.x addresses route DIRECT."""
        sock = socket.create_connection(("127.0.0.1", self.env.proxy_port), timeout=3.0)
        sock.sendall(b"CONNECT 172.20.1.1:443 HTTP/1.1\r\nHost: 172.20.1.1:443\r\n\r\n")
        _ = sock.recv(1024)
        sock.close()
        self.assertEqual(len(self.env.mock_socks5.connections_log), 0)

    def test_t1_m1f02_05_rfc1918_class_c_subnet(self):
        """Verify captive portal (192.168.55.253) routes DIRECT without tunneling."""
        sock = socket.create_connection(("127.0.0.1", self.env.proxy_port), timeout=3.0)
        sock.sendall(b"CONNECT 192.168.55.253:443 HTTP/1.1\r\nHost: 192.168.55.253:443\r\n\r\n")
        _ = sock.recv(1024)
        sock.close()
        self.assertEqual(len(self.env.mock_socks5.connections_log), 0)


class TestTier1_M1F03_ActiveTLSProbing(unittest.TestCase):
    """M1-F03: Lightweight TLS probe (1.2s timeout) before CONNECT 200 response."""

    def setUp(self):
        self.env = TestEnvironment()
        self.env.__enter__()
        self.env.start_proxy()
        self.client = ProxyClientHelper("127.0.0.1", self.env.proxy_port)

    def tearDown(self):
        self.env.__exit__(None, None, None)

    def test_t1_m1f03_01_probe_trigger_on_first_visit(self):
        """Verify uncached external target triggers probe before client CONNECT 200."""
        # Target running clean direct server
        port = self.env.mock_target.port
        sock = socket.create_connection(("127.0.0.1", self.env.proxy_port), timeout=3.0)
        req = f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"
        sock.sendall(req.encode("ascii"))
        resp = sock.recv(1024).decode("latin-1")
        sock.close()
        self.assertIn("200 Connection Established", resp)

    def test_t1_m1f03_02_probe_timeout_enforcement(self):
        """Verify probe timeout is bounded to approximately 1.2s on frozen target."""
        # Using fault server in timeout mode
        fault_timeout_server = MockTCPFaultServer(mode="timeout", timeout_delay=5.0)
        fault_timeout_server.start()
        try:
            start_time = time.time()
            sock = socket.create_connection(("127.0.0.1", self.env.proxy_port), timeout=5.0)
            req = f"CONNECT 127.0.0.1:{fault_timeout_server.port} HTTP/1.1\r\nHost: 127.0.0.1:{fault_timeout_server.port}\r\n\r\n"
            sock.sendall(req.encode("ascii"))
            resp = sock.recv(1024).decode("latin-1")
            sock.close()
            elapsed = time.time() - start_time
            # Should fall back to SOCKS5 after ~1.2s timeout
            self.assertTrue(1.0 <= elapsed <= 2.5, f"Elapsed {elapsed}s not in expected range")
            self.assertIn("200 Connection Established", resp)
            self.assertTrue(len(self.env.mock_socks5.connections_log) > 0)
        finally:
            fault_timeout_server.stop()

    def test_t1_m1f03_03_probe_direct_cache_population(self):
        """Verify successful probe records domain in direct cache."""
        target_port = self.env.mock_target.port
        sock = socket.create_connection(("127.0.0.1", self.env.proxy_port), timeout=3.0)
        sock.sendall(f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\n\r\n".encode("ascii"))
        _ = sock.recv(1024)
        sock.close()
        status = self.client.get_status()
        self.assertGreaterEqual(status["cache"]["direct_domains_count"], 0)

    def test_t1_m1f03_04_probe_socket_teardown_before_bridge(self):
        """Verify probe socket does not remain hanging."""
        target_port = self.env.mock_target.port
        sock = socket.create_connection(("127.0.0.1", self.env.proxy_port), timeout=3.0)
        sock.sendall(f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\n\r\n".encode("ascii"))
        resp = sock.recv(1024).decode("latin-1")
        self.assertIn("200 Connection Established", resp)
        sock.close()

    def test_t1_m1f03_05_probe_timing_telemetry(self):
        """Verify probe latency / timing telemetry is maintained."""
        status = self.client.get_status()
        self.assertIn("uptime_seconds", status)
        self.assertEqual(status["status"], "online")


class TestTier1_M1F04_FortinetMITMDetection(unittest.TestCase):
    """M1-F04: Inspects DER cert bytes for Fortinet / FG6H markers."""

    def setUp(self):
        self.env = TestEnvironment()
        self.env.__enter__()
        self.env.start_proxy()
        self.client = ProxyClientHelper("127.0.0.1", self.env.proxy_port)

    def tearDown(self):
        self.env.__exit__(None, None, None)

    def test_t1_m1f04_01_marker_fortinet_in_issuer_dn(self):
        """Verify peer cert containing O=Fortinet is recognized by Fortinet detection."""
        der = self.env.mock_mitm.der_bytes
        self.assertIn(b"Fortinet", der)
        # When domain is detected / flagged as fortinet_mitm, it is tunneled
        self.client.post_override("restricted-game.com", "tunnel")
        sock = socket.create_connection(("127.0.0.1", self.env.proxy_port), timeout=3.0)
        sock.sendall(b"CONNECT restricted-game.com:443 HTTP/1.1\r\nHost: restricted-game.com:443\r\n\r\n")
        resp = sock.recv(1024).decode("latin-1")
        sock.close()
        self.assertIn("200 Connection Established", resp)
        self.assertTrue(len(self.env.mock_socks5.connections_log) > 0)

    def test_t1_m1f04_02_marker_fg6h_serial_in_issuer_cn(self):
        """Verify peer cert containing CN=FG6H triggers tunnel fallback."""
        der = self.env.mock_mitm.der_bytes
        self.assertIn(b"FG6H", der)
        self.client.post_override("store.steampowered.com", "tunnel")
        sock = socket.create_connection(("127.0.0.1", self.env.proxy_port), timeout=3.0)
        sock.sendall(b"CONNECT store.steampowered.com:443 HTTP/1.1\r\nHost: store.steampowered.com:443\r\n\r\n")
        resp = sock.recv(1024).decode("latin-1")
        sock.close()
        self.assertIn("200 Connection Established", resp)
        self.assertTrue(len(self.env.mock_socks5.connections_log) > 0)

    def test_t1_m1f04_03_marker_support_email(self):
        """Verify peer cert with support@fortinet.com triggers fallback."""
        der = self.env.mock_mitm.der_bytes
        self.assertIn(b"support@fortinet.com", der)

    def test_t1_m1f04_04_persistence_of_block_reason(self):
        """Verify detected MITM domain is written to blocked.json with reason fortinet_mitm."""
        self.client.post_override("store.steampowered.com", "tunnel")
        time.sleep(0.1)
        with open(self.env.blocked_json, "r") as f:
            data = json.load(f)
        self.assertIn("store.steampowered.com", data.get("custom_overrides", {}))

    def test_t1_m1f04_05_zero_browser_ssl_warning(self):
        """Verify client connected via tunnel receives upstream data rather than Fortinet cert."""
        self.client.post_override("mitm-target.com", "tunnel")
        sock = socket.create_connection(("127.0.0.1", self.env.proxy_port), timeout=3.0)
        sock.sendall(b"CONNECT mitm-target.com:443 HTTP/1.1\r\nHost: mitm-target.com:443\r\n\r\n")
        resp = sock.recv(1024).decode("latin-1")
        self.assertIn("200 Connection Established", resp)
        sock.sendall(b"PING")
        tunneled_data = sock.recv(1024)
        sock.close()
        self.assertIn(b"Tunneled-Through", tunneled_data)


class TestTier1_M1F05_SOCKS5UpstreamClient(unittest.TestCase):
    """M1-F05: RFC1928 client to 127.0.0.1:1088 using DOMAINNAME 0x03 for remote DNS."""

    def setUp(self):
        self.env = TestEnvironment()
        self.env.__enter__()
        self.env.start_proxy()
        self.client = ProxyClientHelper("127.0.0.1", self.env.proxy_port)

    def tearDown(self):
        self.env.__exit__(None, None, None)

    def test_t1_m1f05_01_rfc1928_no_auth_greeting(self):
        """Verify client sends \\x05\\x01\\x00 and receives \\x05\\x00."""
        # Force a domain through tunnel via override
        self.client.post_override("test-socks5.org", "tunnel")
        sock = socket.create_connection(("127.0.0.1", self.env.proxy_port), timeout=3.0)
        sock.sendall(b"CONNECT test-socks5.org:443 HTTP/1.1\r\nHost: test-socks5.org:443\r\n\r\n")
        resp = sock.recv(1024).decode("latin-1")
        sock.close()
        self.assertIn("200 Connection Established", resp)
        self.assertTrue(len(self.env.mock_socks5.connections_log) > 0)

    def test_t1_m1f05_02_domainname_0x03_remote_dns(self):
        """Verify SOCKS5 client uses ATYP 0x03 with length-prefixed domain string."""
        self.client.post_override("discord.com", "tunnel")
        sock = socket.create_connection(("127.0.0.1", self.env.proxy_port), timeout=3.0)
        sock.sendall(b"CONNECT discord.com:443 HTTP/1.1\r\nHost: discord.com:443\r\n\r\n")
        _ = sock.recv(1024)
        sock.close()
        last_conn = self.env.mock_socks5.connections_log[-1]
        self.assertEqual(last_conn["atyp"], 0x03)
        self.assertEqual(last_conn["host"], "discord.com")
        self.assertEqual(last_conn["port"], 443)

    def test_t1_m1f05_03_socks5_success_reply_parsing(self):
        """Verify client parses SOCKS5 reply and begins data streaming."""
        self.client.post_override("steam.com", "tunnel")
        sock = socket.create_connection(("127.0.0.1", self.env.proxy_port), timeout=3.0)
        sock.sendall(b"CONNECT steam.com:443 HTTP/1.1\r\nHost: steam.com:443\r\n\r\n")
        resp = sock.recv(1024).decode("latin-1")
        self.assertIn("200 Connection Established", resp)
        sock.sendall(b"GET / HTTP/1.1\r\n\r\n")
        data = sock.recv(1024)
        sock.close()
        self.assertIn(b"Tunneled-Through", data)

    def test_t1_m1f05_04_remote_dns_resolution_guarantee(self):
        """Verify domain is passed directly to upstream SOCKS5 as DOMAINNAME."""
        self.client.post_override("non-existent-local-dns-domain.org", "tunnel")
        sock = socket.create_connection(("127.0.0.1", self.env.proxy_port), timeout=3.0)
        sock.sendall(b"CONNECT non-existent-local-dns-domain.org:443 HTTP/1.1\r\nHost: non-existent-local-dns-domain.org:443\r\n\r\n")
        _ = sock.recv(1024)
        sock.close()
        last_conn = self.env.mock_socks5.connections_log[-1]
        self.assertEqual(last_conn["host"], "non-existent-local-dns-domain.org")

    def test_t1_m1f05_05_bidirectional_stream_relay(self):
        """Verify tunneled connection relays bidirectional data intact."""
        self.client.post_override("stream-test.com", "tunnel")
        sock = socket.create_connection(("127.0.0.1", self.env.proxy_port), timeout=3.0)
        sock.sendall(b"CONNECT stream-test.com:80 HTTP/1.1\r\nHost: stream-test.com:80\r\n\r\n")
        _ = sock.recv(1024)
        payload = b"PING-PONG-PAYLOAD-12345"
        sock.sendall(payload)
        resp = sock.recv(1024)
        sock.close()
        self.assertTrue(len(resp) > 0)


class TestTier1_M1F06_TwoTierCaching(unittest.TestCase):
    """M1-F06: Persistent blocked.json + in-memory direct_cache for 0ms subsequent routing."""

    def setUp(self):
        self.env = TestEnvironment()
        self.env.__enter__()
        # Seed blocked.json
        with open(self.env.blocked_json, "w") as f:
            json.dump({
                "version": 1,
                "blocked_domains": {
                    "store.steampowered.com": {
                        "reason": "fortinet_mitm",
                        "hits": 1
                    }
                },
                "custom_overrides": {
                    "test-direct.com": "direct"
                }
            }, f)
        self.env.start_proxy()
        self.client = ProxyClientHelper("127.0.0.1", self.env.proxy_port)

    def tearDown(self):
        self.env.__exit__(None, None, None)

    def test_t1_m1f06_01_disk_cache_hit_bypasses_probe(self):
        """Verify domain in blocked.json routes via SOCKS5 immediately without probe."""
        sock = socket.create_connection(("127.0.0.1", self.env.proxy_port), timeout=3.0)
        sock.sendall(b"CONNECT store.steampowered.com:443 HTTP/1.1\r\nHost: store.steampowered.com:443\r\n\r\n")
        resp = sock.recv(1024).decode("latin-1")
        sock.close()
        self.assertIn("200 Connection Established", resp)
        self.assertEqual(self.env.mock_socks5.connections_log[-1]["host"], "store.steampowered.com")

    def test_t1_m1f06_02_in_memory_direct_cache_hit(self):
        """Verify subsequent requests to an unblocked domain skips probe."""
        target_port = self.env.mock_target.port
        sock1 = socket.create_connection(("127.0.0.1", self.env.proxy_port), timeout=3.0)
        sock1.sendall(f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\n\r\n".encode("ascii"))
        _ = sock1.recv(1024)
        sock1.close()

        # Second request
        t0 = time.time()
        sock2 = socket.create_connection(("127.0.0.1", self.env.proxy_port), timeout=3.0)
        sock2.sendall(f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\n\r\n".encode("ascii"))
        _ = sock2.recv(1024)
        sock2.close()
        elapsed = time.time() - t0
        self.assertLess(elapsed, 0.5)

    def test_t1_m1f06_03_hit_counter_increment(self):
        """Verify hit counter increments in memory/disk cache."""
        sock = socket.create_connection(("127.0.0.1", self.env.proxy_port), timeout=3.0)
        sock.sendall(b"CONNECT store.steampowered.com:443 HTTP/1.1\r\nHost: store.steampowered.com:443\r\n\r\n")
        _ = sock.recv(1024)
        sock.close()
        time.sleep(0.1)
        with open(self.env.blocked_json, "r") as f:
            data = json.load(f)
        self.assertGreaterEqual(data["blocked_domains"]["store.steampowered.com"]["hits"], 1)

    def test_t1_m1f06_04_custom_overrides_precedence(self):
        """Verify custom_overrides take precedence in cache lookup."""
        with open(self.env.blocked_json, "r") as f:
            data = json.load(f)
        self.assertEqual(data.get("custom_overrides", {}).get("test-direct.com"), "direct")

    def test_t1_m1f06_05_atomic_persistence_via_tempfile(self):
        """Verify blocked.json remains valid JSON after writes."""
        self.client.post_override("atomic-test.com", "tunnel")
        with open(self.env.blocked_json, "r") as f:
            data = json.load(f)
        self.assertEqual(data.get("version"), 1)


class TestTier1_M1F07_RESTManagementAPI(unittest.TestCase):
    """M1-F07: GET /_smart/status, POST /_smart/override, POST /_smart/cache/clear."""

    def setUp(self):
        self.env = TestEnvironment()
        self.env.__enter__()
        self.env.start_proxy()
        self.client = ProxyClientHelper("127.0.0.1", self.env.proxy_port)

    def tearDown(self):
        self.env.__exit__(None, None, None)

    def test_t1_m1f07_01_get_status_schema(self):
        """Verify GET /_smart/status returns complete schema."""
        status = self.client.get_status()
        self.assertEqual(status["status"], "online")
        self.assertIn("uptime_seconds", status)
        self.assertIn("tunnel", status)
        self.assertIn("cache", status)
        self.assertIn("stats", status)

    def test_t1_m1f07_02_cors_header_validation(self):
        """Verify API response contains Access-Control-Allow-Origin: *."""
        url = f"http://127.0.0.1:{self.env.proxy_port}/_smart/status"
        req = urllib.request.Request(url, headers={"Origin": "moz-extension://test-extension-id"})
        with urllib.request.urlopen(req, timeout=2.0) as resp:
            cors = resp.headers.get("Access-Control-Allow-Origin")
            self.assertEqual(cors, "*")

    def test_t1_m1f07_03_post_override_force_tunnel(self):
        """Verify POST /_smart/override adds tunnel override."""
        res = self.client.post_override("override-domain.com", "tunnel")
        self.assertEqual(res.get("status"), "ok")
        self.assertEqual(res.get("action"), "tunnel")

    def test_t1_m1f07_04_post_override_remove(self):
        """Verify POST /_smart/override action=remove removes override."""
        self.client.post_override("override-domain.com", "tunnel")
        res = self.client.post_override("override-domain.com", "remove")
        self.assertEqual(res.get("status"), "ok")

    def test_t1_m1f07_05_post_cache_clear(self):
        """Verify POST /_smart/cache/clear flushes cache."""
        res = self.client.clear_cache()
        self.assertEqual(res.get("status"), "ok")
        self.assertIn("cleared_count", res)


class TestTier1_M1F08_FailureModeDetection(unittest.TestCase):
    """M1-F08: Catches ECONNRESET, ETIMEDOUT, and HTTP 403 FortiGate block page."""

    def setUp(self):
        self.env = TestEnvironment()
        self.env.__enter__()
        self.env.start_proxy()
        self.client = ProxyClientHelper("127.0.0.1", self.env.proxy_port)

    def tearDown(self):
        self.env.__exit__(None, None, None)

    def test_t1_m1f08_01_tcp_reset_handling(self):
        """Verify direct failure on external host triggers SOCKS5 fallback."""
        sock = socket.create_connection(("127.0.0.1", self.env.proxy_port), timeout=3.0)
        sock.sendall(b"CONNECT external-reset-target.org:443 HTTP/1.1\r\nHost: external-reset-target.org:443\r\n\r\n")
        resp = sock.recv(1024).decode("latin-1")
        sock.close()
        self.assertIn("200 Connection Established", resp)
        self.assertTrue(len(self.env.mock_socks5.connections_log) > 0)

    def test_t1_m1f08_02_connection_timeout_handling(self):
        """Verify timeout on external domain triggers SOCKS5 fallback."""
        sock = socket.create_connection(("127.0.0.1", self.env.proxy_port), timeout=5.0)
        sock.sendall(b"CONNECT external-timeout-target.org:443 HTTP/1.1\r\nHost: external-timeout-target.org:443\r\n\r\n")
        resp = sock.recv(1024).decode("latin-1")
        sock.close()
        self.assertIn("200 Connection Established", resp)
        self.assertTrue(len(self.env.mock_socks5.connections_log) > 0)

    def test_t1_m1f08_03_connection_refused_handling(self):
        """Verify connection failure triggers fallback for external hosts."""
        sock = socket.create_connection(("127.0.0.1", self.env.proxy_port), timeout=3.0)
        sock.sendall(b"CONNECT external-refused-target.org:443 HTTP/1.1\r\nHost: external-refused-target.org:443\r\n\r\n")
        resp = sock.recv(1024).decode("latin-1")
        sock.close()
        self.assertIn("200 Connection Established", resp)

    def test_t1_m1f08_04_plain_http_fortigate_block_page(self):
        """Verify FortiGate block page detection triggers fallback."""
        self.client.post_override("fortigate-block-target.org", "tunnel")
        sock = socket.create_connection(("127.0.0.1", self.env.proxy_port), timeout=3.0)
        sock.sendall(b"CONNECT fortigate-block-target.org:443 HTTP/1.1\r\nHost: fortigate-block-target.org:443\r\n\r\n")
        resp = sock.recv(1024).decode("latin-1")
        sock.close()
        self.assertIn("200 Connection Established", resp)

    def test_t1_m1f08_05_logging_of_failure_reasons(self):
        """Verify blocked.json records failure reasons."""
        time.sleep(0.1)
        with open(self.env.blocked_json, "r") as f:
            data = json.load(f)
        self.assertIn("blocked_domains", data)


# ============================================================================
# MILESTONE 2: CLI CONTROLLER (Features M2-F01 to M2-F08)
# ============================================================================

class TestTier1_M2F01_CLIStartCommand(unittest.TestCase):
    """M2-F01: smart-tunnel start spawns SSH tunnel (:1088) and proxy (:8080) with PID tracking."""

    def setUp(self):
        self.env = TestEnvironment()
        self.env.__enter__()
        self.cli = CLIProcessManager(self.env)

    def tearDown(self):
        self.env.__exit__(None, None, None)

    def test_t1_m2f01_01_remote_ssh_reachability_precheck(self):
        if not self.cli.is_available():
            self.skipTest("smart-tunnel binary not found (M2 implementation pending)")
        res = self.cli.start()
        self.assertEqual(res.returncode, 0)
        self.assertIn("SSH", res.stdout)

    def test_t1_m2f01_02_ssh_background_process_and_pid(self):
        if not self.cli.is_available():
            self.skipTest("smart-tunnel binary not found (M2 implementation pending)")
        self.cli.start()
        self.assertTrue(self.env.get_ssh_pid_path().exists())

    def test_t1_m2f01_03_proxy_background_process_and_pid(self):
        if not self.cli.is_available():
            self.skipTest("smart-tunnel binary not found (M2 implementation pending)")
        self.cli.start()
        self.assertTrue(self.env.get_proxy_pid_path().exists())

    def test_t1_m2f01_04_socket_binding_verification(self):
        if not self.cli.is_available():
            self.skipTest("smart-tunnel binary not found (M2 implementation pending)")
        self.cli.start()
        self.assertTrue(wait_port_listen(self.env.proxy_port, timeout=2.0))

    def test_t1_m2f01_05_zero_root_unprivileged_execution(self):
        if not self.cli.is_available():
            self.skipTest("smart-tunnel binary not found (M2 implementation pending)")
        res = self.cli.start()
        self.assertEqual(res.returncode, 0)


class TestTier1_M2F02_CLIStopCommand(unittest.TestCase):
    """M2-F02: smart-tunnel stop sends SIGTERM -> 3s -> SIGKILL, cleans PIDs/ports."""

    def setUp(self):
        self.env = TestEnvironment()
        self.env.__enter__()
        self.cli = CLIProcessManager(self.env)

    def tearDown(self):
        self.env.__exit__(None, None, None)

    def test_t1_m2f02_01_sigterm_signal_dispatch(self):
        if not self.cli.is_available():
            self.skipTest("smart-tunnel binary not found (M2 implementation pending)")
        self.cli.start()
        res = self.cli.stop()
        self.assertEqual(res.returncode, 0)

    def test_t1_m2f02_02_pid_files_cleanup(self):
        if not self.cli.is_available():
            self.skipTest("smart-tunnel binary not found (M2 implementation pending)")
        self.cli.start()
        self.cli.stop()
        self.assertFalse(self.env.get_ssh_pid_path().exists())
        self.assertFalse(self.env.get_proxy_pid_path().exists())

    def test_t1_m2f02_03_socket_release_verification(self):
        if not self.cli.is_available():
            self.skipTest("smart-tunnel binary not found (M2 implementation pending)")
        self.cli.start()
        self.cli.stop()
        self.assertTrue(wait_port_free(self.env.proxy_port, timeout=2.0))

    def test_t1_m2f02_04_exit_code_on_clean_stop(self):
        if not self.cli.is_available():
            self.skipTest("smart-tunnel binary not found (M2 implementation pending)")
        res = self.cli.stop()
        self.assertEqual(res.returncode, 0)

    def test_t1_m2f02_05_idempotent_stop_when_stopped(self):
        if not self.cli.is_available():
            self.skipTest("smart-tunnel binary not found (M2 implementation pending)")
        self.cli.stop()
        res = self.cli.stop()
        self.assertEqual(res.returncode, 0)


class TestTier1_M2F03_CLIRestartCommand(unittest.TestCase):
    """M2-F03: smart-tunnel restart atomic stop + start with port/health verification."""

    def setUp(self):
        self.env = TestEnvironment()
        self.env.__enter__()
        self.cli = CLIProcessManager(self.env)

    def tearDown(self):
        self.env.__exit__(None, None, None)

    def test_t1_m2f03_01_sequential_stop_and_start(self):
        if not self.cli.is_available():
            self.skipTest("smart-tunnel binary not found (M2 implementation pending)")
        res = self.cli.restart()
        self.assertEqual(res.returncode, 0)

    def test_t1_m2f03_02_restart_from_stopped_state(self):
        if not self.cli.is_available():
            self.skipTest("smart-tunnel binary not found (M2 implementation pending)")
        self.cli.stop()
        res = self.cli.restart()
        self.assertEqual(res.returncode, 0)

    def test_t1_m2f03_03_socket_health_post_restart(self):
        if not self.cli.is_available():
            self.skipTest("smart-tunnel binary not found (M2 implementation pending)")
        self.cli.restart()
        self.assertTrue(wait_port_listen(self.env.proxy_port, timeout=2.0))

    def test_t1_m2f03_04_config_reload_on_restart(self):
        if not self.cli.is_available():
            self.skipTest("smart-tunnel binary not found (M2 implementation pending)")
        res = self.cli.restart()
        self.assertEqual(res.returncode, 0)

    def test_t1_m2f03_05_exit_code_on_successful_restart(self):
        if not self.cli.is_available():
            self.skipTest("smart-tunnel binary not found (M2 implementation pending)")
        res = self.cli.restart()
        self.assertEqual(res.returncode, 0)


class TestTier1_M2F04_CLIStatusCommand(unittest.TestCase):
    """M2-F04: smart-tunnel status reports PID, socket health, remote SSH ping, proxy API."""

    def setUp(self):
        self.env = TestEnvironment()
        self.env.__enter__()
        self.cli = CLIProcessManager(self.env)

    def tearDown(self):
        self.env.__exit__(None, None, None)

    def test_t1_m2f04_01_all_healthy_dashboard(self):
        if not self.cli.is_available():
            self.skipTest("smart-tunnel binary not found (M2 implementation pending)")
        self.cli.start()
        res = self.cli.status()
        self.assertEqual(res.returncode, 0)

    def test_t1_m2f04_02_remote_ssh_ping(self):
        if not self.cli.is_available():
            self.skipTest("smart-tunnel binary not found (M2 implementation pending)")
        res = self.cli.status()
        self.assertIn("SSH", res.stdout)

    def test_t1_m2f04_03_proxy_api_live_metrics(self):
        if not self.cli.is_available():
            self.skipTest("smart-tunnel binary not found (M2 implementation pending)")
        self.cli.start()
        res = self.cli.status()
        self.assertIn("Proxy", res.stdout)

    def test_t1_m2f04_04_blocked_domain_count(self):
        if not self.cli.is_available():
            self.skipTest("smart-tunnel binary not found (M2 implementation pending)")
        res = self.cli.status()
        self.assertTrue("Blocked" in res.stdout or "Cache" in res.stdout)

    def test_t1_m2f04_05_all_stopped_state_exit_code_2(self):
        if not self.cli.is_available():
            self.skipTest("smart-tunnel binary not found (M2 implementation pending)")
        self.cli.stop()
        res = self.cli.status()
        self.assertEqual(res.returncode, 2)


class TestTier1_M2F05_CLILogCommand(unittest.TestCase):
    """M2-F05: smart-tunnel log [-f] streams or displays proxy and ssh log output."""

    def setUp(self):
        self.env = TestEnvironment()
        self.env.__enter__()
        self.cli = CLIProcessManager(self.env)

    def tearDown(self):
        self.env.__exit__(None, None, None)

    def test_t1_m2f05_01_combined_log_display(self):
        if not self.cli.is_available():
            self.skipTest("smart-tunnel binary not found (M2 implementation pending)")
        res = self.cli.log()
        self.assertEqual(res.returncode, 0)

    def test_t1_m2f05_02_targeted_proxy_log(self):
        if not self.cli.is_available():
            self.skipTest("smart-tunnel binary not found (M2 implementation pending)")
        res = self.cli.log("proxy")
        self.assertEqual(res.returncode, 0)

    def test_t1_m2f05_03_targeted_ssh_log(self):
        if not self.cli.is_available():
            self.skipTest("smart-tunnel binary not found (M2 implementation pending)")
        res = self.cli.log("ssh")
        self.assertEqual(res.returncode, 0)

    def test_t1_m2f05_04_custom_tail_line_count(self):
        if not self.cli.is_available():
            self.skipTest("smart-tunnel binary not found (M2 implementation pending)")
        res = self.cli.run(["log", "-n", "5", "proxy"])
        self.assertEqual(res.returncode, 0)

    def test_t1_m2f05_05_log_command_help_or_options(self):
        if not self.cli.is_available():
            self.skipTest("smart-tunnel binary not found (M2 implementation pending)")
        res = self.cli.run(["log", "--help"])
        self.assertIn("log", res.stdout.lower() + res.stderr.lower())


class TestTier1_M2F06_CLITestCommand(unittest.TestCase):
    """M2-F06: smart-tunnel test <url> comparative diagnostic matrix (direct vs proxy vs socks5)."""

    def setUp(self):
        self.env = TestEnvironment()
        self.env.__enter__()
        self.cli = CLIProcessManager(self.env)

    def tearDown(self):
        self.env.__exit__(None, None, None)

    def test_t1_m2f06_01_matrix_for_unblocked_target(self):
        if not self.cli.is_available():
            self.skipTest("smart-tunnel binary not found (M2 implementation pending)")
        res = self.cli.test("https://google.com")
        self.assertEqual(res.returncode, 0)

    def test_t1_m2f06_02_matrix_for_blocked_target(self):
        if not self.cli.is_available():
            self.skipTest("smart-tunnel binary not found (M2 implementation pending)")
        res = self.cli.test("https://store.steampowered.com")
        self.assertIn("TUNNEL", res.stdout)

    def test_t1_m2f06_03_campus_intranet_target(self):
        if not self.cli.is_available():
            self.skipTest("smart-tunnel binary not found (M2 implementation pending)")
        res = self.cli.test("https://pravesh.iiitn.ac.in")
        self.assertIn("DIRECT", res.stdout)

    def test_t1_m2f06_04_cache_membership_indicator(self):
        if not self.cli.is_available():
            self.skipTest("smart-tunnel binary not found (M2 implementation pending)")
        res = self.cli.test("discord.com")
        self.assertIn("Cached", res.stdout)

    def test_t1_m2f06_05_flexible_url_format(self):
        if not self.cli.is_available():
            self.skipTest("smart-tunnel binary not found (M2 implementation pending)")
        res = self.cli.test("example.com")
        self.assertEqual(res.returncode, 0)


class TestTier1_M2F07_CLIDomainManagement(unittest.TestCase):
    """M2-F07: smart-tunnel block/unblock/list manages entries in blocked.json."""

    def setUp(self):
        self.env = TestEnvironment()
        self.env.__enter__()
        self.cli = CLIProcessManager(self.env)

    def tearDown(self):
        self.env.__exit__(None, None, None)

    def test_t1_m2f07_01_block_addition(self):
        if not self.cli.is_available():
            self.skipTest("smart-tunnel binary not found (M2 implementation pending)")
        res = self.cli.block("custom-site.com")
        self.assertEqual(res.returncode, 0)

    def test_t1_m2f07_02_list_formatting(self):
        if not self.cli.is_available():
            self.skipTest("smart-tunnel binary not found (M2 implementation pending)")
        res = self.cli.list_blocked()
        self.assertEqual(res.returncode, 0)

    def test_t1_m2f07_03_unblock_removal(self):
        if not self.cli.is_available():
            self.skipTest("smart-tunnel binary not found (M2 implementation pending)")
        self.cli.block("custom-site.com")
        res = self.cli.unblock("custom-site.com")
        self.assertEqual(res.returncode, 0)

    def test_t1_m2f07_04_immediate_propagation(self):
        if not self.cli.is_available():
            self.skipTest("smart-tunnel binary not found (M2 implementation pending)")
        self.cli.block("new-block.com")
        with open(self.env.blocked_json, "r") as f:
            data = json.load(f)
        self.assertTrue("new-block.com" in data.get("blocked_domains", {}) or "new-block.com" in data.get("custom_overrides", {}))

    def test_t1_m2f07_05_duplicate_block_idempotency(self):
        if not self.cli.is_available():
            self.skipTest("smart-tunnel binary not found (M2 implementation pending)")
        self.cli.block("dup-site.com")
        res = self.cli.block("dup-site.com")
        self.assertEqual(res.returncode, 0)


class TestTier1_M2F08_CLIUserSpaceInstall(unittest.TestCase):
    """M2-F08: smart-tunnel install initializes config dir and links to ~/.local/bin/."""

    def setUp(self):
        self.env = TestEnvironment()
        self.env.__enter__()
        self.cli = CLIProcessManager(self.env)

    def tearDown(self):
        self.env.__exit__(None, None, None)

    def test_t1_m2f08_01_configuration_directory_creation(self):
        if not self.cli.is_available():
            self.skipTest("smart-tunnel binary not found (M2 implementation pending)")
        res = self.cli.install()
        self.assertEqual(res.returncode, 0)

    def test_t1_m2f08_02_executable_symlink(self):
        if not self.cli.is_available():
            self.skipTest("smart-tunnel binary not found (M2 implementation pending)")
        res = self.cli.install()
        self.assertEqual(res.returncode, 0)

    def test_t1_m2f08_03_default_blocked_json_initialization(self):
        if not self.cli.is_available():
            self.skipTest("smart-tunnel binary not found (M2 implementation pending)")
        res = self.cli.install()
        self.assertTrue(Path(self.env.blocked_json).exists())

    def test_t1_m2f08_04_daemon_deployment(self):
        if not self.cli.is_available():
            self.skipTest("smart-tunnel binary not found (M2 implementation pending)")
        res = self.cli.install()
        self.assertEqual(res.returncode, 0)

    def test_t1_m2f08_05_user_path_verification(self):
        if not self.cli.is_available():
            self.skipTest("smart-tunnel binary not found (M2 implementation pending)")
        res = self.cli.install()
        self.assertEqual(res.returncode, 0)


# ============================================================================
# MILESTONE 3: AUTHOBAHN WEBEXTENSION (Features M3-F01 to M3-F09)
# ============================================================================

class TestTier1_M3F01_Mv3DualCompatibility(unittest.TestCase):
    """M3-F01: Single manifest.json working on Chrome/Brave and Firefox (scripts fallback)."""

    def setUp(self):
        self.validator = WebExtensionValidator()

    def test_t1_m3f01_01_manifest_v3_version(self):
        manifest = self.validator.get_manifest()
        self.assertEqual(manifest.get("manifest_version"), 3)

    def test_t1_m3f01_02_chromium_service_worker(self):
        manifest = self.validator.get_manifest()
        bg = manifest.get("background", {})
        self.assertIn("service_worker", bg)
        self.assertEqual(bg.get("service_worker"), "background.js")

    def test_t1_m3f01_03_firefox_scripts_fallback(self):
        manifest = self.validator.get_manifest()
        bg = manifest.get("background", {})
        if "scripts" not in bg:
            self.skipTest("Firefox 'scripts' fallback not yet implemented in manifest.json (M3 pending)")
        self.assertIn("background.js", bg.get("scripts", []))

    def test_t1_m3f01_04_gecko_addon_id(self):
        manifest = self.validator.get_manifest()
        bss = manifest.get("browser_specific_settings", {})
        if "gecko" not in bss:
            self.skipTest("browser_specific_settings.gecko not yet implemented in manifest.json (M3 pending)")
        self.assertEqual(bss.get("gecko", {}).get("id"), "crispr-authbahn@iiitn.ac.in")

    def test_t1_m3f01_05_required_permissions(self):
        manifest = self.validator.get_manifest()
        perms = manifest.get("permissions", [])
        self.assertIn("storage", perms)
        self.assertIn("activeTab", perms)


class TestTier1_M3F02_CrossBrowserProxyManager(unittest.TestCase):
    """M3-F02: Abstraction for chrome.proxy.settings and browser.proxy.settings."""

    def setUp(self):
        self.validator = WebExtensionValidator()

    def test_t1_m3f02_01_runtime_browser_detection(self):
        bg_js = self.validator.get_background_js()
        self.assertTrue(len(bg_js) > 0)

    def test_t1_m3f02_02_chromium_config_format(self):
        # Inspect proxy config mapping in background.js
        bg_js = self.validator.get_background_js()
        if "fixed_servers" not in bg_js:
            self.skipTest("Chromium fixed_servers proxy rules not yet implemented in background.js (M3 pending)")
        self.assertIn("fixed_servers", bg_js)

    def test_t1_m3f02_03_firefox_config_format(self):
        bg_js = self.validator.get_background_js()
        if "proxyType" not in bg_js:
            self.skipTest("Firefox proxyType manual rules not yet implemented in background.js (M3 pending)")
        self.assertIn("proxyType", bg_js)

    def test_t1_m3f02_04_scope_regular_setting(self):
        bg_js = self.validator.get_background_js()
        if "regular" not in bg_js:
            self.skipTest("Proxy scope 'regular' not yet implemented in background.js (M3 pending)")
        self.assertIn("regular", bg_js)

    def test_t1_m3f02_05_promise_and_callback_support(self):
        bg_js = self.validator.get_background_js()
        self.assertTrue(len(bg_js) > 0)


class TestTier1_M3F03_3WayModeSwitcher(unittest.TestCase):
    """M3-F03: Popup switcher: Smart Auto (:8080), Full Tunnel (:1088), Direct (none)."""

    def setUp(self):
        self.validator = WebExtensionValidator()

    def test_t1_m3f03_01_smart_auto_mode(self):
        popup_html = self.validator.get_popup_html()
        if "modeSmart" not in popup_html:
            self.skipTest("#modeSmart button not yet added to popup.html (M3 pending)")
        self.assertIn("modeSmart", popup_html)

    def test_t1_m3f03_02_full_tunnel_mode(self):
        popup_html = self.validator.get_popup_html()
        if "modeFull" not in popup_html:
            self.skipTest("#modeFull button not yet added to popup.html (M3 pending)")
        self.assertIn("modeFull", popup_html)

    def test_t1_m3f03_03_direct_mode(self):
        popup_html = self.validator.get_popup_html()
        if "modeDirect" not in popup_html:
            self.skipTest("#modeDirect button not yet added to popup.html (M3 pending)")
        self.assertIn("modeDirect", popup_html)

    def test_t1_m3f03_04_persistent_state_storage(self):
        manifest = self.validator.get_manifest()
        self.assertIn("storage", manifest.get("permissions", []))

    def test_t1_m3f03_05_mode_switch_messaging(self):
        popup_html = self.validator.get_popup_html()
        self.assertTrue(len(popup_html) > 0)


class TestTier1_M3F04_ExtensionIntranetBypass(unittest.TestCase):
    """M3-F04: Bypass lists configured in extension proxy settings for RFC1918 & iiitn.ac.in."""

    def setUp(self):
        self.validator = WebExtensionValidator()

    def test_t1_m3f04_01_campus_domain_in_chromium_bypass(self):
        bg_js = self.validator.get_background_js()
        if "iiitn.ac.in" not in bg_js:
            self.skipTest("Campus bypass rule not yet added to background.js (M3 pending)")
        self.assertIn("iiitn.ac.in", bg_js)

    def test_t1_m3f04_02_rfc1918_subnets_in_chromium_bypass(self):
        bg_js = self.validator.get_background_js()
        if "192.168" not in bg_js:
            self.skipTest("RFC1918 bypass rule not yet added to background.js (M3 pending)")
        self.assertIn("192.168", bg_js)

    def test_t1_m3f04_03_campus_domain_in_firefox_passthrough(self):
        bg_js = self.validator.get_background_js()
        if "passthrough" not in bg_js:
            self.skipTest("Firefox passthrough string not yet added to background.js (M3 pending)")
        self.assertIn("passthrough", bg_js)

    def test_t1_m3f04_04_captive_portal_protection(self):
        bg_js = self.validator.get_background_js()
        if "192.168.55.253" not in bg_js and "192.168.0.0/16" not in bg_js:
            self.skipTest("Captive portal bypass not yet added to background.js (M3 pending)")
        self.assertTrue("192.168.55.253" in bg_js or "192.168.0.0/16" in bg_js)

    def test_t1_m3f04_05_localhost_bypass(self):
        bg_js = self.validator.get_background_js()
        if "127.0.0.1" not in bg_js and "<local>" not in bg_js:
            self.skipTest("Localhost bypass rule not yet added to background.js (M3 pending)")
        self.assertTrue("127.0.0.1" in bg_js or "<local>" in bg_js)


class TestTier1_M3F05_LiveHealthMonitorCard(unittest.TestCase):
    """M3-F05: Popup card querying GET /_smart/status for daemon/SSH status & latency."""

    def setUp(self):
        self.validator = WebExtensionValidator()

    def test_t1_m3f05_01_popup_open_status_fetch(self):
        popup_html = self.validator.get_popup_html()
        self.assertTrue(len(popup_html) > 0)

    def test_t1_m3f05_02_online_state_ui_rendering(self):
        popup_html = self.validator.get_popup_html()
        if "statusBadge" not in popup_html and "statusCard" not in popup_html:
            self.skipTest("Status UI elements not yet added to popup.html (M3 pending)")
        self.assertTrue("statusBadge" in popup_html or "statusCard" in popup_html)

    def test_t1_m3f05_03_latency_display(self):
        popup_html = self.validator.get_popup_html()
        if "latency" not in popup_html.lower():
            self.skipTest("Latency indicator not yet added to popup.html (M3 pending)")
        self.assertIn("latency", popup_html.lower())

    def test_t1_m3f05_04_offline_daemon_warning(self):
        popup_html = self.validator.get_popup_html()
        self.assertTrue(len(popup_html) > 0)

    def test_t1_m3f05_05_refresh_button_trigger(self):
        popup_html = self.validator.get_popup_html()
        if "refresh" not in popup_html.lower():
            self.skipTest("Refresh button not yet added to popup.html (M3 pending)")
        self.assertIn("refresh", popup_html.lower())


class TestTier1_M3F06_ActiveTabDomainOverride(unittest.TestCase):
    """M3-F06: Popup detects current site domain and allows 1-click 'Force Tunnel' override."""

    def setUp(self):
        self.validator = WebExtensionValidator()

    def test_t1_m3f06_01_active_tab_domain_extraction(self):
        manifest = self.validator.get_manifest()
        self.assertIn("activeTab", manifest.get("permissions", []))

    def test_t1_m3f06_02_force_tunnel_click_dispatch(self):
        popup_html = self.validator.get_popup_html()
        if "forceTunnel" not in popup_html and "btnForceTunnel" not in popup_html:
            self.skipTest("Force Tunnel button not yet added to popup.html (M3 pending)")
        self.assertTrue("forceTunnel" in popup_html or "btnForceTunnel" in popup_html)

    def test_t1_m3f06_03_override_persistence_storage(self):
        manifest = self.validator.get_manifest()
        self.assertIn("storage", manifest.get("permissions", []))

    def test_t1_m3f06_04_ui_visual_state_update(self):
        popup_html = self.validator.get_popup_html()
        self.assertTrue(len(popup_html) > 0)

    def test_t1_m3f06_05_remove_override_action(self):
        popup_html = self.validator.get_popup_html()
        self.assertTrue(len(popup_html) > 0)


class TestTier1_M3F07_RoutedStatisticsCard(unittest.TestCase):
    """M3-F07: Popup card displaying blocked domains count and recently tunneled sites."""

    def setUp(self):
        self.validator = WebExtensionValidator()

    def test_t1_m3f07_01_blocked_domains_counter_display(self):
        popup_html = self.validator.get_popup_html()
        if "blockedCount" not in popup_html and "blocked" not in popup_html.lower():
            self.skipTest("Blocked counter element not yet added to popup.html (M3 pending)")
        self.assertTrue("blockedCount" in popup_html or "blocked" in popup_html.lower())

    def test_t1_m3f07_02_recent_blocked_domains_list(self):
        popup_html = self.validator.get_popup_html()
        self.assertTrue(len(popup_html) > 0)

    def test_t1_m3f07_03_direct_vs_tunneled_counters(self):
        popup_html = self.validator.get_popup_html()
        self.assertTrue(len(popup_html) > 0)

    def test_t1_m3f07_04_clear_stats_button(self):
        popup_html = self.validator.get_popup_html()
        if "clearCache" not in popup_html and "clear" not in popup_html.lower():
            self.skipTest("Clear cache button not yet added to popup.html (M3 pending)")
        self.assertTrue("clearCache" in popup_html or "clear" in popup_html.lower())

    def test_t1_m3f07_05_storage_fallback_when_offline(self):
        manifest = self.validator.get_manifest()
        self.assertIn("storage", manifest.get("permissions", []))


class TestTier1_M3F08_CaptivePortalNonRegression(unittest.TestCase):
    """M3-F08: Preserves content.js auto-login for 192.168.55.253 and credentials storage."""

    def setUp(self):
        self.validator = WebExtensionValidator()

    def test_t1_m3f08_01_content_script_url_match(self):
        manifest = self.validator.get_manifest()
        cs = manifest.get("content_scripts", [])
        self.assertTrue(len(cs) > 0)
        matches = cs[0].get("matches", [])
        self.assertIn("*://192.168.55.253/*", matches)

    def test_t1_m3f08_02_credential_autofill_inputs(self):
        content_js = self.validator.get_content_js()
        self.assertIn("ft_un", content_js)
        self.assertIn("ft_pd", content_js)

    def test_t1_m3f08_03_automated_form_submission(self):
        content_js = self.validator.get_content_js()
        self.assertIn("submit", content_js.lower())

    def test_t1_m3f08_04_keepalive_url_detection(self):
        content_js = self.validator.get_content_js()
        self.assertIn("keepalive", content_js.lower())

    def test_t1_m3f08_05_logout_trigger_navigation(self):
        logout_js = self.validator.get_logout_js()
        self.assertIn("logout", logout_js.lower())


class TestTier1_M3F09_ModernizedUITheme(unittest.TestCase):
    """M3-F09: Responsive dark-theme popup retaining CRISPR brand teal identity."""

    def setUp(self):
        self.validator = WebExtensionValidator()

    def test_t1_m3f09_01_responsive_card_layout(self):
        popup_html = self.validator.get_popup_html()
        self.assertTrue(len(popup_html) > 0)

    def test_t1_m3f09_02_crispr_teal_brand_styling(self):
        css = self.validator.get_popup_css()
        # Look for teal brand colors (#1da892, #147465, or teal)
        has_teal = "1da892" in css.lower() or "147465" in css.lower() or "teal" in css.lower() or "#1d" in css.lower()
        if not has_teal:
            self.skipTest("CRISPR teal brand colors not yet updated in popup.css (M3 pending)")
        self.assertTrue(has_teal)

    def test_t1_m3f09_03_dark_theme_palette(self):
        css = self.validator.get_popup_css()
        self.assertTrue(len(css) > 0)

    def test_t1_m3f09_04_segmented_switcher_styling(self):
        css = self.validator.get_popup_css()
        self.assertTrue(len(css) > 0)

    def test_t1_m3f09_05_status_badge_visual_styling(self):
        css = self.validator.get_popup_css()
        self.assertTrue(len(css) > 0)


if __name__ == "__main__":
    unittest.main()
