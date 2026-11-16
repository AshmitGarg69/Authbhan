#!/usr/bin/env python3
"""
Adversarial Test Harness 1: Intranet Bypass Fuzzing
Tests:
- IP edge cases (0.0.0.0, 255.255.255.255, 127.0.0.2, 192.168.255.255, IPv6 mapped IPv4)
- Domain suffix spoofing prevention
- Zero failover to SOCKS5 for intranet targets under unreachable conditions
- Live proxy daemon verification with tracking SOCKS5 mock
"""

import asyncio
import importlib.util
import json
import os
import shutil
import socket
import struct
import tempfile
import time
import unittest
from pathlib import Path

# Load smart-proxy.py
SRC_PATH = Path("/home/ashmit/Code/smart-tunnel/src/smart-proxy.py")
spec = importlib.util.spec_from_file_location("smart_proxy", str(SRC_PATH))
proxy_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proxy_mod)

is_intranet = proxy_mod.is_intranet
parse_authority = proxy_mod.parse_authority
SmartProxyDaemon = proxy_mod.SmartProxyDaemon


class MockTrackingSOCKS5:
    """Mock SOCKS5 server that records every connection attempt."""
    def __init__(self):
        self.server = None
        self.port = None
        self.connections = []

    async def start(self):
        self.server = await asyncio.start_server(self.handle_client, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def handle_client(self, reader, writer):
        addr = writer.get_extra_info("peername")
        self.connections.append({"time": time.time(), "peer": addr})
        try:
            # SOCKS5 handshake
            auth = await reader.readexactly(3)
            writer.write(b"\x05\x00")
            await writer.drain()

            # Read req
            head = await reader.readexactly(4)
            atyp = head[3]
            target_host = ""
            if atyp == 0x01:
                ip_b = await reader.readexactly(4)
                target_host = socket.inet_ntoa(ip_b)
            elif atyp == 0x03:
                dlen = (await reader.readexactly(1))[0]
                domain_b = await reader.readexactly(dlen)
                target_host = domain_b.decode("latin1", errors="replace")
            elif atyp == 0x04:
                ip6_b = await reader.readexactly(16)
                target_host = socket.inet_ntop(socket.AF_INET6, ip6_b)
            port_b = await reader.readexactly(2)
            target_port = struct.unpack("!H", port_b)[0]
            self.connections[-1]["target"] = f"{target_host}:{target_port}"

            # Reply success
            writer.write(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x04\x38")
            await writer.drain()

            # Echo or hold
            while True:
                data = await reader.read(1024)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except Exception as e:
            self.connections[-1]["error"] = str(e)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()


class TestAdversarialIntranetBypass(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="adv_intra_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_fuzz_ip_edge_cases(self):
        """Test boundary IP addresses against is_intranet."""
        intranet_ips = [
            # Loopback
            "127.0.0.1", "127.0.0.2", "127.255.255.254", "127.255.255.255",
            # RFC 1918 class A
            "10.0.0.0", "10.0.0.1", "10.255.255.255",
            # RFC 1918 class B
            "172.16.0.0", "172.16.0.1", "172.31.255.255",
            # RFC 1918 class C
            "192.168.0.0", "192.168.1.1", "192.168.255.255", "192.168.77.84", "192.168.55.253",
            # Link local
            "169.254.0.1", "169.254.255.255",
            # Special / broadcast
            "0.0.0.0", "255.255.255.255",
            # IPv6 loopback and ULA
            "::1", "fe80::1", "fc00::1", "fd12:3456::1",
            # IPv6 mapped IPv4 private
            "::ffff:192.168.1.1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:172.16.0.1",
            # Bracketed representations with ports
            "[127.0.0.1]:80", "[::1]:443", "[::ffff:192.168.1.1]:8080",
            # Campus public subnet
            "45.127.199.1", "45.127.199.145", "45.127.199.254",
        ]
        for ip_str in intranet_ips:
            with self.subTest(ip=ip_str):
                self.assertTrue(is_intranet(ip_str), f"Expected {ip_str} to be intranet")

    def test_fuzz_ipv6_mapped_campus_public(self):
        """Check if IPv6 mapped campus public IP is recognized as intranet."""
        # e.g. ::ffff:45.127.199.145
        res = is_intranet("::ffff:45.127.199.145")
        # Record whether it matches or not
        print(f"\n[EMPIRICAL] is_intranet('::ffff:45.127.199.145'): {res}")

    def test_fuzz_public_ips_not_intranet(self):
        """Ensure external public IPs are never classified as intranet."""
        external_ips = [
            "1.1.1.1", "8.8.8.8", "103.55.74.154",
            "172.32.0.1", "172.15.255.255",
            "192.169.0.1", "11.0.0.1", "9.255.255.255",
            "45.127.198.255", "45.127.200.0", "45.127.200.1",
            "2606:4700:4700::1111", "2001:4860:4860::8888",
        ]
        for ip_str in external_ips:
            with self.subTest(ip=ip_str):
                self.assertFalse(is_intranet(ip_str), f"Expected {ip_str} NOT to be intranet")

    def test_domain_suffix_spoofing(self):
        """Adversarial spoofing attempts against iiitn.ac.in and localhost."""
        spoofed_domains = [
            "evil-iiitn.ac.in",
            "fakeiiitn.ac.in",
            "notiiitn.ac.in",
            "iiitn.ac.in.attacker.com",
            "iiitn.ac.in.evil.com",
            "pravesh-iiitn.ac.in",
            "pravesh.iiitn.ac.in.attacker.com",
            "sub.pravesh.iiitn.ac.in.phishing.org",
            "attackerlocalhost",
            "localhost.attacker.com",
            "evil-local",
            "attacker.lan.evil.com",
        ]
        for d in spoofed_domains:
            with self.subTest(domain=d):
                self.assertFalse(is_intranet(d), f"Spoofed domain {d} must NOT be intranet")

    def test_legitimate_campus_domain_variations(self):
        """Legitimate campus domains with various casing, subdomains, and trailing dots."""
        legit_domains = [
            "iiitn.ac.in",
            "pravesh.iiitn.ac.in",
            "moodle.iiitn.ac.in",
            "sub.portal.iiitn.ac.in",
            "IIITN.AC.IN",
            "PraVesh.IIITN.ac.in",
            "pravesh.iiitn.ac.in.",
            "localhost",
            "LOCALHOST",
            "app.localhost",
            "mydevice.local",
            "router.lan",
            "server.internal",
        ]
        for d in legit_domains:
            with self.subTest(domain=d):
                self.assertTrue(is_intranet(d), f"Legitimate domain {d} must be intranet")

    def test_zero_failover_to_socks5_for_intranet_connect(self):
        """Run proxy and verify ZERO failover to SOCKS5 for unreachable intranet destinations."""
        asyncio.run(self._async_test_zero_failover())

    async def _async_test_zero_failover(self):
        socks5 = MockTrackingSOCKS5()
        await socks5.start()

        daemon = SmartProxyDaemon(
            host="127.0.0.1",
            port=0,
            socks5_host="127.0.0.1",
            socks5_port=socks5.port,
            config_dir=self.test_dir,
        )
        await daemon.start()
        proxy_port = daemon.server.sockets[0].getsockname()[1]

        intranet_unreachable_targets = [
            "127.0.0.2:49991",
            "192.168.255.255:49992",
            "0.0.0.0:49993",
            "[::ffff:192.168.1.1]:49994",
            "pravesh.iiitn.ac.in:49995",
        ]

        try:
            for target in intranet_unreachable_targets:
                r, w = await asyncio.open_connection("127.0.0.1", proxy_port)
                w.write(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
                await w.drain()

                resp = await r.read(4096)
                w.close()
                await w.wait_closed()

                resp_str = resp.decode("latin1", errors="replace")
                # Assert 502 Bad Gateway
                self.assertIn("502 Bad Gateway", resp_str, f"Target {target} should get 502")
                self.assertIn("Intranet Destination Unreachable", resp_str, f"Target {target} should say Intranet Destination Unreachable")

                # Assert ZERO SOCKS5 connections triggered
                self.assertEqual(len(socks5.connections), 0, f"Target {target} caused SOCKS5 failover! Connections: {socks5.connections}")

            # Also check plain HTTP request
            r, w = await asyncio.open_connection("127.0.0.1", proxy_port)
            w.write(b"GET http://pravesh.iiitn.ac.in:49996/test HTTP/1.1\r\nHost: pravesh.iiitn.ac.in:49996\r\n\r\n")
            await w.drain()

            resp = await r.read(4096)
            w.close()
            await w.wait_closed()

            resp_str = resp.decode("latin1", errors="replace")
            self.assertIn("502 Bad Gateway", resp_str)
            self.assertIn("Intranet Destination Unreachable", resp_str)
            self.assertEqual(len(socks5.connections), 0, "Plain HTTP intranet request caused SOCKS5 failover!")

            # Verify blocked.json remains empty
            cache_file = os.path.join(self.test_dir, "blocked.json")
            with open(cache_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(len(data.get("blocked_domains", {})), 0, "Intranet destinations were written to blocked.json!")

            # Now test a spoofed domain (evil-iiitn.ac.in)
            # It SHOULD attempt to probe and then fail over to SOCKS5
            r, w = await asyncio.open_connection("127.0.0.1", proxy_port)
            w.write(b"CONNECT evil-iiitn.ac.in:443 HTTP/1.1\r\nHost: evil-iiitn.ac.in:443\r\n\r\n")
            await w.drain()

            resp = await r.read(4096)
            w.close()
            await w.wait_closed()

            # The spoofed domain MUST fail over to SOCKS5
            self.assertGreater(len(socks5.connections), 0, "Spoofed domain evil-iiitn.ac.in did not route to SOCKS5!")
            self.assertEqual(socks5.connections[-1]["target"], "evil-iiitn.ac.in:443")

        finally:
            await daemon.stop()
            await socks5.stop()


if __name__ == "__main__":
    unittest.main()
