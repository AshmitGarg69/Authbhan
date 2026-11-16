#!/usr/bin/env python3
"""
Adversarial Test Harness 2: SOCKS5 Protocol Edge Cases & Failure Modes
Tests:
- All RFC 1928 REP error codes (0x01-0x08, plus unassigned 0x09, 0xFF)
- Invalid VER in reply (0x04)
- Bound address types: ATYP 0x01 (IPv4), 0x03 (Domain), 0x04 (IPv6), and unknown (0x09)
- Truncated responses at every negotiation phase
- Dropped connections at every negotiation phase
- Slow drip / negotiation timeout
- Proxy daemon client response verification: does the client receive 502 Bad Gateway or unhandled drop?
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

SOCKS5Client = proxy_mod.SOCKS5Client
SOCKS5Error = proxy_mod.SOCKS5Error
SmartProxyDaemon = proxy_mod.SmartProxyDaemon


class ConfigurableMockSOCKS5:
    """Mock SOCKS5 server with programmable failure modes."""

    def __init__(self, mode="normal", rep_code=0x00, atyp=0x01):
        self.server = None
        self.port = None
        self.mode = mode
        self.rep_code = rep_code
        self.atyp = atyp

    async def start(self):
        self.server = await asyncio.start_server(self.handle_client, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def handle_client(self, reader, writer):
        try:
            if self.mode == "drop_immediately":
                writer.close()
                await writer.wait_closed()
                return

            # Read method negotiation
            ver_methods = await reader.read(10)
            if not ver_methods:
                writer.close()
                return

            if self.mode == "drop_after_method_req":
                writer.close()
                await writer.wait_closed()
                return

            if self.mode == "truncated_method_resp":
                writer.write(b"\x05")  # Only 1 byte
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            if self.mode == "invalid_method_version":
                writer.write(b"\x04\x00")  # SOCKS4 in method resp
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            if self.mode == "auth_rejected":
                writer.write(b"\x05\xFF")  # No acceptable auth methods
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            if self.mode == "slow_hang":
                await asyncio.sleep(10.0)
                return

            # Normal method response: VER=5, METHOD=0
            writer.write(b"\x05\x00")
            await writer.drain()

            if self.mode == "drop_after_method_resp":
                writer.close()
                await writer.wait_closed()
                return

            # Read connect request
            req = await reader.read(512)
            if not req:
                writer.close()
                return

            if self.mode == "drop_after_conn_req":
                writer.close()
                await writer.wait_closed()
                return

            if self.mode == "truncated_reply_head":
                writer.write(b"\x05\x00\x00")  # Only 3 bytes of 4-byte header
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            if self.mode == "invalid_reply_ver":
                writer.write(b"\x04\x00\x00\x01\x7f\x00\x00\x01\x10\x00")
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            if self.mode == "invalid_reply_atyp":
                writer.write(b"\x05\x00\x00\x09")  # Unknown atyp 0x09
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            if self.mode == "truncated_bnd_addr":
                # atyp 0x01, but only 2 bytes of IP
                writer.write(b"\x05\x00\x00\x01\x7f\x00")
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            if self.mode == "rep_error":
                # Send error reply
                writer.write(bytes([0x05, self.rep_code, 0x00, 0x01, 127, 0, 0, 1, 0, 0]))
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            # Success with specified ATYP
            if self.atyp == 0x01:
                writer.write(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x04\x38")
            elif self.atyp == 0x03:
                writer.write(b"\x05\x00\x00\x03\x09localhost\x04\x38")
            elif self.atyp == 0x04:
                writer.write(b"\x05\x00\x00\x04" + b"\x00" * 15 + b"\x01" + b"\x04\x38")
            await writer.drain()

            # Normal echo stream
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                writer.write(data)
                await writer.drain()

        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()


class TestAdversarialSOCKS5(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="adv_socks5_")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_socks5_rep_error_codes(self):
        """Test all RFC 1928 REP error codes 0x01-0x08, plus 0x09 and 0xFF."""
        asyncio.run(self._async_test_rep_error_codes())

    async def _async_test_rep_error_codes(self):
        for rep in [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xFF]:
            mock = ConfigurableMockSOCKS5(mode="rep_error", rep_code=rep)
            await mock.start()
            try:
                client = SOCKS5Client("127.0.0.1", mock.port)
                with self.assertRaises(SOCKS5Error) as ctx:
                    await client.connect("target.com", 443, timeout=2.0)
                self.assertEqual(ctx.exception.rep_code, rep, f"Expected rep_code {rep}")
                self.assertIn(f"0x{rep:02x}", str(ctx.exception))
            finally:
                await mock.stop()

    def test_socks5_bound_address_types(self):
        """Verify successful negotiation with bound address types ATYP 0x01, 0x03, 0x04."""
        asyncio.run(self._async_test_bound_atyp())

    async def _async_test_bound_atyp(self):
        for atyp in [0x01, 0x03, 0x04]:
            mock = ConfigurableMockSOCKS5(mode="normal", atyp=atyp)
            await mock.start()
            try:
                client = SOCKS5Client("127.0.0.1", mock.port)
                r, w = await client.connect("target.com", 443, timeout=2.0)
                w.write(b"PING")
                await w.drain()
                resp = await r.read(4)
                self.assertEqual(resp, b"PING")
                w.close()
                await w.wait_closed()
            finally:
                await mock.stop()

    def test_socks5_truncated_and_drop_exceptions(self):
        """Test client reaction to truncated responses and mid-negotiation drops."""
        asyncio.run(self._async_test_truncated_and_drops())

    async def _async_test_truncated_and_drops(self):
        failure_modes = [
            "drop_immediately",
            "drop_after_method_req",
            "drop_after_method_resp",
            "drop_after_conn_req",
            "truncated_method_resp",
            "truncated_reply_head",
            "truncated_bnd_addr",
            "invalid_method_version",
            "auth_rejected",
            "invalid_reply_ver",
            "invalid_reply_atyp",
        ]
        for mode in failure_modes:
            mock = ConfigurableMockSOCKS5(mode=mode)
            await mock.start()
            try:
                client = SOCKS5Client("127.0.0.1", mock.port)
                # We expect an exception (either SOCKS5Error or IncompleteReadError or OSError)
                try:
                    await client.connect("target.com", 443, timeout=1.0)
                    self.fail(f"Mode {mode} should have raised an exception!")
                except Exception as e:
                    print(f"[EMPIRICAL SOCKS5Client] mode={mode} -> raised {type(e).__name__}: {e}")
            finally:
                await mock.stop()

    def test_proxy_daemon_behavior_on_socks5_failures(self):
        """
        Adversarial test against SmartProxyDaemon:
        When upstream SOCKS5 drops or truncates, does the proxy daemon return 502 to the browser
        or does it ungracefully close the client connection without an HTTP response?
        """
        asyncio.run(self._async_test_proxy_on_socks5_failures())

    async def _async_test_proxy_on_socks5_failures(self):
        modes_to_test = [
            "rep_error",            # SOCKS5 returns 0x05 Connection Refused
            "drop_immediately",     # SOCKS5 drops before handshake
            "truncated_method_resp",# SOCKS5 sends 1 byte then closes
            "drop_after_conn_req",  # SOCKS5 drops after receiving CONNECT req
            "truncated_reply_head", # SOCKS5 sends 3 bytes of 4-byte reply
            "slow_hang",            # SOCKS5 hangs (timeout)
        ]

        print("\n--- Testing SmartProxyDaemon Client Responses under SOCKS5 Failures ---")
        for mode in modes_to_test:
            mock = ConfigurableMockSOCKS5(mode=mode, rep_code=0x05)
            await mock.start()

            # Pre-seed blocked.json with "blocked-site.com" so it routes via TUNNEL immediately
            cache_file = os.path.join(self.test_dir, f"blocked_{mode}.json")
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump({
                    "version": 1,
                    "updated_at": "2026-11-13T00:00:00Z",
                    "blocked_domains": {
                        "blocked-site.com": {"reason": "test", "hits": 1}
                    },
                    "custom_overrides": {}
                }, f)

            daemon = SmartProxyDaemon(
                host="127.0.0.1",
                port=0,
                socks5_host="127.0.0.1",
                socks5_port=mock.port,
                config_dir=self.test_dir,
            )
            daemon.cache_path = cache_file
            daemon.cache_mgr = proxy_mod.CacheManager(cache_file)
            await daemon.start()
            proxy_port = daemon.server.sockets[0].getsockname()[1]

            try:
                # Send CONNECT request to proxy
                r, w = await asyncio.open_connection("127.0.0.1", proxy_port)
                w.write(b"CONNECT blocked-site.com:443 HTTP/1.1\r\nHost: blocked-site.com:443\r\n\r\n")
                await w.drain()

                # Read response from proxy
                try:
                    resp = await asyncio.wait_for(r.read(4096), timeout=3.0)
                except asyncio.TimeoutError:
                    resp = b""

                w.close()
                await w.wait_closed()

                resp_str = resp.decode("latin1", errors="replace")
                print(f"[EMPIRICAL DAEMON] mode={mode} -> Client received:\n  First 60 chars: {repr(resp_str[:60])}")
                has_http_502 = "502 Bad Gateway" in resp_str
                print(f"  Got HTTP 502 Bad Gateway? {has_http_502}")

            finally:
                await daemon.stop()
                await mock.stop()


if __name__ == "__main__":
    unittest.main()
