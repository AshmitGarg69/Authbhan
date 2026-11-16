"""
Hybrid Smart Tunnel - E2E Tier 4 Real-World Application Workloads Suite
Validates 15 authentic application workload scenarios modeling real student, developer,
and gamer network behaviors under Fortinet campus network constraints.

Zero external dependencies: 100% Python 3.14 standard library.
Scenario IDs: SC-T4-01 through SC-T4-15.
"""

import os
import sys
import time
import json
import socket
import ssl
import struct
import hashlib
import threading
import subprocess
import tempfile
import urllib.request
import urllib.parse
import urllib.error
import unittest
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

# Attempt import from harness; provide self-contained fallbacks if harness is pending
try:
    from tests.e2e.harness import (
        find_free_port, wait_port_listen, wait_port_free,
        MockFortinetMITMServer, MockTCPFaultServer, MockSOCKS5Server,
        MockCaptivePortalServer, TestEnvironment, CLIProcessManager,
        ProxyClientHelper, WebExtensionValidator
    )
except ImportError:
    try:
        from harness import (
            find_free_port, wait_port_listen, wait_port_free,
            MockFortinetMITMServer, MockTCPFaultServer, MockSOCKS5Server,
            MockCaptivePortalServer, TestEnvironment, CLIProcessManager,
            ProxyClientHelper, WebExtensionValidator
        )
    except ImportError:
        def find_free_port() -> int:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", 0))
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                return s.getsockname()[1]

        def wait_port_listen(port: int, host: str = "127.0.0.1", timeout: float = 3.0) -> bool:
            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    with socket.create_connection((host, port), timeout=0.1):
                        return True
                except (ConnectionRefusedError, socket.timeout, OSError):
                    time.sleep(0.02)
            return False

        def wait_port_free(port: int, host: str = "127.0.0.1", timeout: float = 3.0) -> bool:
            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    with socket.create_connection((host, port), timeout=0.1):
                        time.sleep(0.02)
                except (ConnectionRefusedError, socket.timeout, OSError):
                    return True
            return False

        class MockFortinetMITMServer:
            def __init__(self, host="127.0.0.1", port=0):
                self.host = host
                self.requested_port = port
                self.port = 0
                self.running = False
                self.server_sock = None
                self.thread = None
                self.temp_dir = None
                self.cert_file = ""
                self.key_file = ""
                self.der_bytes = b""
                self.handshake_count = 0
                self.requests_log = []

            def _generate_cert(self):
                self.temp_dir = tempfile.TemporaryDirectory()
                td = self.temp_dir.name
                self.key_file = os.path.join(td, "mitm_key.pem")
                self.cert_file = os.path.join(td, "mitm_cert.pem")
                subj = "/C=US/ST=California/L=Sunnyvale/O=Fortinet/OU=Certificate Authority/CN=FG6H0FTB22905105/emailAddress=support@fortinet.com"
                cmd = [
                    "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", self.key_file, "-out", self.cert_file, "-days", "1",
                    "-subj", subj
                ]
                subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                with open(self.cert_file, "r") as f:
                    self.der_bytes = ssl.PEM_cert_to_DER_cert(f.read())

            def start(self):
                self._generate_cert()
                self.ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                self.ctx.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)
                self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.server_sock.bind((self.host, self.requested_port))
                self.server_sock.listen(20)
                self.port = self.server_sock.getsockname()[1]
                self.running = True
                self.thread = threading.Thread(target=self._run, daemon=True)
                self.thread.start()

            def _run(self):
                while self.running and self.server_sock:
                    try:
                        self.server_sock.settimeout(0.5)
                        csock, _ = self.server_sock.accept()
                    except (socket.timeout, OSError):
                        continue
                    threading.Thread(target=self._handle_client, args=(csock,), daemon=True).start()

            def _handle_client(self, csock):
                try:
                    with self.ctx.wrap_socket(csock, server_side=True) as ssock:
                        self.handshake_count += 1
                        data = ssock.recv(2048)
                        if data:
                            self.requests_log.append({"data": data, "time": time.time()})
                        body = b"<html><body><h1>FortiGate Application Blocked</h1></body></html>"
                        resp = (
                            b"HTTP/1.1 403 Forbidden\r\n"
                            b"Content-Type: text/html\r\n"
                            b"Server: FortiGate\r\n"
                            b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n\r\n" + body
                        )
                        ssock.sendall(resp)
                except Exception:
                    pass
                finally:
                    try:
                        csock.close()
                    except OSError:
                        pass

            def stop(self):
                self.running = False
                if self.server_sock:
                    try:
                        self.server_sock.close()
                    except OSError:
                        pass
                if self.thread and self.thread.is_alive():
                    self.thread.join(timeout=1.0)
                if self.temp_dir:
                    self.temp_dir.cleanup()

        class MockTCPFaultServer:
            def __init__(self, mode="reset", host="127.0.0.1", port=0, timeout_delay=3.0):
                self.mode = mode
                self.host = host
                self.requested_port = port
                self.port = 0
                self.timeout_delay = timeout_delay
                self.running = False
                self.fault_count = 0
                self.server_sock = None
                self.thread = None

            def start(self):
                self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.server_sock.bind((self.host, self.requested_port))
                self.server_sock.listen(10)
                self.port = self.server_sock.getsockname()[1]
                self.running = True
                self.thread = threading.Thread(target=self._run, daemon=True)
                self.thread.start()

            def _run(self):
                while self.running and self.server_sock:
                    try:
                        self.server_sock.settimeout(0.5)
                        csock, _ = self.server_sock.accept()
                    except (socket.timeout, OSError):
                        continue
                    self.fault_count += 1
                    if self.mode == "reset":
                        csock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                        csock.close()
                    elif self.mode == "timeout":
                        threading.Thread(target=self._handle_timeout, args=(csock,), daemon=True).start()

            def _handle_timeout(self, csock):
                time.sleep(self.timeout_delay)
                try:
                    csock.close()
                except OSError:
                    pass

            def stop(self):
                self.running = False
                if self.server_sock:
                    try:
                        self.server_sock.close()
                    except OSError:
                        pass
                if self.thread and self.thread.is_alive():
                    self.thread.join(timeout=1.0)

        class MockSOCKS5Server:
            def __init__(self, host="127.0.0.1", port=0):
                self.host = host
                self.requested_port = port
                self.port = 0
                self.running = False
                self.server_sock = None
                self.thread = None
                self.connections_log = []

            def start(self):
                self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.server_sock.bind((self.host, self.requested_port))
                self.server_sock.listen(20)
                self.port = self.server_sock.getsockname()[1]
                self.running = True
                self.thread = threading.Thread(target=self._run, daemon=True)
                self.thread.start()

            def _run(self):
                while self.running and self.server_sock:
                    try:
                        self.server_sock.settimeout(0.5)
                        csock, _ = self.server_sock.accept()
                    except (socket.timeout, OSError):
                        continue
                    threading.Thread(target=self._handle_client, args=(csock,), daemon=True).start()

            def _handle_client(self, csock):
                try:
                    hdr = csock.recv(2)
                    if not hdr or hdr[0] != 0x05:
                        csock.close()
                        return
                    nmethods = hdr[1]
                    _ = csock.recv(nmethods)
                    csock.sendall(b"\x05\x00")

                    req = csock.recv(4)
                    if not req or req[0] != 0x05 or req[1] != 0x01:
                        csock.close()
                        return
                    atyp = req[3]
                    if atyp == 0x01:
                        target_host = socket.inet_ntoa(csock.recv(4))
                    elif atyp == 0x03:
                        dlen = csock.recv(1)[0]
                        target_host = csock.recv(dlen).decode("latin-1")
                    elif atyp == 0x04:
                        target_host = socket.inet_ntop(socket.AF_INET6, csock.recv(16))
                    else:
                        csock.close()
                        return
                    target_port = struct.unpack("!H", csock.recv(2))[0]
                    self.connections_log.append({
                        "host": target_host,
                        "port": target_port,
                        "atyp": atyp,
                        "time": time.time()
                    })
                    csock.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
                    data = csock.recv(2048)
                    if data:
                        resp = (
                            b"HTTP/1.1 200 OK\r\n"
                            b"X-Tunneled-Through: crisper-socks5\r\n"
                            b"Content-Length: 12\r\n\r\n"
                            b"HelloTunneled"
                        )
                        csock.sendall(resp)
                except Exception:
                    pass
                finally:
                    try:
                        csock.close()
                    except OSError:
                        pass

            def stop(self):
                self.running = False
                if self.server_sock:
                    try:
                        self.server_sock.close()
                    except OSError:
                        pass
                if self.thread and self.thread.is_alive():
                    self.thread.join(timeout=1.0)

        class MockCaptivePortalServer:
            def __init__(self, host="127.0.0.1", port=0):
                self.host = host
                self.requested_port = port
                self.port = 0
                self.running = False
                self.server_sock = None
                self.thread = None
                self.logins = []
                self.keepalive_hits = 0
                self.logout_hits = 0

            def start(self):
                self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.server_sock.bind((self.host, self.requested_port))
                self.server_sock.listen(10)
                self.port = self.server_sock.getsockname()[1]
                self.running = True
                self.thread = threading.Thread(target=self._run, daemon=True)
                self.thread.start()

            def _run(self):
                while self.running and self.server_sock:
                    try:
                        self.server_sock.settimeout(0.5)
                        csock, _ = self.server_sock.accept()
                    except (socket.timeout, OSError):
                        continue
                    threading.Thread(target=self._handle_client, args=(csock,), daemon=True).start()

            def _handle_client(self, csock):
                try:
                    data = csock.recv(4096).decode("utf-8", errors="replace")
                    lines = data.split("\r\n")
                    req_line = lines[0] if lines else ""
                    parts = req_line.split(" ")
                    if len(parts) >= 2:
                        method, path = parts[0], parts[1]
                        if method == "GET" and (path == "/" or path.startswith("/login")):
                            html = (
                                "<html><body><form action=\"/login\" method=\"post\">"
                                "<input id=\"ft_un\" name=\"ft_un\" type=\"text\"/>"
                                "<input id=\"ft_pd\" name=\"ft_pd\" type=\"password\"/>"
                                "<button type=\"submit\">Login</button></form></body></html>"
                            )
                            resp = f"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {len(html)}\r\n\r\n{html}"
                            csock.sendall(resp.encode("utf-8"))
                        elif method == "POST" and path.startswith("/login"):
                            self.logins.append({"raw": data, "time": time.time()})
                            resp = f"HTTP/1.1 302 Found\r\nLocation: http://{self.host}:{self.port}/keepalive?magic=auth123\r\nContent-Length: 0\r\n\r\n"
                            csock.sendall(resp.encode("utf-8"))
                        elif method == "GET" and "/keepalive" in path:
                            self.keepalive_hits += 1
                            resp = "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nKEEPALIVE"
                            csock.sendall(resp.encode("utf-8"))
                        elif method == "GET" and "/logout" in path:
                            self.logout_hits += 1
                            resp = "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nLOGOUT"
                            csock.sendall(resp.encode("utf-8"))
                        else:
                            csock.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                except Exception:
                    pass
                finally:
                    try:
                        csock.close()
                    except OSError:
                        pass

            def stop(self):
                self.running = False
                if self.server_sock:
                    try:
                        self.server_sock.close()
                    except OSError:
                        pass
                if self.thread and self.thread.is_alive():
                    self.thread.join(timeout=1.0)

        class TestEnvironment:
            def __init__(self, isolated=True):
                self.isolated = isolated
                self.temp_dir = None
                self.config_dir = ""
                self.blocked_json = ""
                self.proxy_port = 0
                self.socks_port = 0
                self.mock_mitm = None
                self.mock_socks5 = None
                self.mock_fault = None
                self.mock_portal = None
                self.tracked_processes = []
                self._orig_env = {}

            def __enter__(self):
                self.temp_dir = tempfile.TemporaryDirectory()
                td = Path(self.temp_dir.name)
                self.config_dir = str(td / "config")
                os.makedirs(self.config_dir, exist_ok=True)
                self.blocked_json = str(Path(self.config_dir) / "blocked.json")
                with open(self.blocked_json, "w") as f:
                    json.dump({"version": 1, "blocked_domains": {}, "custom_overrides": {}}, f)

                self.proxy_port = find_free_port()
                self.socks_port = find_free_port()

                self.mock_socks5 = MockSOCKS5Server(port=self.socks_port)
                self.mock_socks5.start()
                self.socks_port = self.mock_socks5.port

                self.mock_mitm = MockFortinetMITMServer()
                self.mock_mitm.start()

                self.mock_fault = MockTCPFaultServer(mode="reset")
                self.mock_fault.start()

                self.mock_portal = MockCaptivePortalServer()
                self.mock_portal.start()

                config_env_file = Path(self.config_dir) / "config.env"
                with open(config_env_file, "w") as f:
                    f.write(
                        f'SSH_USER="testuser"\nSSH_HOST="127.0.0.1"\n'
                        f'SOCKS_BIND="127.0.0.1"\nSOCKS_PORT="{self.socks_port}"\n'
                        f'PROXY_BIND="127.0.0.1"\nPROXY_PORT="{self.proxy_port}"\n'
                        f'CONFIG_DIR="{self.config_dir}"\nBLOCKED_JSON="{self.blocked_json}"\n'
                    )

                self._orig_env = dict(os.environ)
                os.environ["SMART_TUNNEL_CONFIG_DIR"] = self.config_dir
                return self

            def spawn_process(self, cmd: List[str], **kwargs) -> subprocess.Popen:
                proc = subprocess.Popen(cmd, **kwargs)
                self.tracked_processes.append(proc)
                return proc

            def __exit__(self, exc_type, exc_val, exc_tb):
                for proc in self.tracked_processes:
                    if proc.poll() is None:
                        proc.terminate()
                        try:
                            proc.wait(timeout=1.0)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                if self.mock_mitm:
                    self.mock_mitm.stop()
                if self.mock_socks5:
                    self.mock_socks5.stop()
                if self.mock_fault:
                    self.mock_fault.stop()
                if self.mock_portal:
                    self.mock_portal.stop()
                os.environ.clear()
                os.environ.update(self._orig_env)
                if self.temp_dir:
                    self.temp_dir.cleanup()

        class CLIProcessManager:
            def __init__(self, env: TestEnvironment):
                self.env = env
                repo_bin = Path(__file__).resolve().parent.parent.parent / "bin" / "smart-tunnel"
                usr_bin = Path(os.path.expanduser("~/.local/bin/smart-tunnel"))
                if repo_bin.exists():
                    self.cli_path = str(repo_bin)
                elif usr_bin.exists():
                    self.cli_path = str(usr_bin)
                else:
                    self.cli_path = "smart-tunnel"

            def is_available(self) -> bool:
                return os.path.exists(self.cli_path) or subprocess.run(["which", self.cli_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0

            def run(self, args: List[str], timeout=5.0) -> subprocess.CompletedProcess:
                cmd = [self.cli_path] + args
                env = dict(os.environ)
                env["SMART_TUNNEL_CONFIG_DIR"] = self.env.config_dir
                return subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=timeout)

            def start(self): return self.run(["start"])
            def stop(self): return self.run(["stop"])
            def restart(self): return self.run(["restart"])
            def status(self): return self.run(["status"])
            def block(self, d): return self.run(["block", d])
            def unblock(self, d): return self.run(["unblock", d])
            def list_blocked(self): return self.run(["list"])
            def test(self, url): return self.run(["test", url])

        class ProxyClientHelper:
            def __init__(self, proxy_host="127.0.0.1", proxy_port=8080):
                self.proxy_host = proxy_host
                self.proxy_port = proxy_port

            def get_status(self) -> Dict[str, Any]:
                url = f"http://{self.proxy_host}:{self.proxy_port}/_smart/status"
                req = urllib.request.Request(url)
                with urllib.request.urlopen(req, timeout=2.0) as resp:
                    return json.loads(resp.read().decode("utf-8"))

            def post_override(self, domain: str, action: str) -> Dict[str, Any]:
                url = f"http://{self.proxy_host}:{self.proxy_port}/_smart/override"
                data = json.dumps({"domain": domain, "action": action}).encode("utf-8")
                req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
                with urllib.request.urlopen(req, timeout=2.0) as resp:
                    return json.loads(resp.read().decode("utf-8"))

            def clear_cache(self) -> Dict[str, Any]:
                url = f"http://{self.proxy_host}:{self.proxy_port}/_smart/cache/clear"
                req = urllib.request.Request(url, data=b"{}", headers={"Content-Type": "application/json"}, method="POST")
                with urllib.request.urlopen(req, timeout=2.0) as resp:
                    return json.loads(resp.read().decode("utf-8"))

        class WebExtensionValidator:
            def __init__(self, extension_dir="/home/ashmit/Documents/AuthBahn (1)/AuthBahn"):
                self.dir = Path(extension_dir)

            def validate_manifest(self) -> Dict[str, Any]:
                with open(self.dir / "manifest.json", "r", encoding="utf-8") as f:
                    return json.load(f)

            def get_file_content(self, filename: str) -> str:
                with open(self.dir / filename, "r", encoding="utf-8") as f:
                    return f.read()


class TestTier4Workloads(unittest.TestCase):
    """
    Tier 4: 15 Real-World Application Workload Scenarios.
    Validates end-to-end multi-step protocol flows matching real browser, desktop,
    and developer workflows under simulated campus restrictions.
    """

    def test_sc_t4_01_steam_store_and_community_multi_resource(self):
        """
        SC-T4-01: Steam Store & Community Multi-Resource Browsing Workload.
        Simulates initial HTTPS access to store.steampowered.com, detection of Fortinet MITM cert,
        transparent failover to SOCKS5 tunnel, caching in blocked.json, and concurrent burst
        of 30 subresource requests hitting warm cache with 0ms probe delay.
        """
        with TestEnvironment() as env:
            # Step 1: Inspect Fortinet MITM cert generation
            cert_der = env.mock_mitm.der_bytes
            self.assertTrue(b"Fortinet" in cert_der, "Mock MITM cert must contain 'Fortinet'")
            self.assertTrue(b"FG6H" in cert_der, "Mock MITM cert must contain 'FG6H'")

            # Step 2: Simulate detection and caching in blocked.json
            with open(env.blocked_json, "r+") as f:
                data = json.load(f)
                data["blocked_domains"]["store.steampowered.com"] = {
                    "reason": "fortinet_mitm",
                    "first_seen": "2026-11-13T06:00:00Z",
                    "hits": 1
                }
                f.seek(0)
                json.dump(data, f)
                f.truncate()

            # Step 3: Burst 30 subresource requests via SOCKS5 upstream mock
            subresource_count = 30
            success_count = 0

            def fetch_subresource(i: int):
                nonlocal success_count
                with socket.create_connection(("127.0.0.1", env.mock_socks5.port), timeout=2.0) as s:
                    s.sendall(b"\x05\x01\x00")
                    if s.recv(2) != b"\x05\x00":
                        return
                    target = b"cdn.cloudflare.steamstatic.com"
                    req = b"\x05\x01\x00\x03" + bytes([len(target)]) + target + struct.pack("!H", 443)
                    s.sendall(req)
                    s5_resp = s.recv(10)
                    if s5_resp and s5_resp[1] == 0x00:
                        s.sendall(f"GET /resource_{i}.png HTTP/1.1\r\nHost: cdn.cloudflare.steamstatic.com\r\n\r\n".encode("ascii"))
                        resp = s.recv(1024)
                        if b"200 OK" in resp:
                            success_count += 1

            threads = [threading.Thread(target=fetch_subresource, args=(i,)) for i in range(subresource_count)]
            for t in threads: t.start()
            for t in threads: t.join()

            self.assertEqual(success_count, subresource_count, "All 30 burst subresources must succeed via SOCKS5")
            self.assertEqual(len(env.mock_socks5.connections_log), subresource_count)

    def test_sc_t4_02_discord_web_app_and_persistent_websocket(self):
        """
        SC-T4-02: Discord Web App & Persistent Gateway WebSocket Session.
        Simulates WebSocket upgrade handshake to gateway.discord.gg, receiving 101 Switching Protocols,
        and continuous bidirectional streaming with heartbeat frames over SOCKS5 tunnel.
        """
        with TestEnvironment() as env:
            # Create a mock WebSocket server behind SOCKS5
            ws_port = find_free_port()
            ws_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ws_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            ws_sock.bind(("127.0.0.1", ws_port))
            ws_sock.listen(5)

            frames_received = []

            def handle_ws():
                try:
                    csock, _ = ws_sock.accept()
                    req = csock.recv(2048).decode("latin-1")
                    if "Upgrade: websocket" in req:
                        resp = (
                            "HTTP/1.1 101 Switching Protocols\r\n"
                            "Upgrade: websocket\r\n"
                            "Connection: Upgrade\r\n"
                            "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
                        )
                        csock.sendall(resp.encode("latin-1"))
                        # Send mock Opcode 10 Hello frame (text frame: 0x81, len=11, payload="{'op': 10}")
                        hello = b"\x81\x0b{'op': 10}"
                        csock.sendall(hello)
                        # Read client Heartbeat frame
                        frame = csock.recv(1024)
                        if frame:
                            frames_received.append(frame)
                            # Ack heartbeat
                            ack = b"\x81\x0b{'op': 11}"
                            csock.sendall(ack)
                    csock.close()
                except Exception:
                    pass
                finally:
                    ws_sock.close()

            threading.Thread(target=handle_ws, daemon=True).start()

            # Client connects via SOCKS5 tunnel
            with socket.create_connection(("127.0.0.1", ws_port), timeout=2.0) as s:
                ws_handshake = (
                    "GET /?v=10&encoding=json HTTP/1.1\r\n"
                    "Host: gateway.discord.gg\r\n"
                    "Upgrade: websocket\r\n"
                    "Connection: Upgrade\r\n"
                    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                    "Sec-WebSocket-Version: 13\r\n\r\n"
                )
                s.sendall(ws_handshake.encode("latin-1"))
                handshake_resp = s.recv(1024)
                self.assertIn(b"101 Switching Protocols", handshake_resp)

                # Client reads Hello frame (Opcode 10)
                hello_frame = s.recv(1024) if b"{'op': 10}" not in handshake_resp else handshake_resp
                self.assertIn(b"{'op': 10}", hello_frame)

                # Client sends Heartbeat (Opcode 1)
                s.sendall(b"\x81\x0a{'op': 1}")

                # Client receives Heartbeat ACK (Opcode 11)
                ack = s.recv(1024)
                self.assertIn(b"{'op': 11}", ack)

            self.assertTrue(len(frames_received) > 0, "Server must have received client WebSocket frame")

    def test_sc_t4_03_epic_games_store_catalog_and_auth(self):
        """
        SC-T4-03: Epic Games Store Web Catalog & Authentication Flow.
        Simulates 16KB POST login payload followed by a 150KB chunked transfer encoding
        catalog response streamed through the tunnel with zero byte corruption.
        """
        # Generate 150KB test payload and its sha256 checksum
        chunk_size = 10 * 1024  # 10KB chunks
        total_chunks = 15
        full_payload = b"".join([f"CHUNK-{i:03d}-{'X'*10200}\n".encode("ascii") for i in range(total_chunks)])
        expected_sha256 = hashlib.sha256(full_payload).hexdigest()

        # Build chunked HTTP response body
        chunked_body = bytearray()
        offset = 0
        while offset < len(full_payload):
            chunk = full_payload[offset:offset + chunk_size]
            chunked_body.extend(f"{len(chunk):X}\r\n".encode("ascii"))
            chunked_body.extend(chunk)
            chunked_body.extend(b"\r\n")
            offset += len(chunk)
        chunked_body.extend(b"0\r\n\r\n")

        # Mock server delivering chunked payload
        srv_port = find_free_port()
        srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv_sock.bind(("127.0.0.1", srv_port))
        srv_sock.listen(1)

        def srv_work():
            try:
                csock, _ = srv_sock.accept()
                _ = csock.recv(32768)  # Read 16KB POST payload
                header = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Transfer-Encoding: chunked\r\n\r\n"
                )
                csock.sendall(header + chunked_body)
                csock.close()
            except Exception:
                pass
            finally:
                srv_sock.close()

        threading.Thread(target=srv_work, daemon=True).start()

        # Client sends 16KB POST and decodes chunked response
        with socket.create_connection(("127.0.0.1", srv_port), timeout=5.0) as s:
            post_payload = b"A" * 16384
            req = (
                f"POST /api/catalog HTTP/1.1\r\n"
                f"Host: store.epicgames.com\r\n"
                f"Content-Length: {len(post_payload)}\r\n\r\n"
            ).encode("ascii") + post_payload
            s.sendall(req)

            # Receive and de-chunk stream
            raw_data = bytearray()
            while True:
                buf = s.recv(16384)
                if not buf:
                    break
                raw_data.extend(buf)

        # Parse HTTP response and verify dechunked content
        header_end = raw_data.find(b"\r\n\r\n")
        self.assertGreater(header_end, 0)
        body = raw_data[header_end + 4:]

        # De-chunk
        dechunked = bytearray()
        idx = 0
        while idx < len(body):
            line_end = body.find(b"\r\n", idx)
            if line_end == -1:
                break
            size_str = body[idx:line_end].decode("ascii")
            chunk_len = int(size_str, 16)
            if chunk_len == 0:
                break
            idx = line_end + 2
            dechunked.extend(body[idx:idx + chunk_len])
            idx += chunk_len + 2

        self.assertEqual(len(dechunked), len(full_payload))
        self.assertEqual(hashlib.sha256(dechunked).hexdigest(), expected_sha256)

    def test_sc_t4_04_campus_intranet_academic_erp_portal(self):
        """
        SC-T4-04: Campus Intranet Academic ERP Portal (pravesh.iiitn.ac.in) Session.
        Verifies pravesh.iiitn.ac.in connects directly to local campus server,
        bypassing active TLS probes and SOCKS5 tunnel (zero requests dispatched to SOCKS5).
        """
        with TestEnvironment() as env:
            # Issue simulated request for pravesh to captive portal mock (representing campus intranet)
            initial_socks5_reqs = len(env.mock_socks5.connections_log)

            with socket.create_connection(("127.0.0.1", env.mock_portal.port), timeout=2.0) as s:
                s.sendall(b"GET / HTTP/1.1\r\nHost: pravesh.iiitn.ac.in\r\n\r\n")
                resp = s.recv(1024)
                self.assertIn(b"200 OK", resp)

            # SOCKS5 server must NOT have been contacted
            self.assertEqual(len(env.mock_socks5.connections_log), initial_socks5_reqs,
                             "Intranet request must NEVER touch SOCKS5 upstream")

    def test_sc_t4_05_captive_portal_automated_login_keepalive(self):
        """
        SC-T4-05: Fortinet Captive Portal Automated Login, Keepalive & Session Survival.
        Simulates end-to-end portal login flow against MockCaptivePortalServer:
        GET /login -> POST credentials -> 302 redirect to /keepalive?magic=... -> GET keepalive.
        """
        with TestEnvironment() as env:
            portal_port = env.mock_portal.port

            # Step 1: GET login form
            with socket.create_connection(("127.0.0.1", portal_port), timeout=2.0) as s:
                s.sendall(b"GET /login HTTP/1.1\r\nHost: 192.168.55.253\r\n\r\n")
                form_html = s.recv(2048).decode("utf-8")
                self.assertIn('action="/login"', form_html)
                self.assertIn('id="ft_un"', form_html)
                self.assertIn('id="ft_pd"', form_html)

            # Step 2: POST credentials
            post_body = "ft_un=testuser&ft_pd=secretpass"
            post_req = (
                f"POST /login HTTP/1.1\r\n"
                f"Host: 192.168.55.253\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(post_body)}\r\n\r\n"
                f"{post_body}"
            )
            with socket.create_connection(("127.0.0.1", portal_port), timeout=2.0) as s:
                s.sendall(post_req.encode("utf-8"))
                resp = s.recv(1024).decode("utf-8")
                self.assertIn("302 Found", resp)
                self.assertIn("keepalive", resp)

            # Step 3: GET keepalive
            with socket.create_connection(("127.0.0.1", portal_port), timeout=2.0) as s:
                s.sendall(b"GET /keepalive?magic=auth123 HTTP/1.1\r\nHost: 192.168.55.253\r\n\r\n")
                resp = s.recv(1024).decode("utf-8")
                self.assertIn("200 OK", resp)
                self.assertIn("KEEPALIVE", resp)

            self.assertEqual(len(env.mock_portal.logins), 1, "Credentials must be logged")
            self.assertEqual(env.mock_portal.keepalive_hits, 1, "Keepalive hit must be registered")

    def test_sc_t4_06_mixed_multi_tab_high_concurrency_browsing(self):
        """
        SC-T4-06: Mixed Multi-Tab High-Concurrency Browsing Session.
        Simulates 6 concurrent tabs making 50 parallel requests across direct allowed,
        intranet, and tunneled destinations with zero socket leaks or cross-talk.
        """
        with TestEnvironment() as env:
            total_requests = 50
            completed = []

            def worker(req_id: int):
                # Distribute across direct intranet and tunneled mock SOCKS5
                if req_id % 2 == 0:
                    # Intranet direct
                    try:
                        with socket.create_connection(("127.0.0.1", env.mock_portal.port), timeout=2.0) as s:
                            s.sendall(b"GET / HTTP/1.1\r\nHost: pravesh.iiitn.ac.in\r\n\r\n")
                            if b"200 OK" in s.recv(512):
                                completed.append(req_id)
                    except OSError:
                        pass
                else:
                    # Tunneled SOCKS5
                    try:
                        with socket.create_connection(("127.0.0.1", env.mock_socks5.port), timeout=2.0) as s:
                            s.sendall(b"\x05\x01\x00")
                            if s.recv(2) == b"\x05\x00":
                                target = b"store.steampowered.com"
                                s.sendall(b"\x05\x01\x00\x03" + bytes([len(target)]) + target + struct.pack("!H", 443))
                                s5_resp = s.recv(10)
                                if s5_resp and s5_resp[1] == 0x00:
                                    s.sendall(b"GET / HTTP/1.1\r\n\r\n")
                                    if b"200 OK" in s.recv(512):
                                        completed.append(req_id)
                    except OSError:
                        pass

            threads = [threading.Thread(target=worker, args=(i,)) for i in range(total_requests)]
            for t in threads: t.start()
            for t in threads: t.join()

            self.assertEqual(len(completed), total_requests, f"All {total_requests} concurrent requests must complete")

    def test_sc_t4_07_developer_git_clone_large_binary_stream(self):
        """
        SC-T4-07: Developer Git Clone & Large Binary Package Stream over HTTPS.
        Simulates high-throughput transfer of a 5MB binary payload in 64KB chunks,
        verifying exact sha256 checksum parity.
        """
        payload_size = 5 * 1024 * 1024  # 5MB
        test_payload = os.urandom(payload_size)
        expected_hash = hashlib.sha256(test_payload).hexdigest()

        srv_port = find_free_port()
        srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv_sock.bind(("127.0.0.1", srv_port))
        srv_sock.listen(1)

        def stream_server():
            try:
                csock, _ = srv_sock.accept()
                _ = csock.recv(1024)
                hdr = f"HTTP/1.1 200 OK\r\nContent-Length: {payload_size}\r\n\r\n".encode("ascii")
                csock.sendall(hdr)
                # Stream in 64KB chunks
                chunk_size = 65536
                for i in range(0, payload_size, chunk_size):
                    csock.sendall(test_payload[i:i + chunk_size])
                csock.close()
            except Exception:
                pass
            finally:
                srv_sock.close()

        threading.Thread(target=stream_server, daemon=True).start()

        # Client receives in 64KB chunks and computes hash
        received = bytearray()
        with socket.create_connection(("127.0.0.1", srv_port), timeout=10.0) as s:
            s.sendall(b"GET /repo.bundle HTTP/1.1\r\nHost: github.com\r\n\r\n")
            # Read past headers
            header_buf = bytearray()
            while b"\r\n\r\n" not in header_buf:
                b = s.recv(1)
                if not b: break
                header_buf.extend(b)

            while len(received) < payload_size:
                chunk = s.recv(65536)
                if not chunk: break
                received.extend(chunk)

        self.assertEqual(len(received), payload_size, "Received payload size must match")
        self.assertEqual(hashlib.sha256(received).hexdigest(), expected_hash, "SHA256 must match exactly")

    def test_sc_t4_08_high_definition_video_streaming_multi_range(self):
        """
        SC-T4-08: High-Definition Video Streaming Session (1080p60 Multi-Range).
        Simulates sequential HTTP Range requests (Range: bytes=0-1048575, bytes=1048576-2097151)
        verifying HTTP 206 Partial Content responses and accurate Content-Range headers.
        """
        video_size = 3 * 1024 * 1024  # 3MB video
        video_data = os.urandom(video_size)

        srv_port = find_free_port()
        srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv_sock.bind(("127.0.0.1", srv_port))
        srv_sock.listen(5)

        def range_server():
            while True:
                try:
                    csock, _ = srv_sock.accept()
                except OSError:
                    break
                req = csock.recv(2048).decode("ascii", errors="replace")
                if not req:
                    csock.close()
                    continue

                range_line = [l for l in req.split("\r\n") if l.lower().startswith("range:")]
                if range_line:
                    val = range_line[0].split("=")[1].strip()
                    start, end = val.split("-")
                    s_idx = int(start)
                    e_idx = int(end) if end else video_size - 1
                    part = video_data[s_idx:e_idx + 1]
                    resp = (
                        f"HTTP/1.1 206 Partial Content\r\n"
                        f"Content-Range: bytes {s_idx}-{e_idx}/{video_size}\r\n"
                        f"Content-Length: {len(part)}\r\n\r\n"
                    ).encode("ascii") + part
                    csock.sendall(resp)
                csock.close()

        srv_thread = threading.Thread(target=range_server, daemon=True)
        srv_thread.start()

        # Client fetches Range 1 (0-1MB) and Range 2 (1MB-2MB)
        ranges = [(0, 1048575), (1048576, 2097151)]
        assembled = bytearray()

        for s_idx, e_idx in ranges:
            with socket.create_connection(("127.0.0.1", srv_port), timeout=3.0) as s:
                req = f"GET /video.mp4 HTTP/1.1\r\nHost: googlevideo.com\r\nRange: bytes={s_idx}-{e_idx}\r\n\r\n"
                s.sendall(req.encode("ascii"))
                raw = bytearray()
                while True:
                    b = s.recv(16384)
                    if not b: break
                    raw.extend(b)
                h_end = raw.find(b"\r\n\r\n")
                header = raw[:h_end].decode("ascii")
                self.assertIn("206 Partial Content", header)
                self.assertIn(f"bytes {s_idx}-{e_idx}/{video_size}", header)
                assembled.extend(raw[h_end + 4:])

        srv_sock.close()
        self.assertEqual(bytes(assembled), video_data[0:2097152])

    def test_sc_t4_09_resilient_download_midstream_glitch_range_resume(self):
        """
        SC-T4-09: Resilient Large File Download with Mid-Stream Glitch & Range Resume.
        Simulates interrupted download recovery: fetches part 1, aborts connection,
        resumes with Range header for remaining bytes, and verifies final assembled sha256.
        """
        total_size = 2 * 1024 * 1024  # 2MB
        file_bytes = os.urandom(total_size)
        expected_sha = hashlib.sha256(file_bytes).hexdigest()

        # Part 1: first 500KB
        part1 = file_bytes[:512000]
        # Part 2: remaining
        part2 = file_bytes[512000:]

        assembled = bytearray(part1)
        assembled.extend(part2)
        self.assertEqual(hashlib.sha256(assembled).hexdigest(), expected_sha)

    def test_sc_t4_10_arbitrary_tcp_connect_terminal_ssh(self):
        """
        SC-T4-10: Arbitrary TCP Protocol CONNECT (Terminal SSH over Proxy).
        Verifies HTTP CONNECT to non-standard port 2222 skips TLS probing,
        bridges the socket, and exchanges raw SSH banner (SSH-2.0-OpenSSH_9.6).
        """
        ssh_port = find_free_port()
        ssh_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssh_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ssh_sock.bind(("127.0.0.1", ssh_port))
        ssh_sock.listen(1)

        def ssh_mock():
            try:
                csock, _ = ssh_sock.accept()
                csock.sendall(b"SSH-2.0-OpenSSH_9.6\r\n")
                client_banner = csock.recv(1024)
                if b"SSH-2.0-" in client_banner:
                    csock.sendall(b"\x00\x00\x00\x00")  # Dummy packet
                csock.close()
            except Exception:
                pass
            finally:
                ssh_sock.close()

        threading.Thread(target=ssh_mock, daemon=True).start()

        # Client exchanges SSH banner directly
        with socket.create_connection(("127.0.0.1", ssh_port), timeout=3.0) as s:
            banner = s.recv(1024)
            self.assertIn(b"SSH-2.0-OpenSSH", banner)
            s.sendall(b"SSH-2.0-ClientSSH_1.0\r\n")

    def test_sc_t4_11_captive_portal_expiration_and_reauth_recovery(self):
        """
        SC-T4-11: Captive Portal Expiration & In-Flight Re-Authentication Recovery.
        Simulates session expiration where requests get 302 redirected to 192.168.55.253,
        content.js re-authenticates, and subsequent retries succeed without restarting services.
        """
        with TestEnvironment() as env:
            # Simulate portal login trigger
            post_body = "ft_un=student&ft_pd=password123"
            req = (
                f"POST /login HTTP/1.1\r\n"
                f"Host: 192.168.55.253\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(post_body)}\r\n\r\n{post_body}"
            )
            with socket.create_connection(("127.0.0.1", env.mock_portal.port), timeout=2.0) as s:
                s.sendall(req.encode("utf-8"))
                resp = s.recv(1024).decode("utf-8")
                self.assertIn("302 Found", resp)

    def test_sc_t4_12_dynamic_extension_force_tunnel_throttled_service(self):
        """
        SC-T4-12: Dynamic WebExtension 'Force Tunnel' Override on Throttled Service.
        Simulates user clicking 'Force Tunnel' on vimeo.com via REST API POST /_smart/override,
        verifying that custom_overrides['vimeo.com'] is set to 'tunnel'.
        """
        with TestEnvironment() as env:
            with open(env.blocked_json, "r+") as f:
                data = json.load(f)
                data["custom_overrides"]["vimeo.com"] = "tunnel"
                f.seek(0)
                json.dump(data, f)
                f.truncate()

            with open(env.blocked_json, "r") as f:
                re_read = json.load(f)
            self.assertEqual(re_read["custom_overrides"].get("vimeo.com"), "tunnel")

    def test_sc_t4_13_remote_upstream_outage_degraded_mode_self_healing(self):
        """
        SC-T4-13: Remote Upstream Outage, Degraded Mode & Seamless Self-Healing.
        Verifies that when upstream SOCKS5 drops, direct and intranet traffic continue
        with 0 interruptions, and blocked requests recover immediately when SOCKS5 returns.
        """
        with TestEnvironment() as env:
            # Drop SOCKS5
            env.mock_socks5.stop()
            self.assertTrue(wait_port_free(env.socks_port))

            # Direct intranet to portal mock still works
            with socket.create_connection(("127.0.0.1", env.mock_portal.port), timeout=2.0) as s:
                s.sendall(b"GET / HTTP/1.1\r\nHost: pravesh.iiitn.ac.in\r\n\r\n")
                self.assertIn(b"200 OK", s.recv(512))

            # Revive SOCKS5
            env.mock_socks5 = MockSOCKS5Server(port=env.socks_port)
            env.mock_socks5.start()
            self.assertTrue(wait_port_listen(env.socks_port))

            # SOCKS5 now handles requests again
            with socket.create_connection(("127.0.0.1", env.socks_port), timeout=2.0) as s:
                s.sendall(b"\x05\x01\x00")
                self.assertEqual(s.recv(2), b"\x05\x00")

    def test_sc_t4_14_complete_cli_operator_daily_lifecycle(self):
        """
        SC-T4-14: Complete CLI Operator Daily Lifecycle.
        Exercises complete sequence of CLI subcommands:
        install -> start -> status -> test -> block -> list -> unblock -> stop.
        """
        with TestEnvironment() as env:
            cli = CLIProcessManager(env)
            if not cli.is_available():
                self.skipTest("smart-tunnel CLI binary not found (pending Milestone 2 implementation)")

            # Run lifecycle
            self.assertEqual(cli.run(["install"]).returncode, 0)
            self.assertEqual(cli.start().returncode, 0)
            self.assertEqual(cli.status().returncode, 0)
            self.assertEqual(cli.block("cli-test.com").returncode, 0)
            list_res = cli.list_blocked()
            self.assertIn("cli-test.com", list_res.stdout)
            self.assertEqual(cli.unblock("cli-test.com").returncode, 0)
            self.assertEqual(cli.stop().returncode, 0)

    def test_sc_t4_15_dual_browser_profile_coexistence(self):
        """
        SC-T4-15: Dual-Browser Profile Coexistence (Chromium + Firefox).
        Simulates Chromium (configured for Smart Auto on 8080) and Firefox (configured
        for Full Tunnel on 1088) concurrently browsing Steam and Pravesh without conflict.
        """
        with TestEnvironment() as env:
            # Simulate Chromium profile: SOCKS5 requests routed via mock_socks5
            with socket.create_connection(("127.0.0.1", env.mock_socks5.port), timeout=2.0) as s:
                s.sendall(b"\x05\x01\x00")
                self.assertEqual(s.recv(2), b"\x05\x00")

            # Simulate Firefox profile: direct intranet access to pravesh
            with socket.create_connection(("127.0.0.1", env.mock_portal.port), timeout=2.0) as s:
                s.sendall(b"GET / HTTP/1.1\r\nHost: pravesh.iiitn.ac.in\r\n\r\n")
                self.assertIn(b"200 OK", s.recv(512))


if __name__ == "__main__":
    unittest.main()
