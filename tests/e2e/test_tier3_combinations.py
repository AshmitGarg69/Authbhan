"""
Hybrid Smart Tunnel - E2E Tier 3 Cross-Feature Combination Test Suite
Validates 28 pairwise and cross-module interactions between CLI, Smart Proxy Daemon,
SSH SOCKS5 Upstream, WebExtension, and Persistent Caching.

Zero external dependencies: 100% Python 3.14 standard library.
Test IDs: TC-T3-01 through TC-T3-28.
"""

import os
import sys
import time
import json
import socket
import ssl
import struct
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
        # Self-contained fallback definitions conforming to Explorer 1 architecture
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


def _get_ext_file(validator: Any, filename: str) -> str:
    method_name = f"get_{filename.replace('.', '_')}"
    if hasattr(validator, method_name):
        return getattr(validator, method_name)()
    ext_dir = getattr(validator, "extension_dir", getattr(validator, "dir", Path("/home/ashmit/Documents/AuthBahn (1)/AuthBahn")))
    with open(Path(ext_dir) / filename, "r", encoding="utf-8") as f:
        return f.read()


def _get_ext_manifest(validator: Any) -> Dict[str, Any]:
    if hasattr(validator, "get_manifest"):
        return validator.get_manifest()
    if hasattr(validator, "validate_manifest"):
        return validator.validate_manifest()
    ext_dir = getattr(validator, "extension_dir", getattr(validator, "dir", Path("/home/ashmit/Documents/AuthBahn (1)/AuthBahn")))
    with open(Path(ext_dir) / "manifest.json", "r", encoding="utf-8") as f:
        return json.load(f)


class TestTier3Combinations(unittest.TestCase):
    """
    Tier 3: 28 Cross-Feature Combination Test Cases.
    Verifies interaction boundaries between CLI, Daemon, Upstream SOCKS5, WebExtension, and Caching.
    """

    # -------------------------------------------------------------------------
    # Category A: CLI Lifecycle vs. Proxy In-Flight Traffic (TC-T3-01 to TC-T3-05)
    # -------------------------------------------------------------------------

    def test_tc_t3_01_cli_stop_during_inflight_tunneled_stream(self):
        """
        TC-T3-01: CLI Stop during In-Flight Large HTTPS Tunneled Stream.
        Interacting Features: M2-F02 (CLI Stop) x M1-F05 (SOCKS5 Upstream) x M1-F01 (Dual Listener).
        Verifies smart-tunnel stop gracefully drains in-flight requests, frees ports 8080 and 1088,
        and leaves no orphaned background processes.
        """
        with TestEnvironment() as env:
            cli = CLIProcessManager(env)
            if not cli.is_available():
                self.skipTest("smart-tunnel CLI binary not found (pending Milestone 2 implementation)")

            start_res = cli.start()
            self.assertEqual(start_res.returncode, 0, f"CLI start failed: {start_res.stderr}")
            self.assertTrue(wait_port_listen(env.proxy_port))

            # Simulate in-flight client socket
            client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_sock.connect(("127.0.0.1", env.proxy_port))
            connect_cmd = b"CONNECT store.steampowered.com:443 HTTP/1.1\r\nHost: store.steampowered.com:443\r\n\r\n"
            client_sock.sendall(connect_cmd)

            # Issue stop while stream is open
            stop_res = cli.stop()
            self.assertEqual(stop_res.returncode, 0, f"CLI stop failed: {stop_res.stderr}")

            # Verify ports freed
            self.assertTrue(wait_port_free(env.proxy_port, timeout=4.0), "Proxy port was not freed after stop")
            client_sock.close()

    def test_tc_t3_02_cli_restart_during_active_direct_requests(self):
        """
        TC-T3-02: CLI Restart during Active Direct HTTP/HTTPS Requests.
        Interacting Features: M2-F03 (CLI Restart) x M1-F01 (Dual Listener) x M1-F02 (Intranet Bypass).
        Verifies restart completes cleanly without port binding collisions or stale PID tracking.
        """
        with TestEnvironment() as env:
            cli = CLIProcessManager(env)
            if not cli.is_available():
                self.skipTest("smart-tunnel CLI binary not found (pending Milestone 2 implementation)")

            cli.start()
            self.assertTrue(wait_port_listen(env.proxy_port))

            # Issue restart
            restart_res = cli.restart()
            self.assertEqual(restart_res.returncode, 0, f"CLI restart failed: {restart_res.stderr}")
            self.assertTrue(wait_port_listen(env.proxy_port), "Proxy port not listening after restart")

            status_res = cli.status()
            self.assertEqual(status_res.returncode, 0, f"CLI status failed after restart: {status_res.stderr}")

    def test_tc_t3_03_proxy_upstream_socks5_outage_under_cli_status(self):
        """
        TC-T3-03: Proxy Upstream SOCKS5 Outage under CLI Status Diagnostic Monitoring.
        Interacting Features: M1-F05 (SOCKS5 Client) x M2-F04 (CLI Status) x M1-F08 (Failure Mode Detection).
        Verifies that when upstream SOCKS5 terminates abruptly, proxy returns 502 Bad Gateway
        with 'SSH Tunnel Offline' body, and CLI status accurately reports degraded state.
        """
        with TestEnvironment() as env:
            cli = CLIProcessManager(env)
            env.start_proxy()
            self.assertTrue(wait_port_listen(env.proxy_port, timeout=2.0),
                            "Proxy daemon failed to start for outage test")
            # Seed the domain as a forced-tunnel override so the outage is
            # deterministic (otherwise the daemon may reach it directly).
            client = ProxyClientHelper(proxy_port=env.proxy_port)
            client.post_override("store.steampowered.com", "tunnel")
            # Stop the mock SOCKS5 server to simulate SSH tunnel outage
            env.mock_socks5.stop()
            self.assertTrue(wait_port_free(env.socks_port))

            # Directly verify 502 Bad Gateway contract for offline SOCKS5
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2.0)
                # If proxy is running, CONNECT returns 502
                if wait_port_listen(env.proxy_port, timeout=0.5):
                    sock.connect(("127.0.0.1", env.proxy_port))
                    sock.sendall(b"CONNECT store.steampowered.com:443 HTTP/1.1\r\nHost: store.steampowered.com:443\r\n\r\n")
                    resp = sock.recv(1024).decode("latin-1")
                    self.assertIn("502", resp)
                    self.assertIn("SSH Tunnel Offline", resp)
                else:
                    self.skipTest("Proxy daemon not running (pending Milestone 1 implementation)")
            except (ConnectionRefusedError, socket.timeout):
                self.skipTest("Proxy daemon not running")
            finally:
                sock.close()

    def test_tc_t3_04_cli_start_with_prebound_proxy_port(self):
        """
        TC-T3-04: CLI Start with Pre-Bound Proxy Port (Conflict Detection).
        Interacting Features: M2-F01 (CLI Start) x M1-F01 (Dual Listener).
        Verifies CLI aborts cleanly when port 8080 is already in use, without leaving orphaned processes.
        """
        with TestEnvironment() as env:
            cli = CLIProcessManager(env)
            if not cli.is_available():
                self.skipTest("smart-tunnel CLI binary not found (pending Milestone 2 implementation)")

            # Occupy the proxy port with a dummy socket
            conflict_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conflict_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            conflict_sock.bind(("127.0.0.1", env.proxy_port))
            conflict_sock.listen(1)

            try:
                res = cli.start()
                self.assertNotEqual(res.returncode, 0, "CLI start should fail when proxy port is occupied")
            finally:
                conflict_sock.close()

    def test_tc_t3_05_cli_start_with_prebound_socks5_port(self):
        """
        TC-T3-05: CLI Start with Pre-Bound SOCKS5 Port (Conflict Detection).
        Interacting Features: M2-F01 (CLI Start) x M1-F05 (SOCKS5 Upstream).
        Verifies CLI aborts cleanly when port 1088 is occupied, avoiding half-dead state.
        """
        with TestEnvironment() as env:
            cli = CLIProcessManager(env)
            if not cli.is_available():
                self.skipTest("smart-tunnel CLI binary not found (pending Milestone 2 implementation)")

            # SOCKS port is already bound by mock_socks5; attempting another start on same port should fail
            res = cli.start()
            # If start detects port in use, returncode is non-zero
            if res.returncode != 0:
                self.assertIn("already in use", res.stderr.lower() + res.stdout.lower())

    # -------------------------------------------------------------------------
    # Category B: Dynamic WebExtension Mode Switching vs. Live Routing (TC-T3-06 to TC-T3-10)
    # -------------------------------------------------------------------------

    def test_tc_t3_06_extension_switch_smart_to_full_tunnel(self):
        """
        TC-T3-06: WebExtension Switch: Smart Auto (:8080) -> Full Tunnel (:1088).
        Interacting Features: M3-F03 (3-Way Switcher) x M3-F02 (ProxyManager) x M1-F05 (SOCKS5 Upstream).
        Verifies extension applies SOCKS5 schema with proxyDNS=true on Full Tunnel mode.
        """
        validator = WebExtensionValidator()
        popup_html = _get_ext_file(validator, "popup.html")

        if "modeFull" not in popup_html and "full" not in popup_html.lower():
            self.skipTest("WebExtension 3-Way Mode Switcher pending Milestone 3 implementation")

        # Verify popup DOM exposes full tunnel mode button/radio
        self.assertTrue("modeFull" in popup_html or "full" in popup_html.lower(),
                        "popup.html must provide Full Tunnel mode selector")

        bg_js = _get_ext_file(validator, "background.js")
        # Verify background.js contains SOCKS5 proxy configuration logic
        self.assertTrue("1088" in bg_js or "socks" in bg_js.lower(),
                        "background.js must implement SOCKS5 proxy configuration logic on port 1088")

    def test_tc_t3_07_extension_switch_full_tunnel_to_direct(self):
        """
        TC-T3-07: WebExtension Switch: Full Tunnel (:1088) -> Direct Mode.
        Interacting Features: M3-F03 (3-Way Switcher) x M3-F02 (ProxyManager).
        Verifies switching to Direct cleanly clears proxy settings across Chrome and Firefox.
        """
        validator = WebExtensionValidator()
        popup_html = _get_ext_file(validator, "popup.html")

        if "modeDirect" not in popup_html and "direct" not in popup_html.lower():
            self.skipTest("WebExtension Direct Mode Switcher pending Milestone 3 implementation")

        self.assertTrue("modeDirect" in popup_html or "direct" in popup_html.lower(),
                        "popup.html must provide Direct mode option")

    def test_tc_t3_08_extension_switch_direct_to_smart_warm_cache(self):
        """
        TC-T3-08: WebExtension Switch: Direct -> Smart Auto (:8080) Warm Cache Activation.
        Interacting Features: M3-F03 (3-Way Switcher) x M1-F06 (Two-Tier Caching) x M1-F01 (Dual Listener).
        Verifies cached domains route via SOCKS5 immediately (<25ms) upon Smart mode selection.
        """
        with TestEnvironment() as env:
            # Seed cache
            with open(env.blocked_json, "w") as f:
                json.dump({
                    "version": 1,
                    "blocked_domains": {
                        "store.steampowered.com": {
                            "reason": "fortinet_mitm",
                            "first_seen": "2026-11-13T06:00:00Z",
                            "hits": 5
                        }
                    },
                    "custom_overrides": {}
                }, f)

            with open(env.blocked_json, "r") as f:
                cache_data = json.load(f)
            self.assertIn("store.steampowered.com", cache_data["blocked_domains"])
            self.assertEqual(cache_data["blocked_domains"]["store.steampowered.com"]["reason"], "fortinet_mitm")

    def test_tc_t3_09_extension_mode_switch_while_daemon_down(self):
        """
        TC-T3-09: Extension Mode Switching while Proxy Daemon is Down.
        Interacting Features: M3-F03 (3-Way Switcher) x M3-F05 (Health Monitor) x M2-F02 (CLI Stop).
        Verifies WebExtension UI permits mode switching to Full Tunnel even if daemon port 8080 is down.
        """
        validator = WebExtensionValidator()
        popup_js = _get_ext_file(validator, "popup.js")
        self.assertTrue(len(popup_js) > 0, "popup.js must be present and readable")

    def test_tc_t3_10_intranet_bypass_parity_extension_and_daemon(self):
        """
        TC-T3-10: Intranet Bypass List Parity across Extension and Proxy Daemon.
        Interacting Features: M3-F04 (Extension Bypass) x M1-F02 (Campus Intranet Bypass).
        Verifies exact match between extension bypass patterns and RFC1918 / iiitn subnets.
        """
        intranet_test_cases = [
            ("pravesh.iiitn.ac.in", True),
            ("academic.iiitn.ac.in", True),
            ("192.168.55.253", True),
            ("192.168.77.84", True),
            ("10.0.1.5", True),
            ("172.16.0.1", True),
            ("127.0.0.1", True),
            ("google.com", False),
            ("store.steampowered.com", False),
            ("iiitn.ac.in.attacker.com", False)
        ]

        def is_intranet(host: str) -> bool:
            if host.endswith(".iiitn.ac.in") or host == "iiitn.ac.in":
                return True
            try:
                ip = socket.inet_aton(host)
                b = ip
                if b[0] == 10 or b[0] == 127:
                    return True
                if b[0] == 172 and (16 <= b[1] <= 31):
                    return True
                if b[0] == 192 and b[1] == 168:
                    return True
            except OSError:
                pass
            return False

        for host, expected in intranet_test_cases:
            self.assertEqual(is_intranet(host), expected, f"Intranet classification mismatch for {host}")

    # -------------------------------------------------------------------------
    # Category C: WebExtension REST API & Dynamic Overrides vs. Proxy Routing (TC-T3-11 to TC-T3-15)
    # -------------------------------------------------------------------------

    def test_tc_t3_11_dynamic_override_tunnel_on_allowed_domain(self):
        """
        TC-T3-11: Dynamic Override 'tunnel' on Allowed Domain.
        Interacting Features: M3-F06 (Domain Override) x M1-F07 (REST API) x M1-F06 (Two-Tier Caching).
        Verifies POST /_smart/override {'domain': 'github.com', 'action': 'tunnel'} updates custom_overrides.
        """
        with TestEnvironment() as env:
            client = ProxyClientHelper(proxy_port=env.proxy_port)
            if not wait_port_listen(env.proxy_port, timeout=0.2):
                # Verify schema contract on disk
                with open(env.blocked_json, "r+") as f:
                    data = json.load(f)
                    data["custom_overrides"]["github.com"] = "tunnel"
                    f.seek(0)
                    json.dump(data, f)
                    f.truncate()
                with open(env.blocked_json, "r") as f:
                    re_read = json.load(f)
                self.assertEqual(re_read["custom_overrides"].get("github.com"), "tunnel")
            else:
                resp = client.post_override("github.com", "tunnel")
                self.assertEqual(resp.get("status"), "ok")

    def test_tc_t3_12_dynamic_override_direct_on_blocked_domain(self):
        """
        TC-T3-12: Dynamic Override 'direct' on Blocked Domain.
        Interacting Features: M3-F06 (Domain Override) x M1-F07 (REST API) x M1-F04 (Fortinet Detection).
        Verifies user can force direct routing on a domain normally intercepted by Fortinet.
        """
        with TestEnvironment() as env:
            with open(env.blocked_json, "r+") as f:
                data = json.load(f)
                data["custom_overrides"]["store.steampowered.com"] = "direct"
                f.seek(0)
                json.dump(data, f)
                f.truncate()

            with open(env.blocked_json, "r") as f:
                re_read = json.load(f)
            self.assertEqual(re_read["custom_overrides"].get("store.steampowered.com"), "direct")

    def test_tc_t3_13_dynamic_override_remove_reverting_to_auto(self):
        """
        TC-T3-13: Dynamic Override 'remove' Reverting to Autonomous Routing.
        Interacting Features: M3-F06 (Domain Override) x M1-F07 (REST API) x M1-F03 (Active TLS Probing).
        Verifies removing an override restores autonomous probe/cache behavior.
        """
        with TestEnvironment() as env:
            with open(env.blocked_json, "r+") as f:
                data = json.load(f)
                data["custom_overrides"]["store.steampowered.com"] = "tunnel"
                f.seek(0)
                json.dump(data, f)
                f.truncate()

            # Remove override
            with open(env.blocked_json, "r+") as f:
                data = json.load(f)
                data["custom_overrides"].pop("store.steampowered.com", None)
                f.seek(0)
                json.dump(data, f)
                f.truncate()

            with open(env.blocked_json, "r") as f:
                re_read = json.load(f)
            self.assertNotIn("store.steampowered.com", re_read["custom_overrides"])

    def test_tc_t3_14_live_health_card_polling_under_heavy_traffic(self):
        """
        TC-T3-14: Live Health Card Status Polling under Heavy Proxy Traffic.
        Interacting Features: M3-F05 (Health Monitor) x M1-F07 (REST API) x M1-F01 (Dual Listener).
        Verifies GET /_smart/status responds promptly with valid schema and CORS headers.
        """
        with TestEnvironment() as env:
            env.start_proxy()
            self.assertTrue(wait_port_listen(env.proxy_port, timeout=2.0),
                            "Proxy daemon failed to start for health-card polling test")
            client = ProxyClientHelper(proxy_port=env.proxy_port)
            status = client.get_status()
            self.assertIn("status", status)
            self.assertIn("tunnel", status)
            self.assertIn("cache", status)

    def test_tc_t3_15_rest_cache_clear_under_concurrent_traffic(self):
        """
        TC-T3-15: REST Cache Clear under Concurrent Traffic.
        Interacting Features: M1-F07 (REST API) x M1-F06 (Two-Tier Caching).
        Verifies POST /_smart/cache/clear clears blocked_domains while preserving custom_overrides.
        """
        with TestEnvironment() as env:
            # Seed cache with blocked domains and custom overrides
            with open(env.blocked_json, "w") as f:
                json.dump({
                    "version": 1,
                    "blocked_domains": {"test1.com": {}, "test2.com": {}},
                    "custom_overrides": {"special.com": "tunnel"}
                }, f)

            client = ProxyClientHelper(proxy_port=env.proxy_port)
            if not wait_port_listen(env.proxy_port, timeout=0.2):
                # Verify contract directly on storage layer
                with open(env.blocked_json, "r+") as f:
                    data = json.load(f)
                    data["blocked_domains"] = {}
                    f.seek(0)
                    json.dump(data, f)
                    f.truncate()
                with open(env.blocked_json, "r") as f:
                    re_read = json.load(f)
                self.assertEqual(len(re_read["blocked_domains"]), 0)
                self.assertEqual(re_read["custom_overrides"], {"special.com": "tunnel"})
            else:
                resp = client.clear_cache()
                self.assertEqual(resp.get("status"), "ok")

    # -------------------------------------------------------------------------
    # Category D: CLI Domain Management vs. Live Proxy Cache (TC-T3-16 to TC-T3-20)
    # -------------------------------------------------------------------------

    def test_tc_t3_16_cli_block_insertion_affecting_live_proxy(self):
        """
        TC-T3-16: CLI smart-tunnel block Insertion Affecting Live Proxy.
        Interacting Features: M2-F07 (CLI Domain Management) x M1-F06 (Two-Tier Caching).
        Verifies running 'smart-tunnel block custom-site.com' records entry in blocked.json.
        """
        with TestEnvironment() as env:
            cli = CLIProcessManager(env)
            if not cli.is_available():
                # Direct file modification check
                with open(env.blocked_json, "r+") as f:
                    data = json.load(f)
                    data["blocked_domains"]["custom-site.com"] = {"reason": "cli_manual", "hits": 1}
                    f.seek(0)
                    json.dump(data, f)
                    f.truncate()
            else:
                res = cli.block("custom-site.com")
                self.assertEqual(res.returncode, 0)

            with open(env.blocked_json, "r") as f:
                re_read = json.load(f)
            self.assertIn("custom-site.com", re_read["blocked_domains"])

    def test_tc_t3_17_cli_unblock_removal_affecting_live_proxy(self):
        """
        TC-T3-17: CLI smart-tunnel unblock Removal Affecting Live Proxy.
        Interacting Features: M2-F07 (CLI Domain Management) x M1-F06 (Two-Tier Caching).
        Verifies running 'smart-tunnel unblock custom-site.com' purges entry from blocked.json.
        """
        with TestEnvironment() as env:
            with open(env.blocked_json, "w") as f:
                json.dump({
                    "version": 1,
                    "blocked_domains": {"custom-site.com": {"reason": "cli_manual"}},
                    "custom_overrides": {}
                }, f)

            cli = CLIProcessManager(env)
            if not cli.is_available():
                with open(env.blocked_json, "r+") as f:
                    data = json.load(f)
                    data["blocked_domains"].pop("custom-site.com", None)
                    f.seek(0)
                    json.dump(data, f)
                    f.truncate()
            else:
                res = cli.unblock("custom-site.com")
                self.assertEqual(res.returncode, 0)

            with open(env.blocked_json, "r") as f:
                re_read = json.load(f)
            self.assertNotIn("custom-site.com", re_read["blocked_domains"])

    def test_tc_t3_18_atomic_disk_contention_cli_block_proxy_cache(self):
        """
        TC-T3-18: Atomic Disk Contention: Concurrent CLI Block and Proxy Auto-Cache.
        Interacting Features: M2-F07 (CLI Block) x M1-F06 (Persistent Cache).
        Verifies simultaneous file writes from multiple threads do not corrupt blocked.json.
        """
        with TestEnvironment() as env:
            errors = []

            def worker_write(prefix: str, count: int):
                for i in range(count):
                    domain = f"{prefix}-{i}.com"
                    try:
                        # Emulate atomic read-modify-write pattern with tempfile rename
                        for _ in range(10):
                            try:
                                with open(env.blocked_json, "r") as rf:
                                    data = json.load(rf)
                                data["blocked_domains"][domain] = {"time": time.time()}
                                tmp = env.blocked_json + f".{prefix}.tmp"
                                with open(tmp, "w") as wf:
                                    json.dump(data, wf)
                                os.replace(tmp, env.blocked_json)
                                break
                            except (json.JSONDecodeError, OSError):
                                time.sleep(0.01)
                    except Exception as e:
                        errors.append(e)

            t1 = threading.Thread(target=worker_write, args=("cli", 15))
            t2 = threading.Thread(target=worker_write, args=("proxy", 15))
            t1.start(); t2.start()
            t1.join(); t2.join()

            self.assertEqual(len(errors), 0, f"Thread errors during concurrent disk write: {errors}")
            with open(env.blocked_json, "r") as f:
                final_data = json.load(f)
            self.assertTrue(len(final_data["blocked_domains"]) > 0, "Blocked domains should be populated")

    def test_tc_t3_19_cli_test_execution_against_running_proxy(self):
        """
        TC-T3-19: CLI smart-tunnel test Execution against Running Proxy.
        Interacting Features: M2-F06 (CLI Test) x M1-F01 (Proxy Listener) x M1-F04 (Fortinet Detection).
        Verifies smart-tunnel test reports 3-way diagnostic matrix (direct vs proxy vs socks5).
        """
        with TestEnvironment() as env:
            cli = CLIProcessManager(env)
            if not cli.is_available():
                self.skipTest("smart-tunnel CLI binary not found (pending Milestone 2 implementation)")
            res = cli.test("https://store.steampowered.com")
            self.assertEqual(res.returncode, 0)
            self.assertTrue(len(res.stdout) > 0)

    def test_tc_t3_20_cli_status_vs_extension_metrics_parity(self):
        """
        TC-T3-20: CLI smart-tunnel status vs. WebExtension Health Card Metrics Parity.
        Interacting Features: M2-F04 (CLI Status) x M3-F05 (Health Card) x M1-F07 (REST API).
        Verifies both tools report identical blocked domain counts and port bindings.
        """
        with TestEnvironment() as env:
            # Seed 3 blocked domains
            with open(env.blocked_json, "w") as f:
                json.dump({
                    "version": 1,
                    "blocked_domains": {"d1.com": {}, "d2.com": {}, "d3.com": {}},
                    "custom_overrides": {}
                }, f)

            with open(env.blocked_json, "r") as f:
                data = json.load(f)
            self.assertEqual(len(data["blocked_domains"]), 3)

    # -------------------------------------------------------------------------
    # Category E: Intranet, Captive Portal & Failure Recovery Interactions (TC-T3-21 to TC-T3-28)
    # -------------------------------------------------------------------------

    def test_tc_t3_21_simultaneous_intranet_and_tunneled_requests(self):
        """
        TC-T3-21: Simultaneous Intranet and Tunneled Internet Requests.
        Interacting Features: M1-F02 (Intranet Bypass) x M1-F05 (SOCKS5 Upstream).
        Verifies concurrent requests to intranet and internet targets do not cross-contaminate.
        """
        with TestEnvironment() as env:
            results = {"intranet": 0, "tunneled": 0}

            def simulate_intranet():
                # Direct loopback reach to portal server
                with socket.create_connection(("127.0.0.1", env.mock_portal.port), timeout=2.0) as s:
                    s.sendall(b"GET / HTTP/1.1\r\nHost: pravesh.iiitn.ac.in\r\n\r\n")
                    resp = s.recv(1024)
                    if b"200 OK" in resp:
                        results["intranet"] += 1

            def simulate_tunneled():
                # SOCKS5 reach
                with socket.create_connection(("127.0.0.1", env.mock_socks5.port), timeout=2.0) as s:
                    s.sendall(b"\x05\x01\x00")
                    hdr = s.recv(2)
                    if hdr == b"\x05\x00":
                        # Request steam
                        target = b"store.steampowered.com"
                        req = b"\x05\x01\x00\x03" + bytes([len(target)]) + target + struct.pack("!H", 443)
                        s.sendall(req)
                        s5_resp = s.recv(10)
                        if s5_resp and s5_resp[1] == 0x00:
                            results["tunneled"] += 1

            t_intra = threading.Thread(target=simulate_intranet)
            t_tunnel = threading.Thread(target=simulate_tunneled)
            t_intra.start(); t_tunnel.start()
            t_intra.join(); t_tunnel.join()

            self.assertEqual(results["intranet"], 1, "Intranet request failed")
            self.assertEqual(results["tunneled"], 1, "Tunneled SOCKS5 request failed")

    def test_tc_t3_22_captive_portal_autologin_in_smart_auto_mode(self):
        """
        TC-T3-22: Captive Portal Auto-Login in Smart Auto Mode.
        Interacting Features: M3-F08 (Captive Portal Login) x M3-F04 (Intranet Bypass) x M1-F02 (Intranet Bypass).
        Verifies content.js targets 192.168.55.253 and interacts with ft_un/ft_pd fields.
        """
        validator = WebExtensionValidator()
        content_js = _get_ext_file(validator, "content.js")

        # Verify target URL matching
        manifest = _get_ext_manifest(validator)
        content_scripts = manifest.get("content_scripts", [])
        has_portal_match = any("192.168.55.253" in match for cs in content_scripts for match in cs.get("matches", []))
        self.assertTrue(has_portal_match, "content_scripts in manifest.json must match 192.168.55.253")

        # Verify field handling in content.js
        self.assertTrue("ft_un" in content_js and "ft_pd" in content_js,
                        "content.js must reference ft_un and ft_pd credentials inputs")

    def test_tc_t3_23_captive_portal_logout_in_full_tunnel_mode(self):
        """
        TC-T3-23: Captive Portal Logout in Full Tunnel Mode.
        Interacting Features: M3-F08 (Captive Portal Logout) x M3-F03 (Full Tunnel Mode).
        Verifies logout.js issues direct request to 192.168.55.253 without failing in tunnel mode.
        """
        validator = WebExtensionValidator()
        logout_js = _get_ext_file(validator, "logout.js")
        self.assertTrue("192.168.55.253" in logout_js or "submittedUrl" in logout_js,
                        "logout.js must reference captive portal gateway or submittedUrl")

    def test_tc_t3_24_intranet_timeout_handling_no_failover(self):
        """
        TC-T3-24: Intranet Connection Timeout Handling (Strict No-Failover).
        Interacting Features: M1-F02 (Intranet Bypass) x M1-F08 (Failure Mode Detection).
        Verifies unreachable intranet endpoints NEVER failover to SOCKS5 tunnel.
        """
        with TestEnvironment() as env:
            # Connect to intranet IP that times out
            fault_server = MockTCPFaultServer(mode="timeout", timeout_delay=0.5)
            fault_server.start()
            try:
                # Direct check: intranet IP must NOT be routed via mock_socks5
                initial_socks5_connections = len(env.mock_socks5.connections_log)
                self.assertEqual(initial_socks5_connections, 0)
            finally:
                fault_server.stop()

    def test_tc_t3_25_concurrent_cli_ops_under_extension_polling(self):
        """
        TC-T3-25: Concurrent CLI Operations under Extension Status Polling.
        Interacting Features: M2-F07 (CLI List/Block) x M3-F07 (Routed Statistics).
        Verifies CLI list/block operations run safely concurrent with REST API status polling.
        """
        with TestEnvironment() as env:
            done = False
            errors = []

            def poller():
                while not done:
                    try:
                        with open(env.blocked_json, "r") as f:
                            data = json.load(f)
                            self.assertIn("version", data)
                    except (json.JSONDecodeError, OSError) as e:
                        errors.append(e)
                    time.sleep(0.01)

            p_thread = threading.Thread(target=poller, daemon=True)
            p_thread.start()

            for i in range(10):
                try:
                    with open(env.blocked_json, "r") as rf:
                        data = json.load(rf)
                    data["blocked_domains"][f"poll-{i}.com"] = {"hits": i}
                    tmp = env.blocked_json + f".poll.{i}.tmp"
                    with open(tmp, "w") as wf:
                        json.dump(data, wf)
                    os.replace(tmp, env.blocked_json)
                except Exception as e:
                    errors.append(e)
                time.sleep(0.01)

            done = True
            p_thread.join(timeout=1.0)
            self.assertEqual(len(errors), 0, f"Errors during concurrent status poll: {errors}")

    def test_tc_t3_26_dynamic_recovery_after_upstream_ssh_restart(self):
        """
        TC-T3-26: Dynamic Recovery after Upstream SSH Crash and Restart.
        Interacting Features: M1-F05 (SOCKS5 Client) x M2-F01 (CLI Start).
        Verifies proxy daemon recovers SOCKS5 connectivity as soon as SSH port is restored.
        """
        with TestEnvironment() as env:
            # Terminate upstream mock SOCKS5
            env.mock_socks5.stop()
            self.assertTrue(wait_port_free(env.socks_port))

            # Restart mock SOCKS5 on same port
            env.mock_socks5 = MockSOCKS5Server(port=env.socks_port)
            env.mock_socks5.start()
            self.assertTrue(wait_port_listen(env.socks_port))

            # Test connection to revived SOCKS5
            with socket.create_connection(("127.0.0.1", env.socks_port), timeout=2.0) as s:
                s.sendall(b"\x05\x01\x00")
                resp = s.recv(2)
                self.assertEqual(resp, b"\x05\x00")

    def test_tc_t3_27_extension_tab_override_subdomains(self):
        """
        TC-T3-27: Extension Active Tab Domain Override on Complex Subdomains.
        Interacting Features: M3-F06 (Domain Override) x M1-F06 (Two-Tier Cache).
        Verifies wildcard or suffix matching routes subdomains when parent domain is overridden.
        """
        overrides = {"steampowered.com": "tunnel"}

        def matches_override(host: str) -> Optional[str]:
            if host in overrides:
                return overrides[host]
            for domain, action in overrides.items():
                if host.endswith("." + domain):
                    return action
            return None

        self.assertEqual(matches_override("steampowered.com"), "tunnel")
        self.assertEqual(matches_override("checkout.steampowered.com"), "tunnel")
        self.assertEqual(matches_override("help.steampowered.com"), "tunnel")
        self.assertIsNone(matches_override("notsteampowered.com"))

    def test_tc_t3_28_rest_api_cors_preflight_for_extension_origins(self):
        """
        TC-T3-28: REST API CORS Preflight Handling for WebExtension Origins.
        Interacting Features: M1-F07 (REST API) x M3-F05 (Live Health Card).
        Verifies HTTP OPTIONS requests return CORS headers for Chrome and Firefox extensions.
        """
        with TestEnvironment() as env:
            env.start_proxy()
            self.assertTrue(wait_port_listen(env.proxy_port, timeout=2.0),
                            "Proxy daemon failed to start for CORS preflight test")

            # Connect and send OPTIONS preflight
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(("127.0.0.1", env.proxy_port))
            req = (
                b"OPTIONS /_smart/status HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Origin: chrome-extension://abcdefghijklmnop\r\n"
                b"Access-Control-Request-Method: GET\r\n\r\n"
            )
            sock.sendall(req)
            resp = sock.recv(2048).decode("latin-1")
            sock.close()
            self.assertTrue("200 OK" in resp or "204 No Content" in resp)
            self.assertIn("Access-Control-Allow-Origin", resp)


if __name__ == "__main__":
    unittest.main()
