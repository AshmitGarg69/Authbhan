"""
Hybrid Smart Tunnel - E2E Test Harness & Mock Infrastructure
Zero external dependencies: 100% Python 3.14 standard library.
Provides mock servers, process management, isolated test fixtures, and client helpers.
"""

import fcntl
import html.parser
import ipaddress
import json
import os
import re
import select
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


def find_free_port() -> int:
    """Find and return an available ephemeral TCP port on 127.0.0.1."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return s.getsockname()[1]


def wait_port_listen(port: int, host: str = "127.0.0.1", timeout: float = 3.0) -> bool:
    """Poll until a TCP port is actively accepting connections."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.1):
                return True
        except (ConnectionRefusedError, socket.timeout, OSError):
            time.sleep(0.02)
    return False


def wait_port_free(port: int, host: str = "127.0.0.1", timeout: float = 3.0) -> bool:
    """Poll until a TCP port is released and no longer accepting connections."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.1):
                time.sleep(0.02)
        except (ConnectionRefusedError, socket.timeout, OSError):
            return True
    return False


class MockFortinetMITMServer:
    """
    Simulates Fortinet FortiGate SSL interception presenting MITM CA certificate.
    Subject & Issuer contain:
      - O=Fortinet
      - OU=Certificate Authority
      - CN=FG6H0FTB22905105
      - emailAddress=support@fortinet.com
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.host = host
        self.requested_port = port
        self.port = 0
        self.running = False
        self.server_sock: Optional[socket.socket] = None
        self.thread: Optional[threading.Thread] = None
        self.temp_dir: Optional[tempfile.TemporaryDirectory] = None
        self.cert_file = ""
        self.key_file = ""
        self.der_bytes = b""
        self.handshake_count = 0
        self.requests_log: List[Dict[str, Any]] = []

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
        self.server_sock.listen(50)
        self.port = self.server_sock.getsockname()[1]
        self.running = True

        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        while self.running and self.server_sock:
            try:
                self.server_sock.settimeout(0.5)
                csock, _ = self.server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_client, args=(csock,), daemon=True).start()

    def _handle_client(self, csock: socket.socket):
        try:
            with self.ctx.wrap_socket(csock, server_side=True) as ssock:
                self.handshake_count += 1
                data = ssock.recv(4096)
                if data:
                    self.requests_log.append({"data": data, "time": time.time()})
                body = (
                    b"<html><head><title>Application Control Violation</title></head>"
                    b"<body><h1>FortiGate Application Control</h1>"
                    b"<h3>Application Blocked</h3></body></html>"
                )
                resp = (
                    b"HTTP/1.1 403 Forbidden\r\n"
                    b"Content-Type: text/html\r\n"
                    b"Server: FortiGate\r\n"
                    b"Connection: close\r\n"
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
    """
    Simulates TCP network faults:
      - mode='reset': Accepts connection, sets SO_LINGER l_onoff=1, l_linger=0, and closes immediately (hardware TCP RST).
      - mode='timeout': Accepts connection and holds it silent without data for timeout_delay seconds.
    """

    def __init__(self, mode: str = "reset", host: str = "127.0.0.1", port: int = 0, timeout_delay: float = 3.0):
        self.mode = mode
        self.host = host
        self.requested_port = port
        self.port = 0
        self.timeout_delay = timeout_delay
        self.running = False
        self.fault_count = 0
        self.server_sock: Optional[socket.socket] = None
        self.thread: Optional[threading.Thread] = None

    def start(self):
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind((self.host, self.requested_port))
        self.server_sock.listen(50)
        self.port = self.server_sock.getsockname()[1]
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        while self.running and self.server_sock:
            try:
                self.server_sock.settimeout(0.5)
                csock, _ = self.server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.fault_count += 1
            if self.mode == "reset":
                # Explicit TCP RST via SO_LINGER
                try:
                    csock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                    csock.close()
                except OSError:
                    pass
            elif self.mode == "timeout":
                threading.Thread(target=self._handle_timeout, args=(csock,), daemon=True).start()

    def _handle_timeout(self, csock: socket.socket):
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
    """
    RFC 1928 SOCKS5 Server verifying ATYP=0x03 (remote DNS) and upstream bridging.
    Configurable to simulate protocol success or upstream failure replies (e.g. 0x04 / 0x05).
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 0, reply_status: int = 0x00, freeze_handshake: bool = False):
        self.host = host
        self.requested_port = port
        self.port = 0
        self.reply_status = reply_status
        self.freeze_handshake = freeze_handshake
        self.running = False
        self.server_sock: Optional[socket.socket] = None
        self.thread: Optional[threading.Thread] = None
        self.connections_log: List[Dict[str, Any]] = []

    def start(self):
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind((self.host, self.requested_port))
        self.server_sock.listen(50)
        self.port = self.server_sock.getsockname()[1]
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        while self.running and self.server_sock:
            try:
                self.server_sock.settimeout(0.5)
                csock, _ = self.server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_client, args=(csock,), daemon=True).start()

    def _handle_client(self, csock: socket.socket):
        try:
            if self.freeze_handshake:
                time.sleep(4.0)
                csock.close()
                return

            # 1. Method negotiation
            hdr = csock.recv(2)
            if not hdr or hdr[0] != 0x05:
                csock.close()
                return
            nmethods = hdr[1]
            _ = csock.recv(nmethods)
            csock.sendall(b"\x05\x00")  # NO AUTH

            # 2. Command
            req = csock.recv(4)
            if not req or req[0] != 0x05 or req[1] != 0x01:  # CONNECT
                csock.close()
                return
            atyp = req[3]
            if atyp == 0x01:  # IPv4
                target_host = socket.inet_ntoa(csock.recv(4))
            elif atyp == 0x03:  # DOMAINNAME
                dlen = csock.recv(1)[0]
                target_host = csock.recv(dlen).decode("latin-1")
            elif atyp == 0x04:  # IPv6
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

            if self.reply_status != 0x00:
                # Send error reply
                reply = bytes([0x05, self.reply_status, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                csock.sendall(reply)
                csock.close()
                return

            # Send SOCKS5 Success: 05 00 00 01 7F 00 00 01 00 00
            csock.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")

            # Bidirectional relay or synthetic response
            data = csock.recv(4096)
            if data:
                resp_body = b"HTTP/1.1 200 OK\r\nX-Tunneled-Through: crisper-server-1\r\nContent-Length: 12\r\nConnection: close\r\n\r\nHelloTunneled"
                csock.sendall(resp_body)
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
    """
    Simulates Fortinet Captive Portal on 192.168.55.253 / loopback.
    Endpoints:
      - GET / or /login: returns HTML form with #ft_un and #ft_pd
      - POST /login: returns 302 Found redirect to /keepalive?magic=auth1234
      - GET /keepalive: returns 200 OK KEEPALIVE
      - GET /logout: returns 200 OK LOGOUT
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.host = host
        self.requested_port = port
        self.port = 0
        self.running = False
        self.server_sock: Optional[socket.socket] = None
        self.thread: Optional[threading.Thread] = None
        self.logins: List[Dict[str, str]] = []
        self.keepalive_hits = 0
        self.logout_hits = 0

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
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_client, args=(csock,), daemon=True).start()

    def _handle_client(self, csock: socket.socket):
        try:
            req_data = csock.recv(4096).decode("utf-8", errors="replace")
            lines = req_data.split("\r\n")
            request_line = lines[0] if lines else ""
            parts = request_line.split(" ")
            if len(parts) < 2:
                csock.close()
                return
            method, path = parts[0], parts[1]

            if method == "GET" and (path == "/" or path.startswith("/login")):
                html = (
                    "<!DOCTYPE html><html><body>"
                    "<h2>FortiGate Authentication Portal</h2>"
                    "<form action=\"/login\" method=\"post\">"
                    "<input id=\"ft_un\" name=\"ft_un\" type=\"text\"/>"
                    "<input id=\"ft_pd\" name=\"ft_pd\" type=\"password\"/>"
                    "<button id=\"loginButton\" type=\"submit\">Login</button>"
                    "</form></body></html>"
                )
                resp = (
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Type: text/html\r\n"
                    f"Content-Length: {len(html.encode('utf-8'))}\r\n"
                    f"Connection: close\r\n\r\n{html}"
                )
                csock.sendall(resp.encode("utf-8"))

            elif method == "POST" and path.startswith("/login"):
                self.logins.append({"raw": req_data, "time": time.time()})
                resp = (
                    f"HTTP/1.1 302 Found\r\n"
                    f"Location: http://{self.host}:{self.port}/keepalive?magic=auth1234\r\n"
                    f"Content-Length: 0\r\n"
                    f"Connection: close\r\n\r\n"
                )
                csock.sendall(resp.encode("utf-8"))

            elif method == "GET" and "/keepalive" in path:
                self.keepalive_hits += 1
                resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 9\r\nConnection: close\r\n\r\nKEEPALIVE"
                csock.sendall(resp.encode("utf-8"))

            elif method == "GET" and "/logout" in path:
                self.logout_hits += 1
                resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 6\r\nConnection: close\r\n\r\nLOGOUT"
                csock.sendall(resp.encode("utf-8"))
            else:
                csock.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
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


class MockTargetServer:
    """A standard mock HTTP/HTTPS target server for direct routing tests."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0, is_ssl: bool = False):
        self.host = host
        self.requested_port = port
        self.port = 0
        self.is_ssl = is_ssl
        self.running = False
        self.server_sock: Optional[socket.socket] = None
        self.thread: Optional[threading.Thread] = None
        self.requests_log: List[Dict[str, Any]] = []

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
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_client, args=(csock,), daemon=True).start()

    def _handle_client(self, csock: socket.socket):
        try:
            req = csock.recv(4096)
            if req:
                self.requests_log.append({"raw": req, "time": time.time()})
            body = b"<html><body>Direct Target OK</body></html>"
            resp = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/html\r\n"
                b"Connection: close\r\n"
                b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n\r\n" + body
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


class TestEnvironment:
    """Context manager providing isolated config, dynamic ports, and mock servers."""

    def __init__(self, isolated: bool = True):
        self.isolated = isolated
        self.temp_dir: Optional[tempfile.TemporaryDirectory] = None
        self.config_dir = ""
        self.blocked_json = ""
        self.proxy_port = 0
        self.socks_port = 0
        self.mock_mitm: Optional[MockFortinetMITMServer] = None
        self.mock_socks5: Optional[MockSOCKS5Server] = None
        self.mock_fault: Optional[MockTCPFaultServer] = None
        self.mock_portal: Optional[MockCaptivePortalServer] = None
        self.mock_target: Optional[MockTargetServer] = None
        self.tracked_processes: List[subprocess.Popen] = []
        self._orig_env: Dict[str, str] = {}
        self.proxy_proc: Optional[subprocess.Popen] = None

    def __enter__(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        td = Path(self.temp_dir.name)
        self.config_dir = str(td / "config")
        os.makedirs(self.config_dir, exist_ok=True)
        self.blocked_json = str(Path(self.config_dir) / "blocked.json")

        with open(self.blocked_json, "w") as f:
            json.dump({"version": 1, "blocked_domains": {}, "custom_overrides": {}}, f, indent=2)

        # Allocate ephemeral ports
        self.proxy_port = find_free_port()
        self.socks_port = find_free_port()

        # Start Mocks
        self.mock_socks5 = MockSOCKS5Server(port=self.socks_port)
        self.mock_socks5.start()
        self.socks_port = self.mock_socks5.port

        self.mock_mitm = MockFortinetMITMServer()
        self.mock_mitm.start()

        self.mock_fault = MockTCPFaultServer(mode="reset")
        self.mock_fault.start()

        self.mock_portal = MockCaptivePortalServer()
        self.mock_portal.start()

        self.mock_target = MockTargetServer()
        self.mock_target.start()

        # Write config.env
        config_env_file = Path(self.config_dir) / "config.env"
        with open(config_env_file, "w") as f:
            f.write(
                f'SSH_USER="crisper"\n'
                f'SSH_HOST="192.168.77.84"\n'
                f'SOCKS_BIND="127.0.0.1"\n'
                f'SOCKS_PORT="{self.socks_port}"\n'
                f'PROXY_BIND="127.0.0.1"\n'
                f'PROXY_PORT="{self.proxy_port}"\n'
                f'CONFIG_DIR="{self.config_dir}"\n'
                f'BLOCKED_JSON="{self.blocked_json}"\n'
                f'SSH_LOG="{self.config_dir}/ssh.log"\n'
                f'PROXY_LOG="{self.config_dir}/proxy.log"\n'
            )

        # Environment isolation
        self._orig_env = dict(os.environ)
        os.environ["SMART_TUNNEL_CONFIG_DIR"] = self.config_dir

        return self

    def start_proxy(self, extra_args: Optional[List[str]] = None) -> subprocess.Popen:
        """Launches the smart-proxy.py daemon using ephemeral test ports and config directory."""
        if self.proxy_proc and self.proxy_proc.poll() is None:
            return self.proxy_proc

        proxy_script = Path("/home/ashmit/Code/smart-tunnel/src/smart-proxy.py")
        if not proxy_script.exists():
            proxy_script = Path.home() / ".config" / "smart-tunnel" / "smart-proxy.py"

        if not proxy_script.exists():
            raise FileNotFoundError(f"smart-proxy.py not found at {proxy_script}")

        cmd = [
            sys.executable,
            str(proxy_script),
            "--host", "127.0.0.1",
            "--port", str(self.proxy_port),
            "--socks5-host", "127.0.0.1",
            "--socks5-port", str(self.socks_port),
            "--config-dir", self.config_dir,
        ]
        if extra_args:
            cmd.extend(extra_args)

        env = dict(os.environ)
        env["SMART_TUNNEL_CONFIG_DIR"] = self.config_dir
        self.proxy_proc = self.spawn_process(cmd, env=env)
        if not wait_port_listen(self.proxy_port, timeout=3.0):
            self.proxy_proc.terminate()
            raise RuntimeError(f"Smart proxy daemon failed to listen on port {self.proxy_port}")

        # Store proxy PID in config dir
        with open(os.path.join(self.config_dir, "proxy.pid"), "w") as f:
            f.write(str(self.proxy_proc.pid))

        return self.proxy_proc

    def stop_proxy(self):
        """Stops the proxy daemon."""
        if self.proxy_proc and self.proxy_proc.poll() is None:
            self.proxy_proc.terminate()
            try:
                self.proxy_proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                self.proxy_proc.kill()
            self.proxy_proc = None
        wait_port_free(self.proxy_port, timeout=2.0)
        pid_file = Path(self.config_dir) / "proxy.pid"
        if pid_file.exists():
            try:
                pid_file.unlink()
            except OSError:
                pass

    def get_ssh_pid_path(self) -> Path:
        return Path(self.config_dir) / "ssh.pid"

    def get_proxy_pid_path(self) -> Path:
        return Path(self.config_dir) / "proxy.pid"

    def spawn_process(self, cmd: List[str], **kwargs) -> subprocess.Popen:
        proc = subprocess.Popen(cmd, **kwargs)
        self.tracked_processes.append(proc)
        return proc

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Terminate proxy if running
        self.stop_proxy()

        # Terminate all tracked subprocesses
        for proc in self.tracked_processes:
            if proc.poll() is None:
                try:
                    proc.terminate()
                    proc.wait(timeout=1.0)
                except (subprocess.TimeoutExpired, ProcessLookupError):
                    try:
                        proc.kill()
                    except ProcessLookupError:
                        pass

        # Stop mocks
        if self.mock_mitm:
            self.mock_mitm.stop()
        if self.mock_socks5:
            self.mock_socks5.stop()
        if self.mock_fault:
            self.mock_fault.stop()
        if self.mock_portal:
            self.mock_portal.stop()
        if self.mock_target:
            self.mock_target.stop()

        # Restore env
        os.environ.clear()
        os.environ.update(self._orig_env)

        if self.temp_dir:
            try:
                self.temp_dir.cleanup()
            except Exception:
                pass


class CLIProcessManager:
    """Manages CLI invocations of smart-tunnel against the test environment."""

    def __init__(self, env: TestEnvironment):
        self.env = env
        self.search_paths = [
            os.environ.get("SMART_TUNNEL_BIN"),
            "/home/ashmit/Code/smart-tunnel/bin/smart-tunnel",
            str(Path.home() / ".local" / "bin" / "smart-tunnel"),
            shutil.which("smart-tunnel")
        ]
        self.cli_path = self._locate_bin()

    def _locate_bin(self) -> Optional[str]:
        for p in self.search_paths:
            if p and Path(p).is_file() and os.access(p, os.X_OK):
                return str(p)
        return None

    def is_available(self) -> bool:
        self.cli_path = self._locate_bin()
        return self.cli_path is not None

    def run(self, args: List[str], timeout: float = 5.0) -> subprocess.CompletedProcess:
        if not self.is_available():
            raise FileNotFoundError(f"smart-tunnel CLI binary not found in {self.search_paths}")
        cmd = [self.cli_path] + args
        env = dict(os.environ)
        env["SMART_TUNNEL_CONFIG_DIR"] = self.env.config_dir
        return subprocess.run(
            cmd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout
        )

    def start(self) -> subprocess.CompletedProcess:
        return self.run(["start"])

    def stop(self) -> subprocess.CompletedProcess:
        return self.run(["stop"])

    def restart(self) -> subprocess.CompletedProcess:
        return self.run(["restart"])

    def status(self) -> subprocess.CompletedProcess:
        return self.run(["status"])

    def log(self, *extra) -> subprocess.CompletedProcess:
        return self.run(["log", *extra])

    def test(self, url: str) -> subprocess.CompletedProcess:
        return self.run(["test", url])

    def block(self, domain: str) -> subprocess.CompletedProcess:
        return self.run(["block", domain])

    def unblock(self, domain: str) -> subprocess.CompletedProcess:
        return self.run(["unblock", domain])

    def list_blocked(self) -> subprocess.CompletedProcess:
        return self.run(["list"])

    def install(self) -> subprocess.CompletedProcess:
        return self.run(["install"])


class ProxyClientHelper:
    """Interacts with the Smart Proxy daemon via HTTP CONNECT, GET, and REST API."""

    def __init__(self, proxy_host: str = "127.0.0.1", proxy_port: int = 8080):
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

    def http_get(self, url: str, headers: Optional[Dict[str, str]] = None, timeout: float = 3.0) -> Tuple[int, Dict[str, str], bytes]:
        """Sends an HTTP GET via the proxy using proxy connection."""
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 80

        sock = socket.create_connection((self.proxy_host, self.proxy_port), timeout=timeout)
        req_lines = [f"GET {url} HTTP/1.1", f"Host: {host}:{port}"]
        if headers:
            for k, v in headers.items():
                req_lines.append(f"{k}: {v}")
        req_lines.append("Connection: close")
        req_lines.append("\r\n")
        sock.sendall("\r\n".join(req_lines).encode("latin-1"))

        resp_bytes = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp_bytes += chunk
            except socket.timeout:
                break
        sock.close()

        parts = resp_bytes.split(b"\r\n\r\n", 1)
        header_part = parts[0].decode("latin-1", errors="replace") if parts else ""
        body_part = parts[1] if len(parts) > 1 else b""

        status_code = 0
        resp_headers = {}
        lines = header_part.split("\r\n")
        if lines:
            status_line = lines[0]
            tokens = status_line.split(" ")
            if len(tokens) > 1 and tokens[1].isdigit():
                status_code = int(tokens[1])
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    resp_headers[k.strip().lower()] = v.strip()

        return status_code, resp_headers, body_part

    def https_connect(self, target_host: str, target_port: int = 443, timeout: float = 3.0) -> Tuple[int, bytes, bytes]:
        """
        Performs HTTP CONNECT via proxy, completes TLS handshake,
        returns (status_code, peer_der_cert, response_data).
        """
        sock = socket.create_connection((self.proxy_host, self.proxy_port), timeout=timeout)
        connect_req = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n\r\n"
        sock.sendall(connect_req.encode("ascii"))

        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = sock.recv(1024)
            if not chunk:
                break
            resp += chunk

        status_line = resp.decode("latin-1", errors="replace").split("\r\n")[0]
        tokens = status_line.split(" ")
        status_code = int(tokens[1]) if len(tokens) > 1 and tokens[1].isdigit() else 0

        if status_code != 200:
            sock.close()
            return status_code, b"", b""

        # Perform TLS handshake
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with ctx.wrap_socket(sock, server_hostname=target_host) as ssock:
                der = ssock.getpeercert(binary_form=True) or b""
                # Read any initial data
                ssock.settimeout(1.0)
                try:
                    data = ssock.recv(2048)
                except socket.timeout:
                    data = b""
                return status_code, der, data
        except Exception:
            return status_code, b"", b""


class DOMElementFinder(html.parser.HTMLParser):
    """Simple DOM inspector using Python standard library html.parser."""

    def __init__(self):
        super().__init__()
        self.elements_by_id: Dict[str, Dict[str, Any]] = {}
        self.tags: List[Dict[str, Any]] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        attr_dict = {k: v for k, v in attrs}
        elem = {"tag": tag, "attrs": attr_dict}
        self.tags.append(elem)
        if "id" in attr_dict and attr_dict["id"]:
            self.elements_by_id[attr_dict["id"]] = elem


class WebExtensionValidator:
    """Validates WebExtension files, schemas, DOM structures, and manifests."""

    def __init__(self, extension_dir: Optional[str] = None):
        self.extension_dir = Path(
            extension_dir or os.environ.get("AUTHOBAHN_DIR") or "/home/ashmit/Documents/AuthBahn (1)/AuthBahn"
        )

    def is_available(self) -> bool:
        return self.extension_dir.is_dir()

    def get_manifest_path(self) -> Path:
        return self.extension_dir / "manifest.json"

    def get_manifest(self) -> Dict[str, Any]:
        with open(self.get_manifest_path(), "r") as f:
            return json.load(f)

    def get_popup_html(self) -> str:
        with open(self.extension_dir / "popup.html", "r") as f:
            return f.read()

    def get_portal_html(self) -> str:
        with open(self.extension_dir / "portal.html", "r") as f:
            return f.read()

    def get_popup_css(self) -> str:
        with open(self.extension_dir / "popup.css", "r") as f:
            return f.read()

    def get_background_js(self) -> str:
        with open(self.extension_dir / "background.js", "r") as f:
            return f.read()

    def get_content_js(self) -> str:
        with open(self.extension_dir / "content.js", "r") as f:
            return f.read()

    def get_logout_js(self) -> str:
        with open(self.extension_dir / "logout.js", "r") as f:
            return f.read()

    def parse_dom(self, html_content: str) -> DOMElementFinder:
        finder = DOMElementFinder()
        finder.feed(html_content)
        return finder


class EnvironmentDetector:
    """Detects live host reachability and network parameters."""

    @staticmethod
    def is_live_available(host: str = "192.168.77.84", port: int = 22, timeout: float = 1.0) -> bool:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False
