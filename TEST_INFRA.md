# Hybrid Smart Tunnel — E2E Testing Infrastructure Specification

## 1. Executive Summary & Principles
The **Hybrid Smart Tunnel E2E Testing Infrastructure** provides a completely opaque-box, deterministic, and isolated testing framework validating all components of the Hybrid Smart Tunnel system:
1. **Local Smart Proxy Daemon (`smart-proxy.py`)**: Listening on `127.0.0.1:8080`, supporting HTTP/HTTPS CONNECT, 0ms two-tier caching, active TLS probing (1.2s timeout), Fortinet MITM certificate detection, SOCKS5 upstream failover, campus intranet direct bypass, and REST management API.
2. **User-Space CLI Controller (`smart-tunnel`)**: Executable in `~/.local/bin/smart-tunnel` (or `bin/smart-tunnel`), managing background SSH tunnel and proxy daemon without root privileges.
3. **CRISPR AuthBahn WebExtension (v2.0)**: Manifest V3 extension in `/home/ashmit/Documents/AuthBahn (1)/AuthBahn/` supporting Chromium and Firefox, 3-way mode switching (Smart Auto, Full Tunnel, Direct), health monitoring, and captive portal auto-login (`192.168.55.253`).

### Core Architectural Principles
- **Strict Opaque-Box Testing**: Tests never monkey-patch internal functions or import private daemon code. All assertions validate publicly observable interfaces: TCP/HTTP/HTTPS/SOCKS5 sockets, REST API JSON endpoints, CLI exit codes and output, filesystem state, and WebExtension DOM/manifest schemas.
- **Zero External Dependencies**: Implemented strictly using the Python 3.14 standard library (`unittest`, `socket`, `ssl`, `struct`, `urllib`, `json`, `argparse`, `tempfile`, `subprocess`). No third-party packages (`pytest`, `requests`, `selenium`, `cryptography`) are required.
- **Complete Test Isolation & Ephemerality**: Every test runs in an ephemeral temporary directory with dynamically allocated TCP ports (`bind(0)`), custom isolated `config.env`, and dedicated PID tracking, eliminating state leakage, user session disruption, and port collision.
- **Deterministic Fault Simulation**: Complete mock server suite capable of reproducing exact real-world campus network conditions on demand: Fortinet MITM certificate injection, TCP resets, connection blackholes/timeouts, SOCKS5 DNS resolution, and Fortinet captive portal handshakes.

---

## 2. Infrastructure Architecture & Component Layout

```
/home/ashmit/Code/smart-tunnel/
├── TEST_INFRA.md                     # Testing infrastructure specification (this document)
├── TEST_READY.md                     # Test suite readiness declaration & coverage matrix
└── tests/
    └── e2e/
        ├── harness.py                # Core test infrastructure, mock servers, fixtures, client helpers
        ├── run_all_e2e.py            # Master CLI runner with filtering, ANSI colors, and JSON output
        ├── test_tier1_features.py    # Tier 1 Feature Coverage tests (125 tests)
        ├── test_tier2_boundaries.py  # Tier 2 Boundary & Corner Case tests (125 tests)
        ├── test_tier3_combinations.py# Tier 3 Cross-Feature Combination tests (28 tests)
        └── test_tier4_workloads.py   # Tier 4 Real-World Application Workloads (15 scenarios)
```

### High-Level Architecture Diagram

```mermaid
graph TD
    subgraph TestEnvironment [Isolated TestEnvironment (Context Manager)]
        TempDir[Ephemeral Directory /tmp/...]
        IsolatedConfig[Isolated config.env & blocked.json]
        PortAllocator[FreePortManager: Dynamic bind(0)]
        ProcCleanup[Automatic SIGTERM / SIGKILL Process Reaper]
    end

    subgraph MockHarness [Deterministic Mock Servers]
        MITM[MockFortinetMITMServer\nCert: CN=FG6H0FTB22905105, O=Fortinet]
        Fault[MockTCPFaultServer\nModes: SO_LINGER RST / 1.2s+ Timeout]
        SOCKS5[MockSOCKS5Server\nRFC 1928, ATYP=0x03 Remote DNS Assertion]
        Portal[MockCaptivePortalServer\n192.168.55.253 Login, Keepalive, Logout]
    end

    subgraph TestClients [Opaque-Box Test Clients]
        CLIClient[CLIProcessManager\nCalls smart-tunnel subcommands]
        ProxyClient[ProxyClientHelper\nHTTP, HTTPS CONNECT, REST API Client]
        ExtValidator[WebExtensionValidator\nManifest V3 & DOM Element Inspector]
    end

    subgraph MasterRunner [Master Test Runner]
        Runner[run_all_e2e.py\nCLI Flags: --tier, -v, --json, -k, --fail-fast]
        CustomResult[E2ETestResult\nANSI Green/Red/Yellow Live Streaming]
        JSONReport[Machine-Readable JSON Report Export]
    end

    TestEnvironment --> MockHarness
    TestEnvironment --> TestClients
    MasterRunner --> TestEnvironment
```

---

## 3. Mock Harness Components Specification (`harness.py`)

### 3.1 `FreePortManager`
- `find_free_port() -> int`: Binds an IPv4 TCP socket to `("127.0.0.1", 0)`, retrieves the OS-assigned ephemeral port number, and closes the socket.
- `wait_port_listen(port: int, host="127.0.0.1", timeout=3.0) -> bool`: Actively polls `socket.create_connection` every 20ms until the port accepts connections or the timeout expires.
- `wait_port_free(port: int, host="127.0.0.1", timeout=3.0) -> bool`: Actively polls `socket.create_connection` every 20ms until connections are refused, verifying complete port release.

### 3.2 `MockFortinetMITMServer`
- **Purpose**: Reproduces the exact SSL inspection certificate generated by campus FortiGate DPI firewalls.
- **Certificate Signature**:
  - Subject/Issuer: `/C=US/ST=California/L=Sunnyvale/O=Fortinet/OU=Certificate Authority/CN=FG6H0FTB22905105/emailAddress=support@fortinet.com`
  - Validates `b"Fortinet" in der` and `b"FG6H" in der`.
- **Behavior**: Accepts TLS client connections, completes the TLS handshake presenting the synthetic MITM certificate, and returns an authentic FortiGate `HTTP 403 Forbidden` Application Control block page.

### 3.3 `MockTCPFaultServer`
- **Purpose**: Simulates abrupt network resets and unresponsive hosts.
- **Mode `"reset"`**: Configures client socket linger options to `{l_onoff=1, l_linger=0}` via `setsockopt(SOL_SOCKET, SO_LINGER)` and immediately closes the socket. This injects a hardware TCP RST packet, triggering `ConnectionResetError: [Errno 104] Connection reset by peer` on connecting clients.
- **Mode `"timeout"`**: Accepts client connection and holds the socket silent for `timeout_delay` seconds (default: 3.0s), exceeding the proxy daemon's 1.2s probe threshold.

### 3.4 `MockSOCKS5Server`
- **Purpose**: Implements RFC 1928 SOCKS5 dynamic forwarder simulating `crisper@192.168.77.84:1088`.
- **Protocol Compliance**:
  - Method Negotiation: Accepts version `0x05`, sends `0x05, 0x00` (NO AUTHENTICATION REQUIRED).
  - Request Parsing: Asserts `CMD == 0x01` (CONNECT).
  - **Remote DNS Assertion**: Strictly asserts `ATYP == 0x03` (`DOMAINNAME`), extracting the target hostname to guarantee the proxy daemon delegates domain resolution to the remote egress server rather than resolving locally.
  - Bridges bi-directional byte streams or returns synthetic response headers (`X-Tunneled-Through: crisper-socks5`).

### 3.5 `MockCaptivePortalServer`
- **Purpose**: Simulates campus gateway captive portal (`192.168.55.253`).
- **Endpoints**:
  - `GET /` or `GET /login`: Returns HTML login form containing `<input id="ft_un"/>`, `<input id="ft_pd"/>`, and submit button.
  - `POST /login`: Validates credentials, logs submission, and responds with `HTTP 302 Found` with `Location: /keepalive?magic=auth123`.
  - `GET /keepalive`: Returns `HTTP 200 OK` keepalive confirmation.
  - `GET /logout`: Returns `HTTP 200 OK` logout confirmation.

### 3.6 `TestEnvironment`
- Context manager providing isolated test fixtures:
  - Ephemeral sandbox directory via `tempfile.TemporaryDirectory()`.
  - Dynamically assigned `proxy_port` and `socks_port`.
  - Synthesized `config.env` with isolated paths.
  - Clean initial `blocked.json` (`{"version": 1, "blocked_domains": {}, "custom_overrides": {}}`).
  - Sets `SMART_TUNNEL_CONFIG_DIR` environment variable.
  - Spawns background mock servers on background daemon threads.
  - **Process Reaper**: On exit, sends `SIGTERM` followed by `SIGKILL` to all tracked subprocesses and cleans up temporary files.

### 3.7 Client Helpers
- `CLIProcessManager`: Subprocess invoker executing `smart-tunnel <subcommand>` against the isolated test environment, returning `subprocess.CompletedProcess`.
- `ProxyClientHelper`: Issues HTTP requests, HTTPS CONNECT handshakes, and REST API calls (`GET /_smart/status`, `POST /_smart/override`, `POST /_smart/cache/clear`).
- `WebExtensionValidator`: Headless Manifest V3 parser, syntax validator, and HTML DOM element inspector.

---

## 4. Test Tier Architecture & Mapping

The test suite is structured into four progressive tiers totaling **293 test cases**:

| Tier | Suite File | Test Count | Scope & Focus |
|:---:|---|:---:|---|
| **Tier 1** | `tests/e2e/test_tier1_features.py` | 125 | Baseline feature coverage: 5 tests per feature across all 25 features (M1-F01 through M3-F09) |
| **Tier 2** | `tests/e2e/test_tier2_boundaries.py` | 125 | Boundary, edge, and stress cases: timeouts, invalid syntax, port collisions, process kills |
| **Tier 3** | `tests/e2e/test_tier3_combinations.py` | 28 | Cross-module pairwise interactions: CLI vs Daemon, WebExtension vs SOCKS5, Cache contention |
| **Tier 4** | `tests/e2e/test_tier4_workloads.py` | 15 | Real-world application workloads: Steam, Discord WebSockets, Epic Games, ERP, HD Video |
| **Total** | **All Suites** | **293** | **Complete opaque-box coverage of all functional, boundary, and workload requirements** |

---

## 5. Master Test Runner User Manual (`run_all_e2e.py`)

### 5.1 CLI Synopsis
```bash
python3 tests/e2e/run_all_e2e.py [-h] [--tier TIER [TIER ...]] [-v] [--json [FILE]] [-k PATTERN] [--fail-fast] [--no-color]
```

### 5.2 Command Options
| Option | Description | Example |
|---|---|---|
| `--tier`, `-t` | Select tiers to execute (supports space or comma separation) | `--tier 3,4` or `--tier 1 2` |
| `-v`, `--verbose` | Increase output verbosity (`-v` or `-vv`) | `run_all_e2e.py -v` |
| `--json [FILE]` | Export machine-readable JSON report (prints to stdout if FILE omitted) | `--json report.json` |
| `-k`, `--keyword` | Filter test cases by keyword, test ID, or feature ID | `-k M1-F04` or `-k steam` |
| `--fail-fast` | Abort execution immediately upon the first failure or error | `--fail-fast` |
| `--no-color` | Disable ANSI terminal color formatting | `--no-color` |

### 5.3 Exit Codes
- **`0`**: All executed tests passed (or were cleanly skipped due to pending milestones).
- **`1`**: One or more executed tests failed or encountered unhandled errors.

### 5.4 JSON Report Schema
```json
{
  "version": "1.0",
  "timestamp": "2026-11-13T08:15:00Z",
  "summary": {
    "total": 43,
    "passed": 32,
    "failed": 0,
    "errors": 0,
    "skipped": 11,
    "duration_seconds": 45.2,
    "success": true,
    "exit_code": 0
  },
  "tiers": {
    "1": { "total": 0, "passed": 0, "failed": 0 },
    "2": { "total": 0, "passed": 0, "failed": 0 },
    "3": { "total": 28, "passed": 18, "failed": 0 },
    "4": { "total": 15, "passed": 14, "failed": 0 }
  },
  "results": [
    {
      "id": "test_tier3_combinations.TestTier3Combinations.test_tc_t3_10_intranet_bypass_parity_extension_and_daemon",
      "name": "test_tc_t3_10_intranet_bypass_parity_extension_and_daemon",
      "suite": "TestTier3Combinations",
      "status": "PASS",
      "duration_ms": 0.05,
      "error": null
    }
  ]
}
```

---

## 6. Verification & Troubleshooting

### 6.1 Runner Verification Commands
```bash
# Display CLI help
python3 tests/e2e/run_all_e2e.py --help

# Run Tier 3 and Tier 4 suites verbosely
python3 tests/e2e/run_all_e2e.py --tier 3,4 -v

# Filter specific test by keyword
python3 tests/e2e/run_all_e2e.py -k test_tc_t3_10 -v

# Export JSON report
python3 tests/e2e/run_all_e2e.py --tier 3,4 --json /tmp/e2e_report.json
```

### 6.2 Troubleshooting Guide
1. **`Start directory is not importable`**:
   - Cause: `top_level_dir` in `unittest.TestLoader.discover()` pointing outside the package root without `__init__.py`.
   - Resolution: `run_all_e2e.py` sets `top_level_dir=str(test_dir)` to guarantee directory importability.
2. **`AttributeError in WebExtensionValidator`**:
   - Cause: Inconsistent method names between custom wrappers and `harness.py`.
   - Resolution: `test_tier3_combinations.py` implements polymorphic file reader `_get_ext_file(validator, filename)` supporting both direct attribute getters (`get_popup_html`) and filesystem fallback.
3. **`JSONDecodeError during concurrent disk writes`**:
   - Cause: Non-atomic in-place file modifications (`r+` mode with `seek(0)`) during concurrent multi-threaded execution.
   - Resolution: Implemented atomic write pattern (`tempfile` write + atomic `os.replace`), guaranteeing concurrent readers never observe partial files.
