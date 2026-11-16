# AuthBahn — with Smart Tunnel

An automated authentication and smart proxy routing extension for the IIIT Nagpur campus network.

---

## Overview

**AuthBahn** is a lightweight browser extension engineered for the Indian Institute of Information Technology, Nagpur (IIITN) campus network. It serves a dual role:
1. **Automated Captive Portal Login**: Upon encountering the campus Fortinet firewall gateway (`192.168.55.253`), AuthBahn programmatically populates stored LDAP credentials, handles form submission, and maintains session continuity.
2. **Smart Tunnel Proxy (New)**: Bypasses campus firewall restrictions on gaming, developer, and community platforms (Steam, Discord, Epic Games, Reddit, etc.) via a single **ON / OFF switch** at the bottom of the popup.

Originally created as an internal project by **CRISPR** (Coding, Research, Innovations and Software Projects, IIITN) and in active use since April 2024, AuthBahn is published for the campus community to ensure seamless internet access across devices.

The project name draws inspiration from the German *Autobahn* — designed for unrestricted, high-efficiency transit.

---

## How It Works

AuthBahn provides two flexible usage modes:

### 1. Zero-Setup Mode (Recommended for most students)
- **Zero terminal commands, zero Python, zero configuration.**
- Open the extension popup and toggle **Smart Tunnel** to **ON**.
- The extension automatically routes blocked services (Steam, Discord, Reddit, etc.) through the hardened CRISPR club server proxy (`192.168.77.84:3128`).
- **Campus Intranet & Login (`192.168.55.253`, `*.iiitn.ac.in`) stay 100% direct**, ensuring you never get disconnected from local portals or attendance systems.
- Normal unblocked web traffic bypasses the proxy directly for maximum speed.
- Toggle **OFF** anytime to return to a standard direct connection.

### 2. Local Smart Daemon (For developers & power users)
- Power users running the local Python daemon (`./bin/smart-tunnel start`) get local dynamic probing, zero-millisecond memory caching, SSH SOCKS5 tunneling, and REST management.
- When the daemon is active, flipping the toggle automatically detects `127.0.0.1:8080` and connects in Smart Auto mode.

---

## Repository Structure

```text
├── AuthBahn/                  # WebExtension source (Chrome, Brave, Edge, Firefox)
│   ├── manifest.json          # WebExtension manifest (Manifest V3)
│   ├── background.js          # Service worker & ProxyManager (PAC + Smart Auto)
│   ├── popup.html             # Clean CRISPR popup with Smart Tunnel ON/OFF switch
│   ├── popup.css              # Light theme styles
│   ├── popup.js               # Toggle controller & mode auto-detection
│   ├── content.js             # Captive portal auto-login content script
│   ├── portal.html            # Local LDAP credential management view
│   └── icons/assets           # Extension branding and graphics
├── src/
│   └── smart-proxy.py         # Standalone async Python proxy daemon
├── bin/
│   ├── smart-tunnel           # Cross-platform CLI management tool (Linux & macOS)
│   ├── route-traffic          # System-wide GNOME proxy switcher
│   └── server-browser         # Remote browser helper
├── deploy/                    # Club server configuration (Squid proxy + crowd list)
│   ├── squid.conf             # Hardened Squid forward proxy configuration
│   ├── smart-list-service.py  # Shared blocked-domain service
│   └── smart-list.service     # Systemd unit file
├── scripts/
│   └── package-extension.sh   # Extension release packager
└── tests/                     # Unit, adversarial, and E2E test suites (290+ tests)
```

---

## Quick Installation

### Option A: Direct Download (No Git Needed)
1. Download the latest **`AuthBahn-v1.0.zip`** from the [Releases](../../releases) tab.
2. Unzip the downloaded file to a folder on your computer.
3. Open your browser's extension console:
   - **Chrome / Brave / Arc**: `chrome://extensions`
   - **Microsoft Edge**: `edge://extensions`
4. Turn on **Developer mode** (toggle in top-right corner).
5. Click **Load unpacked** (top-left) and select the unzipped folder.
6. Pin AuthBahn to your toolbar.

### Option B: From Git
```bash
git clone -b smart-tunnel https://github.com/AshmitGarg69/Authbhan.git
```
Then load the `AuthBahn` directory in `chrome://extensions` via **Load unpacked**.

---

## Usage Guide

1. **Configuring LDAP Credentials**:
   - Click the AuthBahn toolbar icon.
   - Click **Add Fortigate ID**.
   - Enter your campus LDAP username and password, then select **Save Credentials**.
2. **Automatic Captive Portal Login**:
   - Connect to campus Wi-Fi or Ethernet.
   - When hitting `192.168.55.253`, AuthBahn auto-fills and submits your credentials, redirecting to the keepalive page upon success.
3. **Bypassing Network Restrictions**:
   - In the AuthBahn popup, flip the **Smart Tunnel** toggle at the bottom to **ON**.
   - Blocked domains (Steam, Discord, etc.) are now immediately accessible.
4. **Session Logout**:
   - Click **Logout** in the popup to terminate your captive portal session.

---

## CLI & Server Deployment (Optional)

For server administrators or members wishing to run their own local escape hatch:

```bash
# Start local CLI daemon
./bin/smart-tunnel start

# Check status & cache
./bin/smart-tunnel status

# Run test suite
python3 -m unittest discover -s tests/unit
```

See [`deploy/server-setup.md`](deploy/server-setup.md) for full documentation on deploying the club Squid proxy and crowd-sourced blocked list service.

---

## Security & Privacy Model

- **Zero Telemetry**: AuthBahn operates in complete isolation on your local machine. No credentials, tokens, URLs, or browsing data are ever collected, logged, or sent to external servers.
- **Client-Side Storage**: All credentials are saved exclusively within the browser's sandboxed local storage (`chrome.storage.local`).
- **Targeted Scope**: Content scripts are restricted strictly to the campus captive portal domain (`192.168.55.253`).
- **No Intranet Pivots**: The club server Squid proxy strictly denies requests to private RFC1918 subnets and loopback addresses, preventing SSRF.

---

## Contributors & Maintainers

- **Original Authors**:
  - Ayush Khushwah (Batch of 2025)
  - Krishna Chaudhari (Batch of 2025)

- **Current Maintainer**:
  - Ashmit Garg (Batch of 2029)

*Developed under CRISPR, IIIT Nagpur.*

---

## Feedback & Inquiries

For technical support, inquiries, or bug reports, contact [crispr@iiitn.ac.in](mailto:crispr@iiitn.ac.in) or visit the official project page at [https://crispr.iiitn.ac.in/authbahn.html](https://crispr.iiitn.ac.in/authbahn.html).
