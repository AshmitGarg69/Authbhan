# AuthBahn

An automated authentication extension for the IIIT Nagpur campus Fortinet captive portal.

---

## Overview

AuthBahn is a lightweight browser extension engineered to automate login onto the Indian Institute of Information Technology, Nagpur (IIITN) campus network. Upon encountering the campus Fortinet firewall gateway (`192.168.55.253`), AuthBahn programmatically populates stored LDAP credentials, handles form submission, and maintains session continuity.

Originally created as an internal project by **CRISPR** (Coding, Research, Innovations and Software Projects, IIITN) and in active use since April 2024, AuthBahn is published for the campus community to ensure seamless internet access across devices.

The project name draws inspiration from the German *Autobahn* — designed for unrestricted, high-efficiency transit.

---

## Repository Structure

```text
AuthBahn/
├── AuthBahn/          # Chrome / Chromium extension source directory
│   ├── manifest.json  # WebExtension manifest (Manifest V3)
│   ├── background.js  # Service worker lifecycle scripts
│   ├── content.js     # Form detection and automated credential submission
│   ├── popup.html     # Extension toolbar popup interface
│   ├── popup.js       # Popup event handling
│   ├── portal.html    # Local credential management view
│   └── icons/assets   # Extension branding and graphics
└── __MACOSX/          # macOS archive metadata
```

---

## Installation

AuthBahn is compatible with all modern Chromium-based browsers, including Google Chrome, Brave, Microsoft Edge, and Chromium.

1. Clone or download this repository:
   ```bash
   git clone https://github.com/AshmitGarg69/Authbhan.git
   ```
2. Open your browser's extension management console:
   - **Chrome / Brave / Chromium**: `chrome://extensions`
   - **Microsoft Edge**: `edge://extensions`
3. Enable **Developer mode** using the toggle switch located in the upper-right corner.
4. Click **Load unpacked** in the top-left toolbar.
5. In the file picker, select the `AuthBahn` folder inside the repository directory.
6. The extension is now active. Pin it to your toolbar for quick access.

---

## Usage Guide

1. **Configuring Credentials**:
   - Click the AuthBahn toolbar icon.
   - Select **Add Fortigate ID** to display the credential configuration portal.
   - Enter your campus LDAP username and password, then select **Save Credentials**.
2. **Automatic Authentication**:
   - Connect to the IIITN Wi-Fi or Ethernet network.
   - When redirected to the Fortinet gateway (`192.168.55.253`), AuthBahn automatically populates and submits your credentials, redirecting to the server keepalive upon successful authorization.
3. **Session Management**:
   - To terminate your active session, open the extension popup and click **Logout**.

---

## Security & Privacy Model

- **Zero Telemetry**: AuthBahn operates in complete isolation on your local machine. No credentials, tokens, URLs, or browsing data are ever collected, logged, or sent to CRISPR or external servers.
- **Client-Side Storage**: All credentials are saved exclusively within the browser's sandboxed local storage (`chrome.storage.local`).
- **Targeted Scope**: Content scripts are restricted strictly to the campus captive portal domain (`192.168.55.253`).

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
