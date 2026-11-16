/**
 * CRISPR AuthBahn - Background Service Worker & ProxyManager
 * Manifest V3 compatible for both Chromium and Firefox.
 */

const INTRANET_BYPASS_LIST = [
  "127.0.0.1",
  "::1",
  "localhost",
  "<local>",
  "*.iiitn.ac.in",
  "iiitn.ac.in",
  "pravesh.iiitn.ac.in",
  "academic.iiitn.ac.in",
  "192.168.0.0/16",
  "192.168.55.253",
  "10.0.0.0/8",
  "172.16.0.0/12"
];

const FIREFOX_PASSTHROUGH = "<local>, 127.0.0.1, localhost, *.iiitn.ac.in, iiitn.ac.in, 192.168.0.0/16, 192.168.55.253, 10.0.0.0/8, 172.16.0.0/12";

const ProxyManager = {
  // Canonical Firefox detection: Firefox userAgent contains "Firefox"
  isFirefox: typeof navigator !== "undefined" && /firefox/i.test(navigator.userAgent),

  async setMode(mode) {
    // Apply the proxy config FIRST; only persist the mode on success so a
    // failed switch never leaves the UI (or startup) in a broken state.
    if (mode === "zero") {
      if (this.isFirefox) {
        await this._setFirefoxProxy("direct"); // clear manual settings; onRequest takes over
        await this._setZeroSetupFirefox();
      } else {
        await this._setZeroSetupChrome();
      }
    } else if (this.isFirefox) {
      await this._setFirefoxProxy(mode);
    } else if (typeof chrome !== "undefined" && chrome.proxy && chrome.proxy.settings) {
      await this._setChromeProxy(mode);
    } else {
      throw new Error("No supported proxy settings API found in this browser");
    }
    await chrome.storage.local.set({ proxyMode: mode });
  },

  // Build a PAC script from the shared crowd-sourced blocked list plus local
  // overrides. Used by Zero-Setup mode so members don't need the local daemon.
  async buildPacScript() {
    const data = await chrome.storage.local.get(["sharedList", "domainOverrides", "zeroProxy"]);
    const zeroProxy = data.zeroProxy || "192.168.77.84:3128";
    // Seed default blocked domains so Zero-Setup works immediately even before first server sync
    const domains = new Set([
      "store.steampowered.com",
      "steamcommunity.com",
      "steampowered.com",
      "epicgames.com",
      "discord.com",
      "discord.gg",
      "reddit.com",
      "pastebin.com"
    ]);
    for (const d of Object.keys(data.sharedList || {})) {
      if (d) domains.add(String(d).toLowerCase());
    }
    for (const [d, action] of Object.entries(data.domainOverrides || {})) {
      if (d && action === "tunnel") domains.add(String(d).toLowerCase());
    }
    const list = JSON.stringify(Array.from(domains));
    return (
      "function FindProxyForURL(url, host) {\n" +
      "  host = host.toLowerCase();\n" +
      "  if (host === 'localhost' || host.endsWith('.localhost') ||\n" +
      "      host.endsWith('.iiitn.ac.in') || host === 'iiitn.ac.in' ||\n" +
      "      shExpMatch(host, '192.168.*') || shExpMatch(host, '10.*') ||\n" +
      "      shExpMatch(host, '172.16.*') || shExpMatch(host, '172.17.*') ||\n" +
      "      shExpMatch(host, '172.18.*') || shExpMatch(host, '172.19.*') ||\n" +
      "      shExpMatch(host, '172.2?.*') || shExpMatch(host, '172.30.*') ||\n" +
      "      shExpMatch(host, '172.31.*') || shExpMatch(host, '127.*') ||\n" +
      "      host.endsWith('.local') || host.endsWith('.lan')) {\n" +
      "    return 'DIRECT';\n" +
      "  }\n" +
      "  var blocked = " + list + ";\n" +
      "  for (var i = 0; i < blocked.length; i++) {\n" +
      "    if (host === blocked[i] || host.endsWith('.' + blocked[i])) {\n" +
      "      return 'PROXY " + zeroProxy + "';\n" +
      "    }\n" +
      "  }\n" +
      "  return 'DIRECT';\n" +
      "}"
    );
  },

  async _setZeroSetupChrome() {
    const pac = await this.buildPacScript();
    return new Promise((resolve, reject) => {
      chrome.proxy.settings.set({
        value: { mode: "pac_script", pacScript: { data: pac, mandatory: false } },
        scope: "regular"
      }, () => {
        if (chrome.runtime && chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message || String(chrome.runtime.lastError)));
        } else {
          resolve();
        }
      });
    });
  },

  async _setZeroSetupFirefox() {
    // Firefox: dynamic proxy routing via onRequest listener
    const api = typeof browser !== "undefined" ? browser : chrome;
    if (api.proxy && api.proxy.onRequest && !this._ffListenerAdded) {
      const self = this;
      api.proxy.onRequest.addListener(async (requestInfo) => {
        const pac = await self.buildPacScript();
        // Evaluate the PAC logic directly (no eval in SW: rebuild decision inline)
        const host = (requestInfo.url && new URL(requestInfo.url).hostname || "").toLowerCase();
        const data = await chrome.storage.local.get(["sharedList", "domainOverrides", "zeroProxy"]);
        const zeroProxy = data.zeroProxy || "192.168.77.84:3128";
        if (host === "localhost" || host.endsWith(".localhost") ||
            host.endsWith(".iiitn.ac.in") || host === "iiitn.ac.in" ||
            host.endsWith(".local") || host.endsWith(".lan") ||
            /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(host)) {
          return [{ type: "direct" }];
        }
        const domains = new Set([
          "store.steampowered.com",
          "steamcommunity.com",
          "steampowered.com",
          "epicgames.com",
          "discord.com",
          "discord.gg",
          "reddit.com",
          "pastebin.com"
        ]);
        for (const d of Object.keys(data.sharedList || {})) {
          if (d) domains.add(String(d).toLowerCase());
        }
        for (const [d, action] of Object.entries(data.domainOverrides || {})) {
          if (d && action === "tunnel") domains.add(String(d).toLowerCase());
        }
        for (const d of domains) {
          if (host === d || host.endsWith("." + d)) {
            return [{ type: "http", host: zeroProxy.split(":")[0], port: parseInt(zeroProxy.split(":")[1] || "3128", 10) }];
          }
        }
        return [{ type: "direct" }];
      });
      this._ffListenerAdded = true;
    }
    return Promise.resolve();
  },

  _setChromeProxy(mode) {
    return new Promise((resolve, reject) => {
      let config;
      if (mode === "smart") {
        config = {
          mode: "fixed_servers",
          rules: {
            singleProxy: {
              scheme: "http",
              host: "127.0.0.1",
              port: 8080
            },
            bypassList: INTRANET_BYPASS_LIST
          }
        };
      } else if (mode === "full") {
        config = {
          mode: "fixed_servers",
          rules: {
            singleProxy: {
              scheme: "socks5",
              host: "127.0.0.1",
              port: 1088
            },
            bypassList: INTRANET_BYPASS_LIST
          }
        };
      } else {
        // Direct
        config = { mode: "direct" };
      }

      chrome.proxy.settings.set({ value: config, scope: "regular" }, () => {
        if (chrome.runtime && chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message || String(chrome.runtime.lastError)));
        } else {
          resolve();
        }
      });
    });
  },

  _setFirefoxProxy(mode) {
    return new Promise((resolve, reject) => {
      let config;
      if (mode === "smart") {
        config = {
          proxyType: "manual",
          http: "http://127.0.0.1:8080",
          ssl: "http://127.0.0.1:8080",
          passthrough: FIREFOX_PASSTHROUGH
        };
      } else if (mode === "full") {
        config = {
          proxyType: "manual",
          socks: "127.0.0.1:1088",
          socksVersion: 5,
          proxyDNS: true,
          passthrough: FIREFOX_PASSTHROUGH
        };
      } else {
        // Direct
        config = { proxyType: "none" };
      }

      const api = (typeof browser !== "undefined" ? browser : chrome);
      api.proxy.settings.set({ value: config, scope: "regular" }, () => {
        if (api.runtime && api.runtime.lastError) {
          reject(new Error(api.runtime.lastError.message || String(api.runtime.lastError)));
        } else {
          resolve();
        }
      });
    });
  }
};

// Pre-fetch shared crowd-sourced blocked list from club server
function prefetchSharedList() {
  chrome.storage.local.get(["listServer"], (data) => {
    const base = (data.listServer || "http://192.168.77.84:8081").replace(/\/+$/, "");
    try {
      fetch(`${base}/smart/list`)
        .then((r) => (r.ok ? r.json() : null))
        .then((list) => {
          if (list && list.blocked_domains) {
            chrome.storage.local.set({ sharedList: list.blocked_domains, sharedListUpdated: Date.now() });
          }
        })
        .catch(() => {});
    } catch (e) {}
  });
}

// Initialize default proxy mode on startup
chrome.runtime.onInstalled.addListener(() => {
  prefetchSharedList();
  chrome.storage.local.get(["proxyMode"], (data) => {
    const mode = data.proxyMode || "smart";
    ProxyManager.setMode(mode).catch(() => {});
  });
});

if (chrome.runtime.onStartup) {
  chrome.runtime.onStartup.addListener(() => {
    prefetchSharedList();
    chrome.storage.local.get(["proxyMode"], (data) => {
      const mode = data.proxyMode || "smart";
      ProxyManager.setMode(mode).catch(() => {});
    });
  });
}

// Runtime message listener for popup and content scripts
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && (changes.sharedList || changes.domainOverrides)) {
    chrome.storage.local.get(["proxyMode"], (data) => {
      if (data.proxyMode === "zero") {
        ProxyManager.setMode("zero").catch(() => {});
      }
    });
  }
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "getCredentials") {
    chrome.storage.local.get(["username", "password"], (data) => {
      sendResponse(data || {});
    });
    return true;
  }
  if (request.action === "setProxyMode") {
    ProxyManager.setMode(request.mode)
      .then(() => sendResponse({ success: true, mode: request.mode }))
      .catch((err) => sendResponse({ success: false, error: (err && err.message) || String(err) }));
    return true;
  }
  if (request.action === "getProxyMode") {
    chrome.storage.local.get(["proxyMode"], (data) => {
      sendResponse({ mode: data.proxyMode || "smart" });
    });
    return true;
  }
});
