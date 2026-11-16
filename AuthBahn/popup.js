/**
 * CRISPR AuthBahn - Popup Controller
 * Manages mode switching, status polling, domain overrides, and credentials.
 */

const SMART_PROXY_API = "http://127.0.0.1:8080";
// Club shared crowd-sourced blocked-list service (Zero-Setup mode data source)
const DEFAULT_LIST_SERVER = "http://192.168.77.84:8081";
let activeTabDomain = "";

// Fetch the shared blocked-domain list from the club server and cache it.
// Used by Zero-Setup PAC mode; safe to call when the server is unreachable.
function refreshSharedList(showStatus, done) {
  chrome.storage.local.get(["listServer"], (data) => {
    const base = (data.listServer || DEFAULT_LIST_SERVER).replace(/\/+$/, "");
    let timeoutId;
    try {
      const controller = new AbortController();
      timeoutId = setTimeout(() => controller.abort(), 4000);
      fetch(`${base}/smart/list`, { signal: controller.signal })
        .then((resp) => {
          clearTimeout(timeoutId);
          if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
          return resp.json();
        })
        .then((list) => {
          const domains = list && list.blocked_domains ? list.blocked_domains : {};
          chrome.storage.local.set({ sharedList: domains, sharedListUpdated: Date.now() }, () => {
            if (showStatus) showMessage(`Shared list updated (${Object.keys(domains).length} domains)`);
            if (typeof done === "function") done();
          });
        })
        .catch(() => {
          if (showStatus) showMessage("Shared list server unreachable; using cached list.");
          if (typeof done === "function") done();
        });
    } catch (e) {
      clearTimeout(timeoutId);
      if (typeof done === "function") done();
    }
  });
}

document.addEventListener("DOMContentLoaded", () => {
  // 1. If inside portal.html (LDAP Credentials dialog)
  const saveBtn = document.getElementById("saveButton");
  if (saveBtn) {
    saveBtn.addEventListener("click", saveCredentials);
    checkAndShowSavedMessage();
    return;
  }

  // 2. If inside popup.html
  initToggleSwitch();
  initModeSwitcher();
  initDomainOverride();
  initStatsAndHealth();
  detectActiveTab();
  pollDaemonStatus();
});

// --- Smart Tunnel Toggle Switch (at bottom) ---
function initToggleSwitch() {
  const toggle = document.getElementById("tunnelToggle");
  const statusText = document.getElementById("tunnelStatusText");
  if (!toggle) return;

  function updateStatus(mode) {
    if (!statusText) return;
    if (mode === "smart") {
      statusText.textContent = "Active (Smart Daemon :8080)";
      statusText.style.color = "#1da892";
    } else if (mode === "zero") {
      statusText.textContent = "Active (Zero-Setup Proxy)";
      statusText.style.color = "#1da892";
    } else if (mode === "full") {
      statusText.textContent = "Active (Full SOCKS5 :1088)";
      statusText.style.color = "#1da892";
    } else {
      statusText.textContent = "Direct (Tunnel Disabled)";
      statusText.style.color = "#6c757d";
    }
  }

  chrome.storage.local.get(["proxyMode"], (data) => {
    const mode = data.proxyMode || "direct";
    const isEnabled = (mode === "smart" || mode === "zero" || mode === "full");
    toggle.checked = isEnabled;
    updateStatus(mode);
  });

  toggle.addEventListener("change", async () => {
    if (toggle.checked) {
      let chosenMode = "zero";
      try {
        const c = new AbortController();
        const tid = setTimeout(() => c.abort(), 300);
        const r = await fetch(`${SMART_PROXY_API}/_smart/status`, { signal: c.signal });
        clearTimeout(tid);
        if (r.ok) chosenMode = "smart";
      } catch (e) {
        chosenMode = "zero";
      }

      const apply = () => {
        chrome.runtime.sendMessage({ action: "setProxyMode", mode: chosenMode }, (resp) => {
          if (resp && resp.success) {
            updateStatus(chosenMode);
            setActiveModeButton(chosenMode);
            showMessage(`Smart Tunnel: ON (${chosenMode === "smart" ? "Daemon" : "Zero-Setup"})`);
          } else {
            toggle.checked = false;
            updateStatus("direct");
            showMessage(`Error: ${(resp && resp.error) || "Failed to enable tunnel"}`);
          }
        });
      };

      if (chosenMode === "zero") {
        refreshSharedList(false, apply);
      } else {
        apply();
      }
    } else {
      chrome.runtime.sendMessage({ action: "setProxyMode", mode: "direct" }, (resp) => {
        if (resp && resp.success) {
          updateStatus("direct");
          setActiveModeButton("direct");
          showMessage("Smart Tunnel: OFF (Direct Connection)");
        } else {
          toggle.checked = true;
          showMessage("Failed to disable tunnel");
        }
      });
    }
  });
}

// --- Mode Switcher ---
function initModeSwitcher() {
  const modes = ["modeSmart", "modeZero", "modeFull", "modeDirect"];
  const modeMap = { modeSmart: "smart", modeZero: "zero", modeFull: "full", modeDirect: "direct" };

  chrome.storage.local.get(["proxyMode"], (data) => {
    const currentMode = data.proxyMode || "smart";
    setActiveModeButton(currentMode);
  });

  modes.forEach((btnId) => {
    const btn = document.getElementById(btnId);
    if (!btn) return;
    btn.addEventListener("click", () => {
      const mode = modeMap[btnId];
      const apply = () => {
        chrome.runtime.sendMessage({ action: "setProxyMode", mode }, (resp) => {
          if (resp && resp.success) {
            setActiveModeButton(mode);
            if (mode === "zero") refreshSharedList(true);
            showMessage(`Mode set to ${mode.toUpperCase()}`);
          } else {
            const err = (resp && resp.error) || "Failed to set proxy mode";
            showMessage(`Error: ${err}`);
          }
        });
      };
      if (mode === "zero") {
        // Ensure a shared list exists before switching
        refreshSharedList(false, apply);
      } else {
        apply();
      }
    });
  });
}

function setActiveModeButton(mode) {
  const toggle = document.getElementById("tunnelToggle");
  const statusText = document.getElementById("tunnelStatusText");
  if (toggle) {
    toggle.checked = (mode === "smart" || mode === "zero" || mode === "full");
  }
  if (statusText) {
    if (mode === "smart") {
      statusText.textContent = "Active (Smart Daemon :8080)";
      statusText.style.color = "#1da892";
    } else if (mode === "zero") {
      statusText.textContent = "Active (Zero-Setup Proxy)";
      statusText.style.color = "#1da892";
    } else if (mode === "full") {
      statusText.textContent = "Active (Full SOCKS5 :1088)";
      statusText.style.color = "#1da892";
    } else {
      statusText.textContent = "Direct (Tunnel Disabled)";
      statusText.style.color = "#6c757d";
    }
  }

  const buttons = document.querySelectorAll(".btn-switch");
  buttons.forEach((btn) => {
    if (btn.getAttribute("data-mode") === mode) {
      btn.classList.add("active");
    } else {
      btn.classList.remove("active");
    }
  });
}

// --- Active Tab Domain & Override ---
function detectActiveTab() {
  const domainLabel = document.getElementById("currentDomain");
  if (!domainLabel) return;

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs && tabs[0] && tabs[0].url) {
      try {
        const urlObj = new URL(tabs[0].url);
        if (urlObj.protocol.startsWith("http")) {
          activeTabDomain = urlObj.hostname;
          domainLabel.textContent = activeTabDomain;
          return;
        }
      } catch (e) {}
    }
    domainLabel.textContent = "No active web page";
  });
}

function initDomainOverride() {
  const forceBtn = document.getElementById("forceTunnel");
  if (forceBtn) {
    forceBtn.addEventListener("click", async () => {
      if (!activeTabDomain) {
        showMessage("No active domain detected.");
        return;
      }

      try {
        const resp = await fetch(`${SMART_PROXY_API}/_smart/override`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ domain: activeTabDomain, action: "tunnel" })
        });
        if (resp.ok) {
          showMessage(`Forced tunnel for ${activeTabDomain}`);
          pollDaemonStatus();
        } else {
          showMessage(`Failed to override domain (HTTP ${resp.status})`);
        }
      } catch (e) {
        // Local fallback in storage (also feeds Zero-Setup PAC mode)
        chrome.storage.local.get(["domainOverrides"], (data) => {
          const overrides = data.domainOverrides || {};
          overrides[activeTabDomain] = "tunnel";
          chrome.storage.local.set({ domainOverrides: overrides }, () => {
            showMessage(`Saved offline override for ${activeTabDomain}`);
          });
        });
      }
    });
  }

  const forceDirectBtn = document.getElementById("forceDirect");
  if (forceDirectBtn) {
    forceDirectBtn.addEventListener("click", async () => {
      if (!activeTabDomain) {
        showMessage("No active domain detected.");
        return;
      }

      try {
        const resp = await fetch(`${SMART_PROXY_API}/_smart/override`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ domain: activeTabDomain, action: "direct" })
        });
        if (resp.ok) {
          showMessage(`Forced direct for ${activeTabDomain}`);
          pollDaemonStatus();
        } else {
          showMessage(`Failed to override domain (HTTP ${resp.status})`);
        }
      } catch (e) {
        chrome.storage.local.get(["domainOverrides"], (data) => {
          const overrides = data.domainOverrides || {};
          overrides[activeTabDomain] = "direct";
          chrome.storage.local.set({ domainOverrides: overrides }, () => {
            showMessage(`Saved offline direct override for ${activeTabDomain}`);
          });
        });
      }
    });
  }
}

// --- Stats and Health Monitoring ---
function initStatsAndHealth() {
  const refreshBtn = document.getElementById("btnRefresh");
  if (refreshBtn) {
    refreshBtn.addEventListener("click", () => {
      pollDaemonStatus();
      detectActiveTab();
    });
  }

  const clearBtn = document.getElementById("clearCache");
  if (clearBtn) {
    clearBtn.addEventListener("click", async () => {
      try {
        const resp = await fetch(`${SMART_PROXY_API}/_smart/cache/clear`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({})
        });
        if (resp.ok) {
          showMessage("Cache cleared.");
          pollDaemonStatus();
        }
      } catch (e) {
        showMessage("Daemon offline; cannot clear remote cache.");
      }
    });
  }
}

async function pollDaemonStatus() {
  const badge = document.getElementById("statusBadge");
  const latencyLabel = document.getElementById("latency");
  const countLabel = document.getElementById("blockedCount");
  const recentList = document.getElementById("recentDomains");

  const startTime = Date.now();
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 1200);

    const resp = await fetch(`${SMART_PROXY_API}/_smart/status`, {
      signal: controller.signal
    });
    clearTimeout(timeoutId);

    const latency = Date.now() - startTime;
    if (resp.ok) {
      const data = await resp.json();
      const isTunnelHealthy = data.tunnel && data.tunnel.active;
      if (badge) {
        if (isTunnelHealthy) {
          badge.textContent = "Online";
          badge.className = "badge badge-online";
        } else {
          badge.textContent = "Tunnel Offline";
          badge.className = "badge badge-degraded";
        }
      }
      if (latencyLabel) {
        latencyLabel.textContent = `Latency: ${latency} ms`;
      }
      if (countLabel) {
        const cnt = (data.cache && typeof data.cache.blocked_domains_count === "number")
          ? data.cache.blocked_domains_count
          : 0;
        countLabel.textContent = String(cnt);
      }
      if (recentList && data.recent_blocked) {
        recentList.innerHTML = "";
        data.recent_blocked.slice(0, 5).forEach((d) => {
          const item = document.createElement("span");
          item.className = "recent-item";
          const domainName = (typeof d === "object" && d !== null) ? (d.domain || JSON.stringify(d)) : String(d);
          item.textContent = domainName;
          recentList.appendChild(item);
        });
      }
      // Save stats to storage for offline fallback
      chrome.storage.local.set({ cachedStats: data });
    } else {
      throw new Error(`HTTP ${resp.status}`);
    }
  } catch (err) {
    if (badge) {
      badge.textContent = "Offline";
      badge.className = "badge badge-offline";
    }
    if (latencyLabel) {
      latencyLabel.textContent = "Latency: -- ms";
    }
    // Attempt fallback from storage
    chrome.storage.local.get(["cachedStats"], (sdata) => {
      if (sdata && sdata.cachedStats && countLabel) {
        const cached = sdata.cachedStats;
        const cnt = (cached.cache && typeof cached.cache.blocked_domains_count === "number")
          ? cached.cache.blocked_domains_count
          : 0;
        countLabel.textContent = String(cnt);
      }
    });
  }
}

function showMessage(msg) {
  const container = document.getElementById("message");
  if (!container) return;
  container.textContent = msg;
  container.className = "active";
  setTimeout(() => {
    container.textContent = "";
    container.className = "";
  }, 2500);
}

// --- LDAP Credential Helpers (portal.html) ---
function saveCredentials() {
  const usernameInput = document.getElementById("username");
  const passwordInput = document.getElementById("password");
  if (!usernameInput || !passwordInput) return;

  const username = usernameInput.value;
  const password = passwordInput.value;

  chrome.storage.local.set({ username, password }, () => {
    showSavedMessage();
  });
}

function checkAndShowSavedMessage() {
  chrome.storage.local.get(["username", "password"], (data) => {
    if (data && data.username && data.password) {
      const u = document.getElementById("username");
      if (u) u.value = data.username;
    }
  });
}

function showSavedMessage() {
  const msgContainer = document.getElementById("message");
  if (!msgContainer) return;
  msgContainer.textContent = "Credentials saved!";
  msgContainer.className = "active saved-message";
  setTimeout(() => {
    msgContainer.textContent = "";
    msgContainer.className = "";
  }, 3000);
}
