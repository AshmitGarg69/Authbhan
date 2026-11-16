# Club Server Setup — 192.168.77.84 (crisper)

This makes the tunnel **scalable for the whole campus without SSH keys**.
Members never need accounts: their smart-proxy daemon or AuthBahn extension
talks to a hardened Squid proxy + shared blocked-domain list on this server.

Architecture after setup:

```
mate's laptop (no SSH key!)                 club server (192.168.77.84)
┌────────────────────────────┐              ┌──────────────────────────────┐
│ AuthBahn extension         │              │ squid :3128  (CONNECT proxy, │
│  ├─ Smart mode → 127.0.0.1:8080 (daemon)  │   campus-only, rate-limited, │
│  └─ Zero-Setup → PAC list ─┼──────────────┼→  no intranet pivots)        │
│ smart-proxy daemon ────────┼──────────────┼→ squid :3128                 │
│   probes, caches, TTLs     │              │ smart-list :8081 (crowd list)│
└────────────────────────────┘              └──────────────────────────────┘
```

---

## 1. On the server (192.168.77.84)

SSH in from your laptop (`ssh crisper@192.168.77.84`), then:

```bash
# --- 1a. Squid proxy (the escape hatch everyone shares) ---
sudo apt update && sudo apt install -y squid apache2-utils
sudo cp /etc/squid/squid.conf /etc/squid/squid.conf.bak.$(date +%s)

# Copy the hardened config from this repo (from your laptop, or scp it over):
#   scp deploy/squid.conf crisper@192.168.77.84:/tmp/squid.conf
sudo install -m 0644 /tmp/squid.conf /etc/squid/squid.conf

sudo mkdir -p /var/log/squid && sudo chown -R proxy:proxy /var/log/squid
sudo systemctl enable --now squid
sudo systemctl reload squid

# Verify it's listening:
ss -tlnp | grep 3128

# --- 1b. Shared blocked-domain crowd list service ---
sudo mkdir -p /opt/smart-tunnel /var/lib/smart-tunnel
sudo chown nobody:nogroup /var/lib/smart-tunnel

# From your laptop:
#   scp deploy/smart-list-service.py crisper@192.168.77.84:/tmp/
#   scp deploy/smart-list.service     crisper@192.168.77.84:/tmp/
sudo install -m 0755 /tmp/smart-list-service.py /opt/smart-tunnel/
sudo install -m 0644 /tmp/smart-list.service /etc/systemd/system/smart-list.service
sudo systemctl daemon-reload
sudo systemctl enable --now smart-list

# Verify:
curl -s http://127.0.0.1:8081/health
curl -s http://127.0.0.1:8081/smart/list

# --- 1c. Firewall: only campus subnets may reach these ports ---
# (skip ufw rules if the campus LAN is already trusted; these are belt-and-suspenders)
sudo ufw allow from 192.168.0.0/16 to any port 3128 proto tcp
sudo ufw allow from 10.0.0.0/8     to any port 3128 proto tcp
sudo ufw allow from 172.16.0.0/12  to any port 3128 proto tcp
sudo ufw allow from 192.168.0.0/16 to any port 8081 proto tcp
sudo ufw allow from 10.0.0.0/8     to any port 8081 proto tcp
sudo ufw allow from 172.16.0.0/12  to any port 8081 proto tcp

# --- 1d. (OPTIONAL but recommended) one shared club token ---
# Prevents random campus devices from using your proxy. Still zero per-user
# setup: the token goes in the extension/daemon config once.
sudo htpasswd -c /etc/squid/club_passwd club     # set a password when asked
sudo chmod 640 /etc/squid/club_passwd && sudo chown proxy:proxy /etc/squid/club_passwd
sudoedit /etc/squid/squid.conf                   # uncomment the two `club` lines
sudo systemctl reload squid
```

### Test from a member's laptop (no SSH key needed!)

```bash
# Direct escape-hatch test (should return the SERVER's public IP, 103.55.74.154):
curl -s -m 10 -x http://192.168.77.84:3128 https://icanhazip.com

# Crowd list test:
curl -s -m 5 http://192.168.77.84:8081/smart/list

# Confirm intranet pivots are BLOCKED (should fail / be denied):
curl -s -m 5 -x http://192.168.77.84:3128 http://192.168.55.253/ && echo BAD || echo "GOOD: pivot denied"
```

---

## 2. On each member's laptop (zero root, zero keys)

### Option A — full smart mode (recommended)

```bash
# Get the repo (scp/usb/whatever), then:
cd smart-tunnel
python3 bin/smart-tunnel install

# Point the daemon at the club proxy instead of an SSH tunnel:
mkdir -p ~/.config/smart-tunnel
cat >> ~/.config/smart-tunnel/config.env <<EOF
UPSTREAM_PROXY="http://192.168.77.84:3128"
SYNC_URL="http://192.168.77.84:8081"
EOF

smart-tunnel start          # daemon only; NO ssh needed
smart-tunnel status
```

Then load the AuthBahn extension (unpacked) → mode **Smart Auto**.
The daemon probes locally, caches routes with TTLs, and shares newly-found
blocked domains to the club list so everyone benefits.

### Option B — zero-setup (browser only, no daemon)

Load the AuthBahn extension → mode **Zero-Setup**.
The extension fetches the shared blocked list from `192.168.77.84:8081` and
routes only those domains through `192.168.77.84:3128` via a PAC script.
Everything else goes direct. Blocked site not in the list yet?
Open the popup → **Force Tunnel** adds it locally (and the next smart-mode
user's daemon report adds it for everyone).

---

## 3. Maintenance cheat-sheet (server)

```bash
sudo systemctl status squid smart-list
sudo tail -f /var/log/squid/access.log          # live proxy activity
sudo tail -f /var/log/squid/cache.log
cat /var/lib/smart-tunnel/shared_list.json | python3 -m json.tool | head
# Bandwidth/connection caps live in /etc/squid/squid.conf (maxconn + delay pools)
```
