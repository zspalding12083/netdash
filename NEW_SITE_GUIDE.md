# Setting up netdash at a site

How to install netdash at a site that runs **pfSense and UniFi**, with or without
a cable modem. It's written so a Claude Code session, or a person, can follow it
step by step. It records the problems hit on the original install and how each
was solved.

**Every site runs the same code.** A site differs only in its `/etc/netdash.env`,
its deploy settings and, optionally, a brand folder (logo and colours). Start each
site's project folder as a clone, so fixes can move between sites:

```bash
git clone https://github.com/zspalding12083/netdash.git <site folder>
```

Keep site-only notes (addresses, hardware, quirks) in a `SITE.md` in the site's
folder. Don't commit secrets: `*.env` files are git-ignored apart from the
`deploy/*.env.example` templates.

Points marked *unverified* weren't tested on the original install, so check them
on site.

---

## 1. What netdash is

One Python process, **standard library only** (no pip). It's written for
Python 3.10 (Ubuntu 22.04). It polls each data source in a background thread,
keeps history in its own SQLite file, and serves one HTML page plus JSON at
`/api/...`.

| File | Role |
|---|---|
| `netdash/unifi.py` | UniFi client: UniFi OS (login, CSRF token) or the classic controller, re-login on 401, 15-minute backoff after a rejected login. Parses `stat/sta` (clients) and `stat/device` (APs, switches) |
| `netdash/pfsense.py` | pfSense REST API (pfrest v2) client. Parses system, gateways, interfaces (32-bit counter wrap), DHCP leases, ARP table, firewall rules and the filterlog lines |
| `netdash/ident.py` | Names addresses (leases, ARP, UniFi, MAC inside EUI-64 IPv6, multicast groups, reverse DNS in the background). Labels each firewall block and flags routine noise |
| `netdash/store.py` | netdash's SQLite: Wi-Fi samples, AP samples, clients seen, interface throughput, router health, gateways, firewall events, per-device bytes per hour, users and sessions. Schema lives in code; columns added by small migrations |
| `netdash/server.py` | Poller threads (UniFi every 60 s, pfSense every 30 s), the HTTP API, login and logout, security headers, optional HTTPS, the brand folder |
| `netdash/auth.py` | Logins for a few people: PBKDF2 password hashes, session cookies, lockout after repeated failures (§7) |
| `netdash/modem.py` | Reads [modem_check](https://github.com/zspalding12083/modem_check)'s database (ARRIS SB8200), read-only. Off when there's no modem |
| `netdash/static/index.html`, `login.html` | The whole page (light/dark CSS tokens, cards, hand-drawn SVG charts with hover) and the sign-in page. Modem parts hide when there's no modem |
| `deploy/` | `netdash.service` and `netdash.env.example` (a box that also runs modem_check), `netdash-site.service` and `netdash-site.env.example` (sites without a modem), `sync.sh push/backup/check` |
| `tests/` | unittest tests: captured API shapes, logins and the real HTTP handler, a fake classic controller, no-modem and multi-WAN |

Run the tests with `python3 -m unittest discover -s tests -t .`

### What the page shows

- **Internet, with a modem:** status, download, upload, ping, modem signal and outages from modem_check, plus current WAN traffic and the pfSense gateway monitor.
- **Internet, without a modem:** status from pfSense's gateway monitor for every gateway (multi-WAN, e.g. "1 of 2 connections down"). Latency, loss and jitter per gateway, with latency and loss charts, outages (a gateway down or losing 50% or more), and current traffic summed across WANs.
- **Router & traffic:** pfSense CPU, memory, temperature (°F) and uptime. Per-network table with current Mbps and DHCP devices online. Charts of WAN download and upload, download per network, and CPU. **Data transferred** per network for Day, Week, Month and All.
- **Top devices by traffic:** right now (live rate), or day, week, month or all (UniFi per-device counters, stored per hour).
- **Firewall blocks:** per interface, most blocked and latest, each with device or host names and a plain-language label. "Hide routine" is on by default.
- **Wi-Fi:** a card per AP (clients, channel, how busy each radio is), clients per AP over time, and a sortable, filterable client table. Weak signal (below −80 dBm) is in red; click a client for a week of its signal.

---

## 2. Before starting: questions to settle

1. **Permission.** If the network isn't yours (a workplace, a club, a volunteer organisation), get approval from whoever is responsible for it before installing a monitoring box. Firewall logs and client lists show what people's devices do, so treat them as sensitive.
2. **Where it runs.** It needs a small always-on Linux box *on site*, such as a Pi, a VM or a NAS with Docker. It must reach the pfSense web port and the UniFi controller. Find out what's available and which VLAN it sits on.
3. **How you reach it.** Remote sites need VPN or SSH access from wherever development happens. Agree on this before writing code.
4. **What the UniFi controller is.** UniFi OS console (UDM, UDR, Cloud Key Gen2+, UniFi OS Server), the classic self-hosted Network application, or cloud-only. This decides the API paths (§4).
5. **pfSense version and hardware.** Run `cat /etc/version` and `uname -m` in the pfSense shell. The REST API package build must match the version exactly (§3).
6. **Who views the dashboard.** Logins are off by default. On any shared network, turn them on, use HTTPS, create an account for each person, and add a firewall rule limiting who can reach the port (§7).
7. **Multi-WAN?** Business sites often have two internet connections. netdash stores and shows every gateway (§6).

---

## 3. pfSense: REST API setup (step by step)

The package is **pfrest** (`pfSense-pkg-RESTAPI`), from https://github.com/pfrest/pfSense-pkg-RESTAPI/releases.
v2.10.2 was used for the original install. The API key goes in the `X-API-Key` header.

1. **Pick the right build.** Each release has one `.pkg` per pfSense version. v2.10.2 has 2.8.1, 2.9.0, 25.11.1, 26.03, 26.03.1 and 26.07. The original install is **pfSense Plus 26.07**; the first attempt failed because it used the **2.8.1 (CE)** build.
2. **Download it on another machine.** On pfSense, `pkg-static add https://github.com/...` failed with a certificate error: pfSense didn't trust the Sectigo root GitHub's download server uses. Download on a laptop instead. Check the size against GitHub's listing, or the sha256.
3. **Get it onto pfSense.** `scp` can be awkward because of password prompts. The easy route: **Diagnostics → Command Prompt → Upload File**, which saves to `/tmp/`. Then run `pkg-static add /tmp/pfSense-<version>-pkg-RESTAPI.pkg`.
   - A **"not supported on 32-bit systems"** warning appears on 32-bit hardware. The original install is a **Netgate 3100** (ARM Cortex-A9, 32-bit), and every read endpoint netdash uses works there anyway.
   - Reinstall the package after every pfSense upgrade, because the upgrade removes it. With **Keep Backup** on (the default), the settings, users and keys come back when you reinstall.
4. **System → REST API → Settings:**
   - **Authentication Methods:** the default is *Local database* only, meaning username and password. Add **Key**, and keep Local database for now; it's needed to create the key.
   - **Allowed Interfaces:** choose the interface the dashboard box's traffic **arrives on**, judged by the pfSense IP address it connects to. A box connecting to the LAN address needs **LAN**, even if another interface's name sounds more like "the main network". Choosing the wrong one gives `ENDPOINT_INTERFACE_NOT_ALLOWED`. Check **Status → Interfaces** to see which interface has the address being used.
   - pfSense checks the interface **before** the password. A wrong interface gives the same 403 with or without a correct login, so it tells you nothing about the password.
   - Leave **Login Protection** on. Repeated failed logins block the address temporarily, so don't retry in a loop.
   - **Access List** tab: you can also restrict the API to the dashboard box's IP.
5. **System → User Manager → Add `netdash`.**
   - **Save the new user first.** The *Effective Privileges* section only appears when you edit a saved user; skipping this produces 401s.
   - Watch for the browser auto-filling the password box with a saved password, such as the admin one.
   - Not in `admins`. Add only these privileges:
     - `api-v2-status-system-get`
     - `api-v2-status-gateways-get`
     - `api-v2-status-interfaces-get`
     - `api-v2-status-dhcp-server-leases-get`
     - `api-v2-diagnostics-arp-table-get`
     - `api-v2-status-logs-firewall-get`
     - `api-v2-firewall-rules-get` (optional: rule names in the firewall card)
     - `api-v2-auth-key-post`, **temporarily**, so the user can create its own key
6. **Test the password.** Run `curl -sk -u netdash https://<pfsense>/api/v2/system/version`.
   - `AUTH_AUTHORIZATION_FAILED` (403) means the password is right; that endpoint just isn't granted.
   - `AUTH_AUTHENTICATION_FAILED` (401) means a wrong password, an unsaved user, or Local database not enabled.
7. **Create the key straight into the env file.** Run this on the dashboard box so the key never appears on screen:
   ```bash
   curl -sk -u netdash https://<pfsense>/api/v2/auth/key -H "Content-Type: application/json" -d '{"descr":"netdash"}' \
     | python3 -c 'import json,sys; r=json.load(sys.stdin); k=(r.get("data") or {}).get("key"); open("/etc/netdash.env","a").write("NETDASH_PFSENSE_URL=https://<pfsense>\nNETDASH_PFSENSE_KEY=%s\n" % k) if k else None; print("key saved" if k else r)'
   ```
8. **Lock it down:**
   - Remove `auth-key-post` from the user.
   - Under Authentication Methods, select **Key** only.
   - Turn on **Read Only**. It can only be turned off again from the web interface.
   - Check that GETs still work and that a POST is refused.

### pfSense API behaviour netdash depends on

- **Interface byte counters are 32-bit** on the Netgate 3100 and come back **signed**, so negative numbers appear. They wrap about every 100 s at 340 Mbps. netdash stores them modulo 2³², polls every 30 s and takes deltas modulo 2³². On faster links or 64-bit hardware, check whether the counters are wider. *Unverified elsewhere.*
- `status/interfaces` returns `enable: false` for every interface, including active ones. Use `status == "up"` instead.
- Interface `name` is pfSense's internal id (`wan`, `lan`, `opt3`) and `descr` is the label shown in the web interface. netdash keys history by `descr`.
- **DHCP leases** often have a blank `if`. netdash works out the interface from the IP and the interface subnets.
- **Firewall log** (`status/logs/firewall`):
  - Each entry is a raw syslog `text` line.
  - `?limit=N` returns the **newest N lines**, oldest first within the batch. `offset` behaved oddly. `sort_by=id` returns 400.
  - `limit=0` returns the whole log: about 21,000 lines in 4.8 s on the 3100.
  - pfSense keeps only a few hours, so netdash fetches the newest 1,000 every 2 minutes and drops duplicates in SQLite.
  - The duplicate check is a **unique index with `ifnull(...)`**, because ICMP lines have no ports and NULLs never compare equal.
- **filterlog fields** (by position after the colon): 3 rule tracker id, 4 real interface (e.g. `mvneta1.130`), 6 action, 7 direction, 8 IP version.
  - IPv4: 16 protocol name, 18 source, 19 destination, 20 source port, 21 destination port, 23 TCP flags.
  - IPv6: 12 protocol name, 15 source, 16 destination, 17 source port, 18 destination port, 20 TCP flags.
- **Gateway monitor:** by default pfSense pings the ISP's gateway, and some ISPs' gateways don't answer pings. pfSense then reports WAN **down with 100% loss** while the internet works fine. When modem_check data is available, the page explains this instead of raising an alarm. **Without a modem, the gateway monitor is the main internet-health source**, so set a monitor IP that answers, such as `1.1.1.1` or `8.8.8.8`, in **System → Routing → Gateways**.

---

## 4. UniFi: account and API paths

- Create a **local View Only admin** for netdash (e.g. `netdash-ro`), separate for each site.
- **Passwords containing `$`:** never load `/etc/netdash.env` with `. file` or `set -a` in a shell. The shell mangles the `$` and the wrong password is sent. During the original install, two hand tests did exactly that and **locked the account** (`AUTHENTICATION_FAILED_ACCOUNT_LOCKED`); it had to be unlocked in the UniFi web interface. systemd's `EnvironmentFile` reads the value as-is, so the service itself was fine. For hand tests, parse the file in Python (split each line on the first `=`), and never print the values.
- **UniFi OS** (UniFi OS Server, UDM, UDR, Cloud Key Gen2+):
  - log in with `POST /api/auth/login` and JSON `{username, password, remember:false}`
  - keep the `TOKEN` cookie and send the `X-CSRF-Token` response header back on later requests
  - data comes from `GET /proxy/network/api/s/<site>/stat/sta` and `.../stat/device`
- **Classic self-hosted controller**: `POST /api/login` and `GET /api/s/<site>/stat/...`, without `/proxy/network`. Usually on port 8443. Set `NETDASH_UNIFI_KIND=classic`. Tested against a fake controller in `tests/test_unifi.py`, *not yet against a real one*.
- **Cloud-only** (managed only through unifi.ui.com): there's no local controller to poll. Use Ubiquiti's Site Manager API, *unverified*, or a local controller.
- The site id is usually `default`, even when the display name differs.
- Field facts:
  - UniFi's client `tx_bytes` is traffic **toward** the client. Checked on a real network: a streaming stick showed 43.9 GB tx against 1.3 GB rx.
  - Wired clients behind a UniFi switch use `wired-tx_bytes`, `wired-rx_bytes`, `wired-tx_bytes-r` and so on.
  - The counters restart when a client reconnects. netdash treats a counter that went down as the new total since that restart.
  - The network name is in `last_connection_network_name`, not `network`. The maker is in `oui`.
  - UniFi doesn't report clients' IPv6 addresses, and pfSense's API has no IPv6 neighbour table. So random "privacy" IPv6 addresses can't be matched to a device. Only EUI-64 addresses can, because they contain the MAC.
  - Short-lived clients stay in `stat/sta` for about 4.5 minutes after they leave.

---

## 5. Install layout

- Code in `/opt/netdash/netdash`, owned by the login user so `rsync` works.
- Data in `/var/lib/netdash` (the unit's `StateDirectory`).
- Secrets in `/etc/netdash.env`, `chmod 600`, owned by the service user.
- **Which service file:**
  - **No modem:** `deploy/netdash-site.service` runs as its own system user `netdash` (`sudo useradd --system --home /var/lib/netdash netdash`), with systemd hardening (`ProtectSystem=strict`, `ProtectHome`, `NoNewPrivileges`).
  - **With modem_check on the same box:** `deploy/netdash.service` runs as the user modem_check is installed under, because it has to read `~/modem_check/data/modem.db` in that user's private home directory.
- A sudoers rule for passwordless restarts: `/etc/sudoers.d/netdash-restart`, containing `<user> ALL=(root) NOPASSWD: /usr/bin/systemctl restart netdash`. `deploy/sync.sh push` needs it.
- Add the login user to `systemd-journal` so `journalctl -u netdash` works without sudo.
- `deploy/sync.sh push` runs the tests, rsyncs the code, restarts the service and checks `/api/site`, which needs no login.
  - Put `PI=user@host`, and `URL=https://host:9180` if the site uses HTTPS, in `deploy/local.env` (git-ignored), or pass them on the command line.
- The project folder is the source of truth (a git repo). The box is only ever updated from it.

### Certificate checking (pfSense and UniFi)

netdash checks the certificate of every HTTPS connection it makes. Without a
setting it uses the system's trusted CAs, which reject the self-signed certificates
routers and controllers usually have, so each source needs one of:

- **A pinned fingerprint** (usual for self-signed). On the dashboard box, run
  `python3 -m netdash fingerprint`. It prints `NETDASH_PFSENSE_FINGERPRINT=...` and
  `NETDASH_UNIFI_FINGERPRINT=...` for the URLs in the environment.
  - **Check each one before trusting it.** In pfSense, look under **System → Certificates**. For either device, a browser shows the fingerprint in the padlock's certificate details. Or run the same command from a second machine and compare: matching results from two places means nothing in between is interfering.
  - Several fingerprints, separated by commas, are accepted while rotating a certificate.
- **A CA bundle** (`NETDASH_*_CA`) when an organisation's CA signed the device's certificate.

If a pinned device renews its certificate, after an upgrade or when it expires,
polling that source stops. The page and the log then say
"certificate changed: it is now AB:CD:...". Check the new fingerprint on the
device and update the setting.

Quick checks once it's running:
```bash
python3 -m netdash pfsense     # router health, gateways, interfaces, leases, firewall log sample
python3 -m netdash unifi       # APs and weak clients
```
For these hand checks, load the env file in Python (see §4), not by sourcing it in the shell.

---

## 6. Site settings (`/etc/netdash.env`)

Start from `deploy/netdash-site.env.example` (no modem) or `deploy/netdash.env.example` (with modem_check). Everything a site needs is a setting:

| Setting | What it does |
|---|---|
| `NETDASH_SITE_NAME` | Page title, heading and sign-in page, e.g. `Branch Office` (default `Home network`) |
| `NETDASH_MODEM_DB=none` | No modem: Internet health comes from pfSense's gateways and the modem parts are hidden. Leaving it unset also works when `~/modem_check/data/modem.db` doesn't exist |
| `NETDASH_MODEM_DASHBOARD` | modem_check's own dashboard on the same box, shown at `/modem/` behind the login (default `http://127.0.0.1:8520` when the modem database exists; `none` turns it off) |
| `NETDASH_MODEM_URL` | where the Internet card's modem_check link goes (default `/modem/`, or the modem_check GitHub page when there's no modem dashboard) |
| `NETDASH_UNIFI_URL`, `_USER`, `_PASS`, `_SITE`, `_KIND` | UniFi controller and the View Only account (§4); `_KIND=classic` for the classic controller |
| `NETDASH_PFSENSE_URL`, `_KEY` | pfSense REST API (§3) |
| `NETDASH_PFSENSE_FINGERPRINT`, `NETDASH_UNIFI_FINGERPRINT` | Pin each device's certificate (SHA-256) so nothing on the network can pose as it (§5) |
| `NETDASH_PFSENSE_CA`, `NETDASH_UNIFI_CA` | Or verify against a CA bundle, e.g. the organisation's internal CA |
| `NETDASH_PFSENSE_TLS_VERIFY=off`, `NETDASH_UNIFI_TLS_VERIFY=off` | No certificate checking (not recommended; logged as a warning) |
| `NETDASH_AUTH=on` | Require a login (§7) |
| `NETDASH_SESSION_DAYS` | How long a login lasts (default 30) |
| `NETDASH_TLS_CERT`, `NETDASH_TLS_KEY` | Serve HTTPS with this certificate and key (PEM) |
| `NETDASH_BRAND_DIR` | A folder served at `/brand/`: `brand.css`, `logo.svg` or `logo.png`, `favicon.ico` |
| `NETDASH_KEEP_DAYS` | Samples: Wi-Fi, APs, interfaces, router health, gateways (default 60) |
| `NETDASH_FW_KEEP_DAYS` | Firewall events (default 14) |
| `NETDASH_USAGE_KEEP_DAYS` | Per-device hourly traffic, and clients not seen for that long (default 400; the site example uses 90) |

How netdash behaves without a modem:
- **Every gateway is stored** (`gw_samples`) and shown.
- **Internet-facing interfaces** are recognised by their pfSense `gateway` field (`wan`, `optN` ...). The network table, traffic charts and data-transferred table treat each of them as internet-side.
- **Needs a monitor IP that answers pings** on each gateway (§3). Otherwise pfSense reports the line down although it works, and the page believes it.

Not built yet, if a site wants it: its own ping and speed tests, for outage history independent of pfSense. [modem_check](https://github.com/zspalding12083/modem_check) (`run_ping`, `run_speedtest`) has a tested approach using Cloudflare's speed endpoints and `curl`. Keep the data use small: modem_check's defaults use about 6 GB a day, too much for a metered or shared business line.

---

## 7. Logins, HTTPS and care on shared networks

### Logins (built for a handful of people)

Turn on with `NETDASH_AUTH=on`. Without it, anyone who can reach the port sees everything.

- **Users** live in netdash's database and are managed from the command line on the box, as the service user. It prompts for the password twice, needs at least 10 characters, and won't accept the user name as the password:
  ```bash
  sudo -u netdash python3 -m netdash --db /var/lib/netdash/netdash.db user add alice
  sudo -u netdash python3 -m netdash --db /var/lib/netdash/netdash.db user passwd alice   # also logs alice out everywhere
  sudo -u netdash python3 -m netdash --db /var/lib/netdash/netdash.db user del alice
  sudo -u netdash python3 -m netdash --db /var/lib/netdash/netdash.db user list
  ```
- **How it works:**
  - Passwords are stored as PBKDF2-SHA256 hashes (600,000 rounds, random salt; about 0.3 s per check on a Raspberry Pi-class board).
  - Signing in sets a random session cookie (HttpOnly, SameSite=Strict, and Secure under HTTPS). Only its SHA-256 is stored.
  - Sessions last `NETDASH_SESSION_DAYS`. **Log out** is in the page header.
- **Brute-force protection:** 5 wrong passwords from one address, or for one user name, block further tries for 15 minutes. Failures and blocks are logged with the address: `journalctl -u netdash | grep login`.
- **Other protection:**
  - Cross-site form posts are refused (Origin check).
  - Every response carries `X-Frame-Options: DENY`, `nosniff`, a Content Security Policy and `Referrer-Policy: same-origin`. Don't change that to `no-referrer`: Chrome then sends `Origin: null` on the sign-in form and the Origin check refuses it.
- **Use HTTPS.** Without it, passwords and cookies cross the network in clear text, and the log warns about this at startup. A self-signed certificate is enough for a handful of known users; each browser warns once:
  ```bash
  sudo mkdir -p /etc/netdash
  sudo openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=netdash" \
       -addext "subjectAltName=IP:<box IP>" -keyout /etc/netdash/key.pem -out /etc/netdash/cert.pem
  sudo chown -R netdash /etc/netdash && sudo chmod 600 /etc/netdash/key.pem
  ```
  Then set `NETDASH_TLS_CERT`/`NETDASH_TLS_KEY` and restart. If the organisation has an internal CA, use a certificate from it instead.
- **Also limit who can reach the port:** a pfSense rule allowing 9180 only from the staff or management VLAN. Logins and a firewall rule together are better than either alone.

### Other care

- **Data sensitivity.** Client names, MAC addresses, per-device traffic and firewall logs show people's activity. Keep retention short with the `*_KEEP_DAYS` settings (§6). Don't send alerts or reports outside the organisation without approval.
- **Pinned certificates** (§5) keep a device on the network from posing as pfSense or UniFi to collect the API key or the UniFi password.
- **Read-only everywhere.** The UniFi account is View Only and the pfSense user is read-only, with the API in Read Only mode. netdash never changes anything on the network, and it should stay that way.
- **Lockouts affect other people.** A locked UniFi account or a Login Protection block on a shared network may stop its administrators too. Keep the backoff in `unifi.py`, and test logins once at a time, by hand.
- **Firewall checks worth doing while you're there:**
  - Make sure each rule that blocks an IoT or guest VLAN from the main network targets the subnet actually in use. VLAN names can mislead.
  - Look for devices stuck on `169.254.x.x` self-assigned addresses: something isn't getting DHCP.

---

## 8. Suggested order of work at a new site

1. Settle §2, especially permission, the host and remote access.
2. Clone the code (see the top of this guide). Write `/etc/netdash.env` from the right example (§6).
3. UniFi View Only account. Run `python3 -m netdash unifi` once, with the env file parsed in Python.
4. pfSense REST API (§3). Pin both certificates (`python3 -m netdash fingerprint`, §5), then run `python3 -m netdash pfsense`.
5. Set a gateway monitor IP that answers pings.
6. Deploy (§5). On a shared network, create the HTTPS certificate and the users, and add the pfSense rule limiting who can reach the port (§7).
7. Check the page on desktop and phone width with real data before calling it done.
