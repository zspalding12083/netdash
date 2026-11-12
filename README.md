# netdash

A single-page network dashboard for small sites that run **pfSense** and **UniFi**:
internet health, traffic per network and per device, Wi-Fi, and firewall blocks
with plain-language explanations. If the site has an **ARRIS SB8200** cable modem
monitored by [modem_check](https://github.com/zspalding12083/modem_check), netdash
also shows the modem's signal, speed tests and outages.

- **Read-only.** It uses a View Only UniFi account and a read-only pfSense API key, and never changes anything on the network.
- **Standard library only.** Python 3.10+, no pip packages; one process, SQLite for history.
- **Built for a handful of viewers.** Optional logins (hashed passwords, lockout after repeated failures) and HTTPS.

## What it shows

- **Internet:** online/offline status and outages. These come from modem_check's ping and speed tests and modem readings when a modem is monitored. Otherwise they come from pfSense's gateway monitor, for every gateway (multi-WAN).
- **Router & traffic:** pfSense CPU, memory, temperature and uptime. Current Mbps and DHCP devices per network (LAN and each VLAN). Charts of internet and per-network traffic. Data transferred per network by day, week, month or all time.
- **Top devices by traffic:** live, or totals by day, week, month or all time, from UniFi's per-device counters (wired and Wi-Fi).
- **Firewall blocks:** per interface, most blocked and latest, with device or host names and a label such as "mDNS discovery", "late packet of an already-closed connection" or "inbound SSH connection attempt". Routine noise is hidden by default.
- **Wi-Fi:** each access point's clients, channels and how busy each radio is; clients per AP over time; a sortable client list with weak signals flagged; a week of signal history for any client.

The page has light and dark themes and works on phones. Each site can add its own
logo and colours.

## Requirements

- An always-on Linux box on the site's network (a Raspberry Pi-class board is plenty) with Python 3.10 or newer.
- **pfSense** (tested on Plus 26.07; pfrest also supports CE) with the [pfrest REST API package](https://github.com/pfrest/pfSense-pkg-RESTAPI), set up with a read-only key.
- **UniFi**: a UniFi OS console or UniFi OS Server, or a classic self-hosted controller, with a local View Only account.
- Optional: [modem_check](https://github.com/zspalding12083/modem_check) on the same box, for cable modem data.

## Setup

**[NEW_SITE_GUIDE.md](NEW_SITE_GUIDE.md)** is the full, step-by-step setup. It covers:
- the pfSense API package and its pitfalls
- the UniFi account
- the install layout
- every setting
- logins and HTTPS

In short:

```bash
git clone https://github.com/zspalding12083/netdash.git
cd netdash
python3 -m unittest discover -s tests -t .          # optional: run the tests

# settings and secrets (owned by the service user, chmod 600)
sudo cp deploy/netdash-site.env.example /etc/netdash.env   # or netdash.env.example with modem_check
sudo editor /etc/netdash.env

# check the connections
python3 -m netdash pfsense
python3 -m netdash unifi

# install as a service (see the guide for the service user and paths)
sudo cp deploy/netdash-site.service /etc/systemd/system/netdash.service
sudo systemctl enable --now netdash
```

Then open `http://<box>:9180/`, or `https://` when `NETDASH_TLS_CERT` is set.

Don't load `/etc/netdash.env` with `. file` in a shell for testing: passwords containing `$`
get mangled, and a few wrong logins can lock the UniFi account.

## Logins

Set `NETDASH_AUTH=on`, then add accounts on the box:

```bash
sudo -u netdash python3 -m netdash --db /var/lib/netdash/netdash.db user add alice
```

Use HTTPS with logins (`NETDASH_TLS_CERT` / `NETDASH_TLS_KEY`); a self-signed certificate is
fine for a few known users. See section 7 of the guide.

## Related

- **[modem_check](https://github.com/zspalding12083/modem_check)**: monitors an ARRIS SB8200 cable modem and the connection, with outage reports for the ISP. netdash reads its database, read-only, and links to its dashboard (`NETDASH_MODEM_URL`).

## License

MIT; see [LICENSE](LICENSE).
