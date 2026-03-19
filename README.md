<div align="center">

# 🛡️ Q-Feeds Wazuh Integration

**Threat intelligence for Wazuh SIEM — detect malicious IPs, domains, and phishing URLs in your logs**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Wazuh](https://img.shields.io/badge/Wazuh-4.x+-orange)](https://wazuh.com/)

</div>

---

## 📋 Table of Contents

- [Quick Start](#-quick-start)
- [Overview](#-overview)
- [How It Works](#-how-it-works)
- [Configuring Domain Detection on OPNsense](#-configuring-domain-detection-on-opnsense-unbound)
- [Installation](#-detailed-installation)
- [Configuration](#-configuration)
- [Usage and Verification](#-usage-and-verification)
- [Troubleshooting](#-troubleshooting)
- [Uninstalling](#-uninstalling)
- [License](#-license)

---

## 🚀 Quick Start

### Step 1: Get your API token

Obtain your API key at [tip.qfeeds.com](https://tip.qfeeds.com/).

### Step 2: Download the scripts

```bash
git clone https://github.com/Q-Feeds/Q-Feeds-Wazuh-Integration.git /tmp/qfeeds-wazuh
cd /tmp/qfeeds-wazuh
```

### Step 3: Run the installer as root

```bash
sudo bash install.sh
```

The installer will:
1. Prompt for your API token, feed selection, and optional settings
2. Install the updater script, decoders, rules, and cron job
3. Perform the first full feed download immediately

### Step 4: Done

Your Wazuh manager is now monitoring for malicious IPs and domains. The cron job checks for updates every 20 minutes (configurable), and actual API calls only happen when your license allows.

---

## 📖 Overview

Integrate [Q-Feeds](https://qfeeds.com) Threat Intelligence with [Wazuh SIEM](https://wazuh.com) to detect and optionally block connections to known malicious IP addresses and domains.

- ✅ **Malware IP detection** — alerts when a source or destination IP matches the Q-Feeds malware IP blacklist
- ✅ **Malware domain detection** — alerts when a domain in DNS, web, or proxy logs matches the Q-Feeds malware domain blacklist
- ✅ **Phishing URL detection** — alerts when a full URL in proxy or web logs matches the Q-Feeds phishing URL feed (requires license)
- ✅ **Active Response** (optional) — automatically blocks matched IPs using the local firewall via Wazuh's `firewall-drop` command
- ✅ **IPv4 and IPv6 support** for IP feeds
- ✅ **Custom decoders** — includes Unbound DNS decoder for OPNsense and other Unbound-based resolvers
- ✅ **Multi-platform domain detection** — dedicated rules for Sysmon (Windows), web/proxy servers, and Unbound DNS
- ✅ **License-aware scheduling** — only fetches new data when the Q-Feeds API indicates updates are available
- ✅ **Automatic CDB compilation** — restarts Wazuh only when changes are detected (4.x+ compiles automatically)
- ✅ **Easy install/uninstall** — interactive installer and clean uninstaller

---

## 🔧 How It Works

### Architecture

```
Q-Feeds API           Wazuh Manager
-----------           -------------------------------------------
                      qfeeds-wazuh-updater.py (cron, every 20m)
  /licenses  <------  1. Check if update is due
  /api       <------  2. Download feeds (plain text)
                      3. Convert to CDB format
                      4. Write to /var/ossec/etc/lists/
                      5. Restart Wazuh manager (compiles CDB lists automatically on 4.x+)
                      
                      Wazuh Rules Engine
                      ------------------
                      Log event arrives
                        -> Decoder extracts srcip / dstip / url
                        -> Custom rule checks CDB list
                        -> Match found? Generate alert (level 10)
                        -> Active Response enabled? Block IP
```

### CDB List Format

Wazuh CDB lists use a `key:value` format. This integration stores indicators as keys with empty values:

| Feed Type | CDB Entry Example | Matching |
|---|---|---|
| Malware IPs | `192.168.1.1:` | `address_match_key` on srcip/dstip |
| Malware IPs (CIDR /24) | `192.168.1.:` | Matches entire /24 subnet |
| Malware Domains | `evil-domain.com:` | `match_key` on url field |
| Phishing URLs | `https://evil.com/login:` | `match_key` on url field |
| Phishing URLs (no scheme) | `evil.com/login:` | `match_key` on url field |

IPv4 CIDRs are converted to Wazuh's dot-notation. Only /8, /16, /24, and /32 masks are supported by Wazuh — other CIDR sizes are skipped.

Phishing URLs are stored in two variants per entry: with the original protocol prefix (e.g. `https://`) and without it. This maximizes matching across different log sources — proxy logs typically include the scheme, while other sources may not.

### Wazuh Rules

The integration installs these custom rules:

| Rule ID | Level | Description | Trigger |
|---|---|---|---|
| 100200 | 10 | Source IP found in malware IP blacklist | `srcip` in firewall, web, syslog, sysmon, IDS logs |
| 100201 | 10 | Destination IP found in malware IP blacklist | `dstip` in firewall, web, syslog, sysmon, IDS logs |
| 100210 | 10 | Domain found in malware domain blacklist | `url` in web server or proxy logs |
| 100211 | 10 | DNS query to malware domain (Sysmon) | `win.eventdata.queryName` in Sysmon Event ID 22 |
| 100212 | 10 | DNS query to malware domain (Unbound) | `url` decoded from Unbound query logs (RFC5424) |
| 100213 | 10 | DNS query to malware domain (Unbound) | `url` decoded from Unbound query logs (RFC3164) |
| 100220 | 10 | Phishing URL detected in web/proxy logs | `url` in web server or proxy logs (requires license) |

### Custom Decoders

The integration includes a custom decoder (`/var/ossec/etc/decoders/qfeeds_decoders.xml`) for **Unbound DNS resolver** logs. It extracts the client IP, queried domain, query type, and response code from Unbound query lines. This decoder supports both RFC5424 (raw OPNsense logs) and RFC3164 (syslog-forwarded) formats.

### Log Sources That Trigger Detection

**IP rules** (100200, 100201) fire when any Wazuh decoder extracts a `srcip` or `dstip` field. Common sources:

- Web server access logs (Apache, Nginx)
- Firewall logs (iptables, nftables, PF)
- Suricata / Snort IDS alerts
- Sysmon network connection events
- SSH, FTP, and other service logs

**Domain rules** (100210–100213) fire when a decoder extracts a domain from logs. Sources per rule:

| Source | Platform | Rule | Notes |
|---|---|---|---|
| Sysmon Event ID 22 (DNS Query) | Windows | 100211 | Best option — logs queries client-side before any DNS server blocks them |
| Web server access logs | Any | 100210 | Apache, Nginx, etc. |
| Web proxy logs | Any | 100210 | Squid, etc. |
| Unbound DNS resolver | OPNsense, Linux, FreeBSD | 100212/100213 | Requires "Log Queries" enabled in Unbound (see below) |

**Phishing URL rule** (100220) fires when a decoded `url` field matches a full phishing URL. This works best with log sources that capture the complete URL including the path:

| Source | Platform | Rule | Notes |
|---|---|---|---|
| Web proxy logs | Any | 100220 | Squid, Zscaler, etc. — logs the full URL for HTTP traffic |
| Web server access logs | Any | 100220 | If the request URI matches a known phishing path |
| Reverse proxy / WAF | Any | 100220 | Logs upstream requests with full URLs |

> **Note:** HTTPS traffic through a proxy is typically logged as a `CONNECT` to the domain only (the path is encrypted). Full URL matching for HTTPS phishing URLs requires SSL inspection / TLS interception on the proxy.

---

## 🌐 Configuring Domain Detection on OPNsense (Unbound)

If you run OPNsense with the Wazuh agent plugin and want domain detection via Unbound DNS logs (rules 100212/100213), follow these steps.

> **Note:** If OPNsense's built-in DNSBL (Unbound blocklist) is active with the Q-Feeds domain feed, blocked domains are intercepted before they reach Unbound's log and will not trigger these rules. In that case, domain detection in Wazuh is redundant since OPNsense already blocks them. These rules are most useful when Unbound runs as a plain resolver **without** DNSBL, or when you want to detect queries to malicious domains that are not (yet) in the local blocklist.

### 1. Enable Unbound query logging

In OPNsense, go to **Services > Unbound DNS > Advanced** and enable **Log Queries**. This logs one line per DNS query with the client IP, domain name, and query type.

Optionally enable **Log Replies** to also log response codes and timing information.

Leave **Log Level Verbosity** at the default (level 1). Do **not** use level 3 for this purpose — it produces excessive internal logging (iterator, validator, etc.) alongside query lines.

> **Note:** Query logging has a performance impact on the DNS resolver. Monitor CPU usage and response times after enabling.

### 2. Configure the Wazuh agent to read Unbound logs

The Unbound resolver log at `/var/log/resolver/latest.log` is in RFC5424 format and is not collected by the Wazuh agent by default. Add it to the agent configuration on OPNsense.

Edit `/var/ossec/etc/ossec.conf` on OPNsense (via SSH) and add the following block **inside** the `<ossec_config>` tags:

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/resolver/latest.log</location>
</localfile>
```

Then restart the agent:

```bash
service wazuh-agent restart
```

Verify the agent is reading the file:

```bash
tail -20 /var/ossec/logs/ossec.log | grep resolver
```

You should see: `Analyzing file: '/var/log/resolver/latest.log'`.

> **Note:** This manual edit to `ossec.conf` may be overwritten by OPNsense Wazuh agent plugin updates. After a plugin update, verify the `<localfile>` entry is still present.

### 3. Verify on the Wazuh manager

Use `wazuh-logtest` on the Wazuh manager to confirm the decoder and rules work:

```bash
/var/ossec/bin/wazuh-logtest
```

Paste a sample Unbound query line (copy from `/var/log/resolver/latest.log` on OPNsense — look for lines containing `info:` followed by an IP address and domain). The output should show decoder `qfeeds-unbound` extracting `srcip`, `url`, `extra_data`, and `status` fields.

---

## 📝 Detailed Installation

### Interactive Install

```bash
sudo bash install.sh
```

The installer will prompt for:

1. **API Token** — your Q-Feeds API token
2. **Feed types** — enable/disable Malware IPs, Malware Domains, and Phishing URLs
3. **IPv6** — include IPv6 addresses in the IP feed
4. **Active Response** — auto-block matched IPs with a configurable timeout
5. **IP Whitelist** — IPs that should never trigger alerts
6. **Cron schedule** — how often to check for updates (default: every 20 minutes)

### What Gets Installed

| Component | Location |
|---|---|
| Config file | `/etc/qfeeds/qfeeds_wazuh.conf` |
| Updater script | `/usr/local/bin/qfeeds-wazuh-updater.py` |
| Wazuh decoders | `/var/ossec/etc/decoders/qfeeds_decoders.xml` |
| Wazuh rules | `/var/ossec/etc/rules/qfeeds_rules.xml` |
| CDB list (IPs) | `/var/ossec/etc/lists/qfeeds-malware-ip` |
| CDB list (domains) | `/var/ossec/etc/lists/qfeeds-malware-domains` |
| CDB list (phishing URLs) | `/var/ossec/etc/lists/qfeeds-phishing-urls` |
| Log file | `/var/log/qfeeds_wazuh.log` |
| Cron job | User crontab for root |

The installer also modifies `/var/ossec/etc/ossec.conf` to add CDB list references and (optionally) Active Response configuration. All modifications are wrapped in marker comments for clean removal.

---

## ⚙️ Configuration

### Configuration File

Located at `/etc/qfeeds/qfeeds_wazuh.conf`:

```bash
API_TOKEN="your-api-token-here"

FEED_MALWARE_IP="yes"
FEED_MALWARE_DOMAINS="yes"
FEED_PHISHING_URLS="no"

IPV6="yes"

ACTIVE_RESPONSE="yes"
ACTIVE_RESPONSE_TIMEOUT="60"

WHITELIST_V4=""
WHITELIST_V6=""

LOG_FILE="/var/log/qfeeds_wazuh.log"
```

### Configuration Reference

| Variable | Description | Default |
|---|---|---|
| `API_TOKEN` | Q-Feeds API token (required) | — |
| `FEED_MALWARE_IP` | Enable malware IP feed | `yes` |
| `FEED_MALWARE_DOMAINS` | Enable malware domains feed | `yes` |
| `FEED_PHISHING_URLS` | Enable phishing URLs feed (requires license) | `no` |
| `IPV6` | Include IPv6 in IP feed | `yes` |
| `ACTIVE_RESPONSE` | Enable Active Response (set during install) | `no` |
| `ACTIVE_RESPONSE_TIMEOUT` | Block duration in seconds | `60` |
| `WHITELIST_V4` | Comma-separated IPv4 addresses to never alert on | *(empty)* |
| `WHITELIST_V6` | Comma-separated IPv6 addresses to never alert on | *(empty)* |
| `LOG_FILE` | Path to the updater log file | `/var/log/qfeeds_wazuh.log` |

### Changing Configuration After Install

You can edit `/etc/qfeeds/qfeeds_wazuh.conf` directly for options like API token, IPv6, and whitelists. These take effect on the next updater run.

To enable/disable feeds or Active Response after installation, you will also need to update the Wazuh rules file and ossec.conf. It is easier to re-run the installer.

---

## ✅ Prerequisites

- [x] **Wazuh manager** 4.x or later (installed at `/var/ossec`)
- [x] **Root access** on the Wazuh manager server
- [x] **curl** installed on the system
- [x] **Q-Feeds API token** with an active license
- [x] Internet access to `api.qfeeds.com`

No additional Python installation is needed — the integration uses the Python bundled with Wazuh (`/var/ossec/framework/python/bin/python3`).

---

## 🎯 Usage and Verification

### Force an Immediate Update

```bash
sudo QFEEDS_FORCE_UPDATE=1 /var/ossec/framework/python/bin/python3 /usr/local/bin/qfeeds-wazuh-updater.py
```

### Check the Log

```bash
tail -f /var/log/qfeeds_wazuh.log
```

### Verify CDB Lists

```bash
# Check the IP list
wc -l /var/ossec/etc/lists/qfeeds-malware-ip
head -20 /var/ossec/etc/lists/qfeeds-malware-ip

# Check the domains list
wc -l /var/ossec/etc/lists/qfeeds-malware-domains
head -20 /var/ossec/etc/lists/qfeeds-malware-domains

# Check the phishing URLs list (if enabled)
wc -l /var/ossec/etc/lists/qfeeds-phishing-urls
head -20 /var/ossec/etc/lists/qfeeds-phishing-urls
```

### Verify Rules Are Loaded

```bash
grep -i "qfeeds" /var/ossec/logs/ossec.log
```

### Test a Rule

```bash
/var/ossec/bin/wazuh-logtest
```

Then paste a sample log line containing a known blacklisted IP or domain.

### View Alerts in Wazuh Dashboard

Navigate to **Threat Hunting** and filter by:
- `rule.id: 100200` (source IP match)
- `rule.id: 100201` (destination IP match)
- `rule.id: 100210` (domain match — web/proxy)
- `rule.id: 100211` (domain match — Sysmon DNS)
- `rule.id: 100212` or `rule.id: 100213` (domain match — Unbound DNS)
- `rule.id: 100220` (phishing URL match)
- `rule.groups: qfeeds` (all Q-Feeds alerts)

---

## 🔍 Troubleshooting

### No alerts generated

1. Verify the CDB lists exist and contain data:
   ```bash
   ls -la /var/ossec/etc/lists/qfeeds-*
   wc -l /var/ossec/etc/lists/qfeeds-malware-ip
   ```

2. Verify the rules file is loaded:
   ```bash
   cat /var/ossec/etc/rules/qfeeds_rules.xml
   ```

3. Verify CDB list references are in ossec.conf:
   ```bash
   grep "qfeeds" /var/ossec/etc/ossec.conf
   ```

4. Restart Wazuh and check for errors:
   ```bash
   sudo systemctl restart wazuh-manager
   grep -i "error" /var/ossec/logs/ossec.log | tail -20
   ```

### Updater fails to download feeds

1. Check the log for errors:
   ```bash
   tail -50 /var/log/qfeeds_wazuh.log
   ```

2. Verify API connectivity:
   ```bash
   curl -s "https://api.qfeeds.com/licenses?api_token=YOUR_TOKEN" | python3 -m json.tool
   ```

3. Verify the API token is valid:
   ```bash
   grep API_TOKEN /etc/qfeeds/qfeeds_wazuh.conf
   ```

### CDB list not compiling

On Wazuh 4.x+, CDB lists are compiled automatically when the manager restarts. On older versions, run the compiler manually:

```bash
sudo /var/ossec/bin/ossec-makelists
```

### Active Response not blocking

1. Verify Active Response is configured in ossec.conf:
   ```bash
   grep -A5 "Q-FEEDS-AR" /var/ossec/etc/ossec.conf
   ```

2. Check Active Response logs:
   ```bash
   tail -20 /var/ossec/logs/active-responses.log
   ```

3. Verify the `firewall-drop` command exists:
   ```bash
   ls /var/ossec/active-response/bin/firewall-drop
   ```

### Unbound domain detection not working

1. Verify "Log Queries" is enabled in OPNsense Unbound settings
2. Verify the Wazuh agent is reading the resolver log:
   ```bash
   grep resolver /var/ossec/logs/ossec.log
   ```
3. Test the decoder on the Wazuh manager:
   ```bash
   /var/ossec/bin/wazuh-logtest
   ```
   Paste a sample Unbound query line — the decoder should extract `srcip`, `url`, `extra_data`, and `status`.
4. If OPNsense DNSBL is active, blocked domains will not appear in the resolver log (see [OPNsense section](#-configuring-domain-detection-on-opnsense-unbound))

---

## 🗑️ Uninstalling

```bash
sudo bash uninstall.sh
```

This removes all Q-Feeds components:
- Cron job
- CDB lists and compiled `.cdb` files (IPs, domains, and phishing URLs)
- Wazuh decoders file
- Wazuh rules file
- ossec.conf modifications (CDB list references and Active Response)
- Configuration file
- Updater script
- Log and lock files

Backup copies of `ossec.conf` are preserved.

> **Note:** The uninstaller does **not** remove the `<localfile>` entry for Unbound logs on OPNsense agents. Remove it manually if no longer needed.

---

## 📄 License

This project is licensed under the **Apache License 2.0** — see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

**Use at your own risk.**

Q-Feeds is not responsible for any damage caused by this integration. Always test in a non-production environment first.

---

<div align="center">

[Report Bug](https://github.com/Q-Feeds/Q-Feeds-Wazuh-Integration/issues) · [Request Feature](https://github.com/Q-Feeds/Q-Feeds-Wazuh-Integration/issues)

</div>
