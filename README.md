# Q-Feeds Wazuh Integration

Integrate [Q-Feeds](https://qfeeds.com) Threat Intelligence with [Wazuh SIEM](https://wazuh.com) to detect and optionally block connections to known malicious IP addresses and domains.

The integration downloads threat intelligence feeds from the Q-Feeds API, converts them into Wazuh CDB (Constant Database) lists, and installs custom rules that generate alerts whenever a match is found in your logs.

## Features

- **Malware IP detection** -- alerts when a source or destination IP in your logs matches the Q-Feeds malware IP blacklist
- **Malware domain detection** -- alerts when a domain in DNS or web logs matches the Q-Feeds malware domain blacklist
- **Active Response** (optional) -- automatically blocks matched IPs using the local firewall via Wazuh's `firewall-drop` command
- **IPv4 and IPv6 support** for IP feeds
- **License-aware scheduling** -- only fetches new data when the Q-Feeds API indicates updates are available
- **Automatic CDB compilation** -- recompiles CDB lists and restarts Wazuh only when changes are detected
- **Easy install/uninstall** -- interactive installer and clean uninstaller

## Quick Start

```bash
# 1. Clone or download this repository on the Wazuh manager
git clone <repository-url> /tmp/qfeeds-wazuh
cd /tmp/qfeeds-wazuh

# 2. Run the installer as root
sudo bash install.sh

# 3. Follow the interactive prompts (API token, feed selection, etc.)
```

You will need your Q-Feeds API token, available at [tip.qfeeds.com](https://tip.qfeeds.com).

## Requirements

- **Wazuh manager** 4.x or later (installed at `/var/ossec`)
- **Root access** on the Wazuh manager server
- **curl** installed on the system
- **Q-Feeds API token** with an active license
- Internet access to `api.qfeeds.com`

No additional Python installation is needed -- the integration uses the Python bundled with Wazuh (`/var/ossec/framework/python/bin/python3`).

## How It Works

### Architecture

```
Q-Feeds API           Wazuh Manager
-----------           -------------------------------------------
                      qfeeds-wazuh-updater.py (cron, every 20m)
  /licenses  <------  1. Check if update is due
  /api       <------  2. Download feeds (plain text)
                      3. Convert to CDB format
                      4. Write to /var/ossec/etc/lists/
                      5. Compile CDB lists (ossec-makelists)
                      6. Restart Wazuh manager
                      
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

IPv4 CIDRs are converted to Wazuh's dot-notation. Only /8, /16, /24, and /32 masks are supported by Wazuh -- other CIDR sizes are skipped.

### Wazuh Rules

The integration installs these custom rules:

| Rule ID | Level | Description |
|---|---|---|
| 100200 | 10 | Source IP found in malware IP blacklist |
| 100201 | 10 | Destination IP found in malware IP blacklist |
| 100210 | 10 | Domain found in malware domain blacklist |

Rules trigger on events in these groups: `web`, `attack`, `attacks`, `syslog`, `firewall`, `ids`, `sysmon`, `dns`, `proxy`.

### Log Sources That Trigger Detection

**IP rules** (100200, 100201) fire when any Wazuh decoder extracts a `srcip` or `dstip` field. Common sources:

- Web server access logs (Apache, Nginx)
- Firewall logs (iptables, nftables, PF)
- Suricata / Snort IDS alerts
- Sysmon network connection events
- SSH, FTP, and other service logs

**Domain rules** (100210) fire when a decoder extracts a `url` field. Common sources:

- Sysmon Event 22 (DNS query)
- Web proxy logs (Squid, etc.)
- Web server access logs

## Installation

### Interactive Install

```bash
sudo bash install.sh
```

The installer will prompt for:

1. **API Token** -- your Q-Feeds API token
2. **Feed types** -- enable/disable Malware IPs and Malware Domains
3. **IPv6** -- include IPv6 addresses in the IP feed
4. **Active Response** -- auto-block matched IPs with a configurable timeout
5. **IP Whitelist** -- IPs that should never trigger alerts
6. **Cron schedule** -- how often to check for updates (default: every 20 minutes)

### What Gets Installed

| Component | Location |
|---|---|
| Config file | `/etc/qfeeds/qfeeds_wazuh.conf` |
| Updater script | `/usr/local/bin/qfeeds-wazuh-updater.py` |
| Wazuh rules | `/var/ossec/etc/rules/qfeeds_rules.xml` |
| CDB list (IPs) | `/var/ossec/etc/lists/qfeeds-malware-ip` |
| CDB list (domains) | `/var/ossec/etc/lists/qfeeds-malware-domains` |
| Log file | `/var/log/qfeeds_wazuh.log` |
| Cron job | User crontab for root |

The installer also modifies `/var/ossec/etc/ossec.conf` to add CDB list references and (optionally) Active Response configuration. All modifications are wrapped in marker comments for clean removal.

## Configuration

### Config File

Located at `/etc/qfeeds/qfeeds_wazuh.conf`:

```bash
API_TOKEN="your-api-token-here"

FEED_MALWARE_IP="yes"
FEED_MALWARE_DOMAINS="yes"

IPV6="yes"

ACTIVE_RESPONSE="yes"
ACTIVE_RESPONSE_TIMEOUT="60"

WHITELIST_V4=""
WHITELIST_V6=""

LOG_FILE="/var/log/qfeeds_wazuh.log"
```

| Variable | Description | Default |
|---|---|---|
| `API_TOKEN` | Q-Feeds API token (required) | -- |
| `FEED_MALWARE_IP` | Enable malware IP feed | `yes` |
| `FEED_MALWARE_DOMAINS` | Enable malware domains feed | `yes` |
| `IPV6` | Include IPv6 in IP feed | `yes` |
| `ACTIVE_RESPONSE` | Enable Active Response (set during install) | `no` |
| `ACTIVE_RESPONSE_TIMEOUT` | Block duration in seconds | `60` |
| `WHITELIST_V4` | Comma-separated IPv4 addresses to never alert on | empty |
| `WHITELIST_V6` | Comma-separated IPv6 addresses to never alert on | empty |
| `LOG_FILE` | Path to the updater log file | `/var/log/qfeeds_wazuh.log` |

### Changing Configuration After Install

You can edit `/etc/qfeeds/qfeeds_wazuh.conf` directly for options like API token, IPv6, and whitelists. These take effect on the next updater run.

To enable/disable feeds or Active Response after installation, you will also need to update the Wazuh rules file and ossec.conf. It is easier to re-run the installer.

## Usage

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
```

### Verify Rules Are Loaded

```bash
# Check Wazuh logs for rule loading
grep -i "qfeeds" /var/ossec/logs/ossec.log
```

### Test a Rule (Using ossec-logtest)

```bash
# Test an IP match against the IP blacklist
/var/ossec/bin/wazuh-logtest
```

Then paste a sample log line containing a known blacklisted IP.

### View Alerts in Wazuh Dashboard

Navigate to **Threat Hunting** and filter by:
- `rule.id: 100200` (source IP match)
- `rule.id: 100201` (destination IP match)
- `rule.id: 100210` (domain match)
- `rule.groups: qfeeds` (all Q-Feeds alerts)

## Uninstalling

```bash
sudo bash uninstall.sh
```

This removes all Q-Feeds components:
- Cron job
- CDB lists and compiled `.cdb` files
- Wazuh rules file
- ossec.conf modifications (CDB list references and Active Response)
- Configuration file
- Updater script
- Log and lock files

Backup copies of `ossec.conf` are preserved.

## Troubleshooting

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

Run the compiler manually and check for errors:
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

## License

Apache License 2.0 -- see [LICENSE](LICENSE) for details.

## Disclaimer

Use at your own risk. Q-Feeds is not responsible for any damage caused by this integration. Always test in a non-production environment first.
