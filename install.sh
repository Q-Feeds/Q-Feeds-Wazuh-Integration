#!/bin/bash
# =============================================================================
# Q-Feeds Wazuh Integration Installer
# =============================================================================
# Copyright (c) 2026 Q-Feeds
# All rights reserved.
#
# This script installs and configures the Q-Feeds Threat Intelligence
# integration for Wazuh SIEM. It sets up CDB lists for malware IP addresses
# and/or malware domains, with optional Active Response for automatic blocking.
#
# Before proceeding, you must accept the Terms & Conditions and End-User License
# Agreement (EULA) as published on https://qfeeds.com/terms
#
# Redistribution and use in source and binary forms, with or without
# modification, are strictly prohibited without prior written consent from
# Q-Feeds.
# =============================================================================

set -e

# ================================
# Constants
# ================================
CONFIG_DIR="/etc/qfeeds"
CONFIG_FILE="/etc/qfeeds/qfeeds_wazuh.conf"
UPDATER_SRC="qfeeds-wazuh-updater.py"
UPDATER_DEST="/usr/local/bin/qfeeds-wazuh-updater.py"
WAZUH_DIR="/var/ossec"
WAZUH_RULES_FILE="$WAZUH_DIR/etc/rules/qfeeds_rules.xml"
WAZUH_DECODERS_FILE="$WAZUH_DIR/etc/decoders/qfeeds_decoders.xml"
WAZUH_LISTS_DIR="$WAZUH_DIR/etc/lists"
WAZUH_CONF="$WAZUH_DIR/etc/ossec.conf"
WAZUH_PYTHON="$WAZUH_DIR/framework/python/bin/python3"
LOG_FILE="/var/log/qfeeds_wazuh.log"
CRON_CMD="$WAZUH_PYTHON $UPDATER_DEST"
API_BASE="https://api.qfeeds.com"

# ================================
# Functions
# ================================

accept_terms() {
    echo "================================================================================"
    echo "Q-Feeds Terms & Conditions and End-User License Agreement (EULA)"
    echo "================================================================================"
    echo "Before using this software, you must accept the Terms & Conditions and EULA"
    echo "as published on https://qfeeds.com/terms"
    echo
    echo "Please review the Terms & Conditions and EULA at the following URL:"
    echo "https://qfeeds.com/terms"
    echo
    echo "Running this script is your own responsibility. Q-Feeds is not responsible"
    echo "for any damage caused by this script."
    echo
    echo "================================================================================"
    echo
    read -rp "Do you accept the Terms & Conditions and EULA? (yes/no): " response
    case "$response" in
        [yY][eE][sS]|[yY])
            echo "Thank you for accepting the Terms & Conditions and EULA."
            ;;
        *)
            echo "You must accept the Terms & Conditions and EULA to proceed."
            exit 1
            ;;
    esac
}

preflight_checks() {
    if [ "$EUID" -ne 0 ]; then
        echo "Error: This script must be run as root."
        exit 1
    fi

    if [ ! -f "$WAZUH_DIR/bin/wazuh-control" ] && [ ! -f "$WAZUH_DIR/bin/ossec-control" ]; then
        echo "Error: Wazuh manager not found at $WAZUH_DIR."
        echo "Please install the Wazuh manager before running this installer."
        exit 1
    fi

    if [ ! -f "$WAZUH_PYTHON" ]; then
        echo "Error: Wazuh Python not found at $WAZUH_PYTHON."
        echo "This integration requires the Python bundled with Wazuh manager."
        exit 1
    fi

    if ! command -v curl &>/dev/null; then
        echo "Error: curl is required but not installed."
        exit 1
    fi

    if [ ! -f "$WAZUH_CONF" ]; then
        echo "Error: Wazuh configuration file not found at $WAZUH_CONF."
        exit 1
    fi

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [ ! -f "$SCRIPT_DIR/$UPDATER_SRC" ]; then
        echo "Error: Updater script '$UPDATER_SRC' not found in $SCRIPT_DIR."
        echo "Please ensure install.sh and $UPDATER_SRC are in the same directory."
        exit 1
    fi

    echo "Pre-flight checks passed."
}

check_feed_licenses() {
    echo
    echo "Verifying API token and checking feed licenses..."

    LICENSE_MALWARE_IP="unknown"
    LICENSE_MALWARE_DOMAINS="unknown"
    LICENSE_MALICIOUS_URLS="unknown"
    LICENSE_INFO=""

    local response http_status body
    response=$(curl -s -w "\n%{http_code}" -m 30 -A "Q-Feeds-Wazuh/1.0" \
        "${API_BASE}/licenses?api_token=${API_TOKEN}")

    http_status=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')

    if [ "$http_status" != "200" ]; then
        echo "  Warning: License API returned HTTP $http_status."
        echo "  Feed selection will proceed without license validation."
        echo
        return
    fi

    local license_output
    license_output=$("$WAZUH_PYTHON" -c '
import json, sys
try:
    data = json.loads(sys.stdin.read())
    ci = data.get("company_info", {})
    ln = ci.get("license_name", "")
    exp = ci.get("license_expiry_date", "")
    if exp:
        exp = exp.split("T")[0]
    if ln and exp:
        print("LICENSE_INFO=" + ln + " (expires " + exp + ")")
    elif ln:
        print("LICENSE_INFO=" + ln)
    feeds = {f["feed_type"]: f.get("licensed", False) for f in data.get("feeds", [])}
    for ft in ["malware_ip", "malware_domains", "malicious_urls"]:
        val = "yes" if feeds.get(ft, False) else "no"
        print(ft + "=" + val)
except Exception:
    sys.exit(1)
' <<< "$body" 2>/dev/null)

    if [ $? -ne 0 ]; then
        echo "  Warning: Could not parse license response."
        echo "  Feed selection will proceed without license validation."
        echo
        return
    fi

    LICENSE_INFO=$(echo "$license_output" | grep "^LICENSE_INFO=" | cut -d= -f2-)

    echo "$license_output" | grep -q "^malware_ip=yes" && LICENSE_MALWARE_IP="yes"
    echo "$license_output" | grep -q "^malware_ip=no" && LICENSE_MALWARE_IP="no"
    echo "$license_output" | grep -q "^malware_domains=yes" && LICENSE_MALWARE_DOMAINS="yes"
    echo "$license_output" | grep -q "^malware_domains=no" && LICENSE_MALWARE_DOMAINS="no"
    echo "$license_output" | grep -q "^malicious_urls=yes" && LICENSE_MALICIOUS_URLS="yes"
    echo "$license_output" | grep -q "^malicious_urls=no" && LICENSE_MALICIOUS_URLS="no"

    if [ -n "$LICENSE_INFO" ]; then
        echo "  License: $LICENSE_INFO"
    fi
    echo

    local status
    for feed_label in "Malware IPs:LICENSE_MALWARE_IP" "Malware Domains:LICENSE_MALWARE_DOMAINS" "Malicious URLs:LICENSE_MALICIOUS_URLS"; do
        local label="${feed_label%%:*}"
        local var="${feed_label##*:}"
        local val="${!var}"
        if [ "$val" = "yes" ]; then
            status="licensed"
        elif [ "$val" = "no" ]; then
            status="not licensed"
        else
            status="unknown"
        fi
        printf "  %-22s %s\n" "$label" "$status"
    done
    echo
}

configure_taxii() {
    echo
    echo "--- TAXII 2.1 Configuration ---"
    echo

    read -rp "TAXII Server URL [default: https://taxii.qfeeds.com]: " TAXII_URL
    TAXII_URL=${TAXII_URL:-"https://taxii.qfeeds.com"}

    read -rp "TAXII Username: " TAXII_USERNAME
    if [ -z "$TAXII_USERNAME" ]; then
        echo "Error: Username cannot be empty."
        exit 1
    fi

    read -rsp "TAXII Password: " TAXII_PASSWORD
    echo
    if [ -z "$TAXII_PASSWORD" ]; then
        echo "Error: Password cannot be empty."
        exit 1
    fi

    echo
    echo "Discovering API root..."
    local discovery_response
    discovery_response=$(curl -s -m 30 -u "${TAXII_USERNAME}:${TAXII_PASSWORD}" \
        -H "Accept: application/taxii+json;version=2.1" \
        "${TAXII_URL}/taxii2/")

    local discovered_root
    discovered_root=$("$WAZUH_PYTHON" -c '
import json, sys
try:
    data = json.loads(sys.stdin.read())
    roots = data.get("api_roots", [])
    if roots:
        root = roots[0]
        # Extract path from full URL if present
        if "://" in root:
            root = "/" + root.split("://", 1)[1].split("/", 1)[1]
        print(root.strip("/"))
except Exception:
    pass
' <<< "$discovery_response" 2>/dev/null)

    if [ -n "$discovered_root" ]; then
        echo "  Discovered API root: $discovered_root"
        TAXII_API_ROOT="$discovered_root"
    else
        read -rp "Could not auto-discover. Enter API root path [default: taxii2/feeds_database]: " TAXII_API_ROOT
        TAXII_API_ROOT=${TAXII_API_ROOT:-"taxii2/feeds_database"}
    fi

    echo
    echo "Fetching available collections..."
    local collections_response
    collections_response=$(curl -s -m 30 -u "${TAXII_USERNAME}:${TAXII_PASSWORD}" \
        -H "Accept: application/taxii+json;version=2.1" \
        "${TAXII_URL}/${TAXII_API_ROOT}/collections/")

    local collections_list
    collections_list=$("$WAZUH_PYTHON" -c '
import json, sys
try:
    data = json.loads(sys.stdin.read())
    for i, c in enumerate(data.get("collections", []), 1):
        cid = c.get("id", "unknown")
        title = c.get("title", cid)
        desc = c.get("description", "")
        print(f"{i}|{cid}|{title}|{desc}")
except Exception as e:
    print("error|" + str(e))
    sys.exit(1)
' <<< "$collections_response" 2>/dev/null)

    if [ -z "$collections_list" ] || echo "$collections_list" | grep -q "^error|"; then
        echo "  Warning: Could not fetch collections from TAXII server."
        echo "  You can enter collection IDs manually."
        read -rp "Enter collection IDs (comma-separated): " TAXII_COLLECTIONS
        if [ -z "$TAXII_COLLECTIONS" ]; then
            echo "Error: At least one collection is required."
            exit 1
        fi
    else
        echo
        echo "  Available collections:"
        echo "  ──────────────────────────────────────────────────"
        local idx=0
        while IFS='|' read -r num cid title desc; do
            idx=$((idx + 1))
            printf "  %2s) %-45s %s\n" "$num" "$title" "$desc"
        done <<< "$collections_list"
        echo "  ──────────────────────────────────────────────────"
        echo
        read -rp "Select collections (comma-separated numbers, or 'all'): " COLLECTION_CHOICE

        if [ "$COLLECTION_CHOICE" = "all" ]; then
            TAXII_COLLECTIONS=$(echo "$collections_list" | cut -d'|' -f2 | tr '\n' ',' | sed 's/,$//')
        else
            TAXII_COLLECTIONS=""
            IFS=',' read -ra SELECTED <<< "$COLLECTION_CHOICE"
            for sel in "${SELECTED[@]}"; do
                sel=$(echo "$sel" | tr -d ' ')
                local cid
                cid=$(echo "$collections_list" | sed -n "${sel}p" | cut -d'|' -f2)
                if [ -n "$cid" ]; then
                    [ -n "$TAXII_COLLECTIONS" ] && TAXII_COLLECTIONS="${TAXII_COLLECTIONS},"
                    TAXII_COLLECTIONS="${TAXII_COLLECTIONS}${cid}"
                fi
            done
        fi

        if [ -z "$TAXII_COLLECTIONS" ]; then
            echo "Error: No collections selected."
            exit 1
        fi

        echo "  Selected: $TAXII_COLLECTIONS"
    fi

    HAS_HASH_COLLECTIONS="no"
    if echo "$TAXII_COLLECTIONS" | grep -qi "hash"; then
        HAS_HASH_COLLECTIONS="yes"
    fi

    echo
    echo "--- Expired Indicators ---"
    echo "Indicators with valid_until in the past are normally skipped."
    read -rp "Skip expired indicators? [Y/n]: " SKIP_EXPIRED_CHOICE
    case "$SKIP_EXPIRED_CHOICE" in
        [nN][oO]|[nN]) TAXII_SKIP_EXPIRED="no" ;;
        *) TAXII_SKIP_EXPIRED="yes" ;;
    esac

    WHITELIST_V4=""
    WHITELIST_V6=""
    echo
    read -rp "Configure an IP whitelist? [y/N]: " WL_CHOICE
    case "$WL_CHOICE" in
        [yY][eE][sS]|[yY])
            read -rp "Enter IPv4 whitelist (comma-separated): " WHITELIST_V4
            read -rp "Enter IPv6 whitelist (comma-separated): " WHITELIST_V6
            ;;
    esac

    ACTIVE_RESPONSE="no"
    ACTIVE_RESPONSE_TIMEOUT="60"
    echo
    echo "--- Active Response ---"
    echo "Active Response automatically blocks matched IPs using the local firewall."
    read -rp "Enable Active Response? [y/N]: " AR_CHOICE
    case "$AR_CHOICE" in
        [yY][eE][sS]|[yY])
            ACTIVE_RESPONSE="yes"
            read -rp "Block timeout in seconds [default: 60]: " AR_TIMEOUT
            ACTIVE_RESPONSE_TIMEOUT=${AR_TIMEOUT:-60}
            ;;
    esac

    INTEGRATION_MODE="taxii"
    API_TOKEN=""
    FEED_MALWARE_IP="no"
    FEED_MALWARE_DOMAINS="no"
    FEED_MALICIOUS_URLS="no"
    IPV6="no"
}

configure_script() {
    echo
    echo "=== Configuration ==="
    echo

    mkdir -p "$CONFIG_DIR"

    echo "--- Integration Mode ---"
    echo "  1) Standard API  — Direct REST API feeds (requires API token)"
    echo "  2) TAXII 2.1     — STIX indicators via TAXII protocol (requires TAXII credentials)"
    echo
    read -rp "Select integration mode [1/2]: " MODE_CHOICE
    case "$MODE_CHOICE" in
        2) INTEGRATION_MODE="taxii" ;;
        *) INTEGRATION_MODE="standard" ;;
    esac

    if [ "$INTEGRATION_MODE" = "taxii" ]; then
        configure_taxii
    else
        read -rp "Enter your Q-Feeds API Token: " API_TOKEN
        if [ -z "$API_TOKEN" ]; then
            echo "Error: API Token cannot be empty."
            exit 1
        fi

        check_feed_licenses

        echo "--- Feed Selection ---"

        if [ "$LICENSE_MALWARE_IP" = "no" ]; then
            echo "  Malware IP feed: not licensed — skipping"
            FEED_MALWARE_IP="no"
        else
            read -rp "Enable Malware IP feed? [Y/n]: " FEED_IP_CHOICE
            case "$FEED_IP_CHOICE" in
                [nN][oO]|[nN]) FEED_MALWARE_IP="no" ;;
                *) FEED_MALWARE_IP="yes" ;;
            esac
        fi

        if [ "$LICENSE_MALWARE_DOMAINS" = "no" ]; then
            echo "  Malware Domains feed: not licensed — skipping"
            FEED_MALWARE_DOMAINS="no"
        else
            read -rp "Enable Malware Domains feed? [Y/n]: " FEED_DOMAINS_CHOICE
            case "$FEED_DOMAINS_CHOICE" in
                [nN][oO]|[nN]) FEED_MALWARE_DOMAINS="no" ;;
                *) FEED_MALWARE_DOMAINS="yes" ;;
            esac
        fi

        if [ "$LICENSE_MALICIOUS_URLS" = "no" ]; then
            echo "  Malicious URLs feed: not licensed — skipping"
            FEED_MALICIOUS_URLS="no"
        elif [ "$LICENSE_MALICIOUS_URLS" = "yes" ]; then
            read -rp "Enable Malicious URLs feed? [Y/n]: " FEED_URLS_CHOICE
            case "$FEED_URLS_CHOICE" in
                [nN][oO]|[nN]) FEED_MALICIOUS_URLS="no" ;;
                *) FEED_MALICIOUS_URLS="yes" ;;
            esac
        else
            read -rp "Enable Malicious URLs feed? (license status unknown) [y/N]: " FEED_URLS_CHOICE
            case "$FEED_URLS_CHOICE" in
                [yY][eE][sS]|[yY]) FEED_MALICIOUS_URLS="yes" ;;
                *) FEED_MALICIOUS_URLS="no" ;;
            esac
        fi

        if [ "$FEED_MALWARE_IP" = "no" ] && [ "$FEED_MALWARE_DOMAINS" = "no" ] && [ "$FEED_MALICIOUS_URLS" = "no" ]; then
            echo "Error: At least one feed type must be enabled."
            exit 1
        fi

        IPV6="no"
        if [ "$FEED_MALWARE_IP" = "yes" ]; then
            echo
            echo "--- IPv6 ---"
            read -rp "Include IPv6 addresses in the IP feed? [Y/n]: " IPV6_CHOICE
            case "$IPV6_CHOICE" in
                [nN][oO]|[nN]) IPV6="no" ;;
                *) IPV6="yes" ;;
            esac
        fi

        ACTIVE_RESPONSE="no"
        ACTIVE_RESPONSE_TIMEOUT="60"
        if [ "$FEED_MALWARE_IP" = "yes" ]; then
            echo
            echo "--- Active Response ---"
            echo "Active Response automatically blocks matched IPs using the local firewall."
            echo "This only applies to Malware IP rules."
            read -rp "Enable Active Response? [y/N]: " AR_CHOICE
            case "$AR_CHOICE" in
                [yY][eE][sS]|[yY])
                    ACTIVE_RESPONSE="yes"
                    read -rp "Block timeout in seconds [default: 60]: " AR_TIMEOUT
                    ACTIVE_RESPONSE_TIMEOUT=${AR_TIMEOUT:-60}
                    ;;
            esac
        fi

        WHITELIST_V4=""
        WHITELIST_V6=""
        if [ "$FEED_MALWARE_IP" = "yes" ]; then
            echo
            echo "--- Whitelist ---"
            read -rp "Configure an IP whitelist (IPs that should never trigger alerts)? [y/N]: " WL_CHOICE
            case "$WL_CHOICE" in
                [yY][eE][sS]|[yY])
                    read -rp "Enter IPv4 whitelist (comma-separated, e.g. 1.2.3.4,5.6.7.8): " WHITELIST_V4
                    if [ "$IPV6" = "yes" ]; then
                        read -rp "Enter IPv6 whitelist (comma-separated): " WHITELIST_V6
                    fi
                    ;;
            esac
        fi

        TAXII_URL=""
        TAXII_API_ROOT=""
        TAXII_USERNAME=""
        TAXII_PASSWORD=""
        TAXII_COLLECTIONS=""
        TAXII_SKIP_EXPIRED=""
        HAS_HASH_COLLECTIONS="no"
    fi

    cat > "$CONFIG_FILE" <<EOF
# Q-Feeds Wazuh Integration Configuration
# Generated by install.sh on $(date -u '+%Y-%m-%dT%H:%M:%SZ')

INTEGRATION_MODE="$INTEGRATION_MODE"

API_TOKEN="$API_TOKEN"

FEED_MALWARE_IP="$FEED_MALWARE_IP"
FEED_MALWARE_DOMAINS="$FEED_MALWARE_DOMAINS"
FEED_MALICIOUS_URLS="$FEED_MALICIOUS_URLS"

IPV6="$IPV6"

TAXII_URL="$TAXII_URL"
TAXII_API_ROOT="$TAXII_API_ROOT"
TAXII_USERNAME="$TAXII_USERNAME"
TAXII_PASSWORD="$TAXII_PASSWORD"
TAXII_COLLECTIONS="$TAXII_COLLECTIONS"
TAXII_SKIP_EXPIRED="$TAXII_SKIP_EXPIRED"

ACTIVE_RESPONSE="$ACTIVE_RESPONSE"
ACTIVE_RESPONSE_TIMEOUT="$ACTIVE_RESPONSE_TIMEOUT"

WHITELIST_V4="$WHITELIST_V4"
WHITELIST_V6="$WHITELIST_V6"

LOG_FILE="$LOG_FILE"
EOF

    chmod 600 "$CONFIG_FILE"
    echo
    echo "Configuration saved to $CONFIG_FILE"
}

install_updater() {
    echo
    echo "=== Installing Updater Script ==="
    cp "$SCRIPT_DIR/$UPDATER_SRC" "$UPDATER_DEST"
    chmod 700 "$UPDATER_DEST"
    echo "Updater installed at $UPDATER_DEST"
}

install_wazuh_decoders() {
    echo
    echo "=== Installing Wazuh Decoders ==="

    if [ -f "$WAZUH_DECODERS_FILE" ]; then
        cp "$WAZUH_DECODERS_FILE" "${WAZUH_DECODERS_FILE}.bak.$(date +%s)"
        echo "Backed up existing decoders file."
    fi

    cat > "$WAZUH_DECODERS_FILE" <<'DECODERS_EOF'
<!-- =============================================================================
     Q-Feeds Threat Intelligence Decoders
     Generated by Q-Feeds Wazuh Integration installer
     https://qfeeds.com
     ============================================================================= -->

<!--
  Unbound DNS resolver decoder.
  Matches query and reply lines (enable "Log Queries" in Unbound, verbosity 1).
  Supports both RFC5424 (OPNsense raw log) and RFC3164 (syslog pre-decoded) formats.
  Query format:  [thread:id] info: <client_ip> <domain>. <type> IN
  Reply format:  [thread:id] info: <client_ip> <domain>. <type> IN <rcode> <time> <cached> <size>
-->
<decoder name="qfeeds-unbound">
  <prematch>unbound \d+ - </prematch>
</decoder>

<decoder name="qfeeds-unbound-rfc3164">
  <program_name>^unbound$</program_name>
</decoder>

<decoder name="qfeeds-unbound-query">
  <parent>qfeeds-unbound</parent>
  <regex type="pcre2">\[\d+:\d+\] info: ([\da-fA-F.:]+) (\S+)\.\s+(\w+)\s+IN(?:\s+(\S+))?</regex>
  <order>srcip,url,extra_data,status</order>
</decoder>

<decoder name="qfeeds-unbound-query-rfc3164">
  <parent>qfeeds-unbound-rfc3164</parent>
  <regex type="pcre2">\[\d+:\d+\] info: ([\da-fA-F.:]+) (\S+)\.\s+(\w+)\s+IN(?:\s+(\S+))?</regex>
  <order>srcip,url,extra_data,status</order>
</decoder>
DECODERS_EOF

    if [ "$HAS_HASH_COLLECTIONS" = "yes" ]; then
        cat >> "$WAZUH_DECODERS_FILE" <<'HASH_DECODERS_EOF'

<!--
  Sysmon hash extraction decoders.
  Extract individual hash values from Sysmon Hashes field for CDB matching.
  Sysmon format: SHA1=xxx,MD5=yyy,SHA256=zzz,IMPHASH=www
  These run as children of windows_eventchannel.
-->
<decoder name="qfeeds-sysmon-sha256">
  <parent>windows_eventchannel</parent>
  <prematch>SHA256=</prematch>
  <regex type="pcre2">SHA256=([A-Fa-f0-9]{64})</regex>
  <order>sha256</order>
</decoder>

<decoder name="qfeeds-sysmon-sha1">
  <parent>windows_eventchannel</parent>
  <prematch>SHA1=</prematch>
  <regex type="pcre2">SHA1=([A-Fa-f0-9]{40})</regex>
  <order>sha1</order>
</decoder>

<decoder name="qfeeds-sysmon-md5">
  <parent>windows_eventchannel</parent>
  <prematch>MD5=</prematch>
  <regex type="pcre2">MD5=([A-Fa-f0-9]{32})</regex>
  <order>md5</order>
</decoder>
HASH_DECODERS_EOF
        echo "  Hash extraction decoders added."
    fi

    chown wazuh:wazuh "$WAZUH_DECODERS_FILE" 2>/dev/null || \
        chown ossec:ossec "$WAZUH_DECODERS_FILE" 2>/dev/null || true
    chmod 660 "$WAZUH_DECODERS_FILE"

    echo "Wazuh decoders installed at $WAZUH_DECODERS_FILE"
}

install_wazuh_rules() {
    echo
    echo "=== Installing Wazuh Rules ==="

    # Back up existing rules file if it exists
    if [ -f "$WAZUH_RULES_FILE" ]; then
        cp "$WAZUH_RULES_FILE" "${WAZUH_RULES_FILE}.bak.$(date +%s)"
        echo "Backed up existing rules file."
    fi

    cat > "$WAZUH_RULES_FILE" <<'RULES_HEADER'
<!-- =============================================================================
     Q-Feeds Threat Intelligence Rules
     Generated by Q-Feeds Wazuh Integration installer
     https://qfeeds.com
     ============================================================================= -->

RULES_HEADER

    # Build rules XML dynamically based on enabled feeds/mode
    local install_ip_rules="no"
    local install_domain_rules="no"
    local install_url_rules="no"
    local install_hash_rules="no"

    if [ "$INTEGRATION_MODE" = "taxii" ]; then
        install_ip_rules="yes"
        install_domain_rules="yes"
        install_url_rules="yes"
        [ "$HAS_HASH_COLLECTIONS" = "yes" ] && install_hash_rules="yes"
    else
        [ "$FEED_MALWARE_IP" = "yes" ] && install_ip_rules="yes"
        [ "$FEED_MALWARE_DOMAINS" = "yes" ] && install_domain_rules="yes"
        [ "$FEED_MALICIOUS_URLS" = "yes" ] && install_url_rules="yes"
    fi

    {
        echo '<group name="qfeeds,">'

        if [ "$install_ip_rules" = "yes" ]; then
            cat <<'IP_RULES'

  <rule id="100200" level="10">
    <if_group>web|attack|attacks|syslog|firewall|ids|sysmon</if_group>
    <list field="srcip" lookup="address_match_key">etc/lists/qfeeds-malware-ip</list>
    <description>Q-Feeds: Source IP found in malware IP blacklist</description>
    <group>threat_intelligence,qfeeds_ip,</group>
  </rule>

  <rule id="100201" level="10">
    <if_group>web|attack|attacks|syslog|firewall|ids|sysmon</if_group>
    <list field="dstip" lookup="address_match_key">etc/lists/qfeeds-malware-ip</list>
    <description>Q-Feeds: Destination IP found in malware IP blacklist</description>
    <group>threat_intelligence,qfeeds_ip,</group>
  </rule>
IP_RULES
        fi

        if [ "$install_domain_rules" = "yes" ]; then
            cat <<'DOMAIN_RULES'

  <!-- Domain match: web server / proxy logs (uses decoded url field) -->
  <rule id="100210" level="10">
    <if_group>web|proxy</if_group>
    <list field="url" lookup="match_key">etc/lists/qfeeds-malware-domains</list>
    <description>Q-Feeds: Domain found in malware domain blacklist</description>
    <group>threat_intelligence,qfeeds_domain,</group>
  </rule>

  <!-- Domain match: Windows Sysmon Event ID 22 (DNS Query) -->
  <rule id="100211" level="10">
    <if_group>sysmon_event_22</if_group>
    <list field="win.eventdata.queryName" lookup="match_key">etc/lists/qfeeds-malware-domains</list>
    <description>Q-Feeds: DNS query to malware domain (Sysmon)</description>
    <group>threat_intelligence,qfeeds_domain,</group>
  </rule>

  <!-- Domain match: Unbound DNS resolver via RFC5424 logs (requires Log Queries enabled) -->
  <rule id="100212" level="10">
    <decoded_as>qfeeds-unbound</decoded_as>
    <list field="url" lookup="match_key">etc/lists/qfeeds-malware-domains</list>
    <description>Q-Feeds: DNS query to malware domain (Unbound)</description>
    <group>threat_intelligence,qfeeds_domain,</group>
  </rule>

  <!-- Domain match: Unbound DNS resolver via RFC3164/syslog logs (requires Log Queries enabled) -->
  <rule id="100213" level="10">
    <decoded_as>qfeeds-unbound-rfc3164</decoded_as>
    <list field="url" lookup="match_key">etc/lists/qfeeds-malware-domains</list>
    <description>Q-Feeds: DNS query to malware domain (Unbound)</description>
    <group>threat_intelligence,qfeeds_domain,</group>
  </rule>
DOMAIN_RULES
        fi

        if [ "$install_url_rules" = "yes" ]; then
            cat <<'PHISHING_RULES'

  <!-- Phishing URL match: web server / proxy logs (uses decoded url field) -->
  <rule id="100220" level="10">
    <if_group>web|proxy</if_group>
    <list field="url" lookup="match_key">etc/lists/qfeeds-phishing-urls</list>
    <description>Q-Feeds: Phishing URL detected in web/proxy logs</description>
    <group>threat_intelligence,qfeeds_phishing,</group>
  </rule>
PHISHING_RULES
        fi

        if [ "$install_hash_rules" = "yes" ]; then
            cat <<'HASH_RULES'

  <!-- Hash match: SHA-256 in Sysmon process/driver/image events -->
  <rule id="100230" level="10">
    <if_group>sysmon_event1|sysmon_event6|sysmon_event7</if_group>
    <list field="sha256" lookup="match_key">etc/lists/qfeeds-malicious-hashes-sha256</list>
    <description>Q-Feeds: SHA-256 hash found in malicious hash list (Sysmon)</description>
    <group>threat_intelligence,qfeeds_hash,</group>
  </rule>

  <!-- Hash match: SHA-1 in Sysmon process/driver/image events -->
  <rule id="100231" level="10">
    <if_group>sysmon_event1|sysmon_event6|sysmon_event7</if_group>
    <list field="sha1" lookup="match_key">etc/lists/qfeeds-malicious-hashes-sha1</list>
    <description>Q-Feeds: SHA-1 hash found in malicious hash list (Sysmon)</description>
    <group>threat_intelligence,qfeeds_hash,</group>
  </rule>

  <!-- Hash match: MD5 in Sysmon process/driver/image events -->
  <rule id="100232" level="10">
    <if_group>sysmon_event1|sysmon_event6|sysmon_event7</if_group>
    <list field="md5" lookup="match_key">etc/lists/qfeeds-malicious-hashes-md5</list>
    <description>Q-Feeds: MD5 hash found in malicious hash list (Sysmon)</description>
    <group>threat_intelligence,qfeeds_hash,</group>
  </rule>
HASH_RULES
        fi

        echo
        echo '</group>'
    } >> "$WAZUH_RULES_FILE"

    chown wazuh:wazuh "$WAZUH_RULES_FILE" 2>/dev/null || \
        chown ossec:ossec "$WAZUH_RULES_FILE" 2>/dev/null || true
    chmod 660 "$WAZUH_RULES_FILE"

    echo "Wazuh rules installed at $WAZUH_RULES_FILE"
}

configure_ossec() {
    echo
    echo "=== Configuring ossec.conf ==="

    # Back up ossec.conf
    cp "$WAZUH_CONF" "${WAZUH_CONF}.bak.$(date +%s)"
    echo "Backed up ossec.conf."

    # Check if Q-Feeds config already exists and remove it
    if grep -q "Q-FEEDS-LISTS-START" "$WAZUH_CONF"; then
        echo "Removing previous Q-Feeds CDB list configuration..."
        sed -i '/<!-- Q-FEEDS-LISTS-START -->/,/<!-- Q-FEEDS-LISTS-END -->/d' "$WAZUH_CONF"
    fi
    if grep -q "Q-FEEDS-AR-START" "$WAZUH_CONF"; then
        echo "Removing previous Q-Feeds Active Response configuration..."
        sed -i '/<!-- Q-FEEDS-AR-START -->/,/<!-- Q-FEEDS-AR-END -->/d' "$WAZUH_CONF"
    fi

    # Add CDB list references inside <ruleset>
    local list_block=""
    list_block="    <!-- Q-FEEDS-LISTS-START -->"

    if [ "$INTEGRATION_MODE" = "taxii" ]; then
        list_block="$list_block\n    <list>etc/lists/qfeeds-malware-ip</list>"
        list_block="$list_block\n    <list>etc/lists/qfeeds-malware-domains</list>"
        list_block="$list_block\n    <list>etc/lists/qfeeds-phishing-urls</list>"
        if [ "$HAS_HASH_COLLECTIONS" = "yes" ]; then
            list_block="$list_block\n    <list>etc/lists/qfeeds-malicious-hashes-md5</list>"
            list_block="$list_block\n    <list>etc/lists/qfeeds-malicious-hashes-sha1</list>"
            list_block="$list_block\n    <list>etc/lists/qfeeds-malicious-hashes-sha256</list>"
        fi
    else
        if [ "$FEED_MALWARE_IP" = "yes" ]; then
            list_block="$list_block\n    <list>etc/lists/qfeeds-malware-ip</list>"
        fi
        if [ "$FEED_MALWARE_DOMAINS" = "yes" ]; then
            list_block="$list_block\n    <list>etc/lists/qfeeds-malware-domains</list>"
        fi
        if [ "$FEED_MALICIOUS_URLS" = "yes" ]; then
            list_block="$list_block\n    <list>etc/lists/qfeeds-phishing-urls</list>"
        fi
    fi

    list_block="$list_block\n    <!-- Q-FEEDS-LISTS-END -->"

    # Insert before </ruleset>
    sed -i "/<\/ruleset>/i\\$list_block" "$WAZUH_CONF"
    echo "Added CDB list references to ossec.conf."

    # Add Active Response if enabled
    if [ "$ACTIVE_RESPONSE" = "yes" ]; then
        local ar_block=""
        ar_block="  <!-- Q-FEEDS-AR-START -->\n"
        ar_block="${ar_block}  <active-response>\n"
        ar_block="${ar_block}    <disabled>no</disabled>\n"
        ar_block="${ar_block}    <command>firewall-drop</command>\n"
        ar_block="${ar_block}    <location>local</location>\n"
        ar_block="${ar_block}    <rules_id>100200,100201</rules_id>\n"
        ar_block="${ar_block}    <timeout>$ACTIVE_RESPONSE_TIMEOUT</timeout>\n"
        ar_block="${ar_block}  </active-response>\n"
        ar_block="${ar_block}  <!-- Q-FEEDS-AR-END -->"

        # Insert before the last </ossec_config>
        sed -i "/<\/ossec_config>/i\\$ar_block" "$WAZUH_CONF"
        echo "Added Active Response configuration to ossec.conf (timeout: ${ACTIVE_RESPONSE_TIMEOUT}s)."
    fi
}

setup_cron() {
    echo
    echo "=== Setting Up Cron Job ==="
    if [ "$INTEGRATION_MODE" = "taxii" ]; then
        # Random hour (0-23) per install to spread TAXII server load across the day
        RANDOM_HOUR=$((RANDOM % 24))
        DEFAULT_CRON="0 $RANDOM_HOUR * * *"
        echo "TAXII collections can be large; a daily schedule is recommended."
        read -rp "Enter cron schedule [default: 0 $RANDOM_HOUR * * * (daily)]: " CRON_SCHEDULE
    else
        DEFAULT_CRON="*/20 * * * *"
        read -rp "Enter cron schedule [default: */20 * * * * (every 20 minutes)]: " CRON_SCHEDULE
    fi
    CRON_SCHEDULE=${CRON_SCHEDULE:-$DEFAULT_CRON}

    # Remove any existing Q-Feeds Wazuh cron entries, then add new one
    (crontab -l 2>/dev/null | grep -v "$UPDATER_DEST" || true; echo "$CRON_SCHEDULE $CRON_CMD") | crontab -
    echo "Cron job added: $CRON_SCHEDULE $CRON_CMD"
}

create_taxii_placeholder_lists() {
    mkdir -p "$WAZUH_LISTS_DIR"
    # Minimal valid CDB list files so Wazuh does not complain about missing files.
    # Using RFC 5737 TEST-NET and reserved values that will not match real traffic.
    for spec in "qfeeds-malware-ip:192.0.2.1:" "qfeeds-malware-domains:placeholder.invalid:" \
                "qfeeds-phishing-urls:https://placeholder.invalid/:" \
                "qfeeds-malicious-hashes-md5:00000000000000000000000000000000:" \
                "qfeeds-malicious-hashes-sha1:0000000000000000000000000000000000000000:" \
                "qfeeds-malicious-hashes-sha256:0000000000000000000000000000000000000000000000000000000000000000:"; do
        file="${spec%%:*}"
        rest="${spec#*:}"
        path="$WAZUH_LISTS_DIR/$file"
        echo "$rest" > "$path"
        chown wazuh:wazuh "$path" 2>/dev/null || chown ossec:ossec "$path" 2>/dev/null || true
        chmod 660 "$path"
    done
    if [ -x "$WAZUH_DIR/bin/ossec-makelists" ]; then
        "$WAZUH_DIR/bin/ossec-makelists" 2>/dev/null || true
    fi
    echo "  Created placeholder CDB lists (cron will populate them on first run)."
}

run_initial_update() {
    if [ "$INTEGRATION_MODE" = "taxii" ]; then
        echo
        echo "=== Initial Feed Download (TAXII) ==="
        echo "TAXII collections can contain millions of objects. Downloading now may take a long time."
        echo
        read -rp "Run initial feed download now? (skip to let cron run it in background) [y/N]: " RUN_NOW_CHOICE
        case "$RUN_NOW_CHOICE" in
            [yY][eE][sS]|[yY])
                echo
                echo "Downloading feeds (this may take several minutes or hours for large collections)..."
                QFEEDS_FORCE_UPDATE=1 "$WAZUH_PYTHON" "$UPDATER_DEST"
                local exit_code=$?
                if [ $exit_code -eq 0 ]; then
                    echo "Initial feed download completed successfully."
                else
                    echo "Warning: Initial feed download exited with code $exit_code."
                    echo "Check the log at $LOG_FILE for details."
                fi
                ;;
            *)
                echo
                echo "Skipping initial download."
                create_taxii_placeholder_lists
                echo "The cron job will run the first full download. Monitor $LOG_FILE for progress."
                ;;
        esac
    else
        echo
        echo "=== Running Initial Feed Download ==="
        echo "This will download the feeds and create the CDB lists..."
        echo

        QFEEDS_FORCE_UPDATE=1 "$WAZUH_PYTHON" "$UPDATER_DEST"
        local exit_code=$?

        if [ $exit_code -eq 0 ]; then
            echo
            echo "Initial feed download completed successfully."
        else
            echo
            echo "Warning: Initial feed download exited with code $exit_code."
            echo "Check the log at $LOG_FILE for details."
            echo "The cron job will retry automatically."
        fi
    fi
}

restart_wazuh() {
    echo
    echo "=== Restarting Wazuh Manager ==="
    if systemctl is-active --quiet wazuh-manager; then
        systemctl restart wazuh-manager
        echo "Wazuh manager restarted."
    elif [ -x "$WAZUH_DIR/bin/wazuh-control" ]; then
        "$WAZUH_DIR/bin/wazuh-control" restart
        echo "Wazuh manager restarted."
    elif [ -x "$WAZUH_DIR/bin/ossec-control" ]; then
        "$WAZUH_DIR/bin/ossec-control" restart
        echo "Wazuh manager restarted."
    else
        echo "Warning: Could not restart Wazuh manager automatically."
        echo "Please restart it manually: systemctl restart wazuh-manager"
    fi
}

# ================================
# Main Execution
# ================================
echo "================================================================================"
echo "Q-Feeds Wazuh Integration Installer"
echo "================================================================================"
echo

preflight_checks
accept_terms
configure_script
install_updater
install_wazuh_decoders
install_wazuh_rules
configure_ossec
setup_cron
run_initial_update
restart_wazuh

echo
echo "================================================================================"
echo "Q-Feeds Wazuh Integration installed successfully!"
echo "================================================================================"
echo
echo "  Config file:    $CONFIG_FILE"
echo "  Updater script: $UPDATER_DEST"
echo "  Wazuh decoders: $WAZUH_DECODERS_FILE"
echo "  Wazuh rules:    $WAZUH_RULES_FILE"
echo "  CDB lists:      $WAZUH_LISTS_DIR/qfeeds-*"
echo "  Log file:       $LOG_FILE"
echo
echo "  To uninstall:   sudo ./uninstall.sh"
echo "  To force update: sudo QFEEDS_FORCE_UPDATE=1 $CRON_CMD"
echo
exit 0
