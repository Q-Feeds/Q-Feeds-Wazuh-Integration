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
    LICENSE_PHISHING_URLS="unknown"
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
    for ft in ["malware_ip", "malware_domains", "phishing_urls"]:
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
    echo "$license_output" | grep -q "^phishing_urls=yes" && LICENSE_PHISHING_URLS="yes"
    echo "$license_output" | grep -q "^phishing_urls=no" && LICENSE_PHISHING_URLS="no"

    if [ -n "$LICENSE_INFO" ]; then
        echo "  License: $LICENSE_INFO"
    fi
    echo

    local status
    for feed_label in "Malware IPs:LICENSE_MALWARE_IP" "Malware Domains:LICENSE_MALWARE_DOMAINS" "Phishing URLs:LICENSE_PHISHING_URLS"; do
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

configure_script() {
    echo
    echo "=== Configuration ==="
    echo

    mkdir -p "$CONFIG_DIR"

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

    if [ "$LICENSE_PHISHING_URLS" = "no" ]; then
        echo "  Phishing URLs feed: not licensed — skipping"
        FEED_PHISHING_URLS="no"
    elif [ "$LICENSE_PHISHING_URLS" = "yes" ]; then
        read -rp "Enable Phishing URLs feed? [Y/n]: " FEED_PHISHING_CHOICE
        case "$FEED_PHISHING_CHOICE" in
            [nN][oO]|[nN]) FEED_PHISHING_URLS="no" ;;
            *) FEED_PHISHING_URLS="yes" ;;
        esac
    else
        read -rp "Enable Phishing URLs feed? (license status unknown) [y/N]: " FEED_PHISHING_CHOICE
        case "$FEED_PHISHING_CHOICE" in
            [yY][eE][sS]|[yY]) FEED_PHISHING_URLS="yes" ;;
            *) FEED_PHISHING_URLS="no" ;;
        esac
    fi

    if [ "$FEED_MALWARE_IP" = "no" ] && [ "$FEED_MALWARE_DOMAINS" = "no" ] && [ "$FEED_PHISHING_URLS" = "no" ]; then
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

    cat > "$CONFIG_FILE" <<EOF
# Q-Feeds Wazuh Integration Configuration
# Generated by install.sh on $(date -u '+%Y-%m-%dT%H:%M:%SZ')

API_TOKEN="$API_TOKEN"

FEED_MALWARE_IP="$FEED_MALWARE_IP"
FEED_MALWARE_DOMAINS="$FEED_MALWARE_DOMAINS"
FEED_PHISHING_URLS="$FEED_PHISHING_URLS"

IPV6="$IPV6"

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

    # Build rules XML dynamically based on enabled feeds
    {
        echo '<group name="qfeeds,">'

        if [ "$FEED_MALWARE_IP" = "yes" ]; then
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

        if [ "$FEED_MALWARE_DOMAINS" = "yes" ]; then
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

        if [ "$FEED_PHISHING_URLS" = "yes" ]; then
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
    if [ "$FEED_MALWARE_IP" = "yes" ]; then
        list_block="$list_block\n    <list>etc/lists/qfeeds-malware-ip</list>"
    fi
    if [ "$FEED_MALWARE_DOMAINS" = "yes" ]; then
        list_block="$list_block\n    <list>etc/lists/qfeeds-malware-domains</list>"
    fi
    if [ "$FEED_PHISHING_URLS" = "yes" ]; then
        list_block="$list_block\n    <list>etc/lists/qfeeds-phishing-urls</list>"
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
    read -rp "Enter cron schedule [default: */20 * * * *]: " CRON_SCHEDULE
    CRON_SCHEDULE=${CRON_SCHEDULE:-"*/20 * * * *"}

    # Remove any existing Q-Feeds Wazuh cron entries, then add new one
    (crontab -l 2>/dev/null | grep -v "$UPDATER_DEST"; echo "$CRON_SCHEDULE $CRON_CMD") | crontab -
    echo "Cron job added: $CRON_SCHEDULE $CRON_CMD"
}

run_initial_update() {
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
