#!/bin/bash
# =============================================================================
# Q-Feeds Wazuh Integration Uninstaller
# =============================================================================
# Copyright (c) 2026 Q-Feeds
# All rights reserved.
#
# Removes the Q-Feeds Wazuh Integration from your system, including CDB lists,
# custom rules, cron jobs, configuration files, and ossec.conf modifications.
#
# This does NOT remove the Wazuh manager or any system packages.
# =============================================================================

set -e

if [ "$EUID" -ne 0 ]; then
    echo "Error: This uninstaller must be run as root."
    exit 1
fi

echo "================================================================================"
echo "Q-Feeds Wazuh Integration Uninstaller"
echo "================================================================================"
echo

read -rp "Are you sure you want to uninstall the Q-Feeds Wazuh Integration? (yes/no): " CONFIRM
if [[ ! "$CONFIRM" =~ ^[Yy]([Ee][Ss])?$ ]]; then
    echo "Uninstallation aborted."
    exit 0
fi

echo

# ================================
# Constants
# ================================
CONFIG_FILE="/etc/qfeeds/qfeeds_wazuh.conf"
UPDATER_DEST="/usr/local/bin/qfeeds-wazuh-updater.py"
WAZUH_DIR="/var/ossec"
WAZUH_RULES_FILE="$WAZUH_DIR/etc/rules/qfeeds_rules.xml"
WAZUH_DECODERS_FILE="$WAZUH_DIR/etc/decoders/qfeeds_decoders.xml"
WAZUH_LISTS_DIR="$WAZUH_DIR/etc/lists"
WAZUH_CONF="$WAZUH_DIR/etc/ossec.conf"
LOG_FILE="/var/log/qfeeds_wazuh.log"

# ================================
# Remove Cron Job
# ================================
echo "Removing cron job..."
if crontab -l 2>/dev/null | grep -q "$UPDATER_DEST"; then
    (crontab -l 2>/dev/null | grep -v "$UPDATER_DEST") | crontab -
    echo "  Cron job removed."
else
    echo "  No cron job found."
fi

# ================================
# Clean ossec.conf
# ================================
echo "Cleaning ossec.conf..."
if [ -f "$WAZUH_CONF" ]; then
    CHANGES_MADE=0

    if grep -q "Q-FEEDS-LISTS-START" "$WAZUH_CONF"; then
        cp "$WAZUH_CONF" "${WAZUH_CONF}.bak.$(date +%s)"
        sed -i '/<!-- Q-FEEDS-LISTS-START -->/,/<!-- Q-FEEDS-LISTS-END -->/d' "$WAZUH_CONF"
        echo "  Removed CDB list references from ossec.conf."
        CHANGES_MADE=1
    fi

    if grep -q "Q-FEEDS-AR-START" "$WAZUH_CONF"; then
        if [ "$CHANGES_MADE" -eq 0 ]; then
            cp "$WAZUH_CONF" "${WAZUH_CONF}.bak.$(date +%s)"
        fi
        sed -i '/<!-- Q-FEEDS-AR-START -->/,/<!-- Q-FEEDS-AR-END -->/d' "$WAZUH_CONF"
        echo "  Removed Active Response configuration from ossec.conf."
    fi

    if [ "$CHANGES_MADE" -eq 0 ] && ! grep -q "Q-FEEDS-AR-START" "${WAZUH_CONF}.bak."* 2>/dev/null; then
        echo "  No Q-Feeds configuration found in ossec.conf."
    fi
else
    echo "  ossec.conf not found at $WAZUH_CONF. Skipping."
fi

# ================================
# Remove Wazuh Decoders File
# ================================
echo "Removing Wazuh decoders..."
if [ -f "$WAZUH_DECODERS_FILE" ]; then
    rm -f "$WAZUH_DECODERS_FILE"
    echo "  Removed $WAZUH_DECODERS_FILE"
else
    echo "  Decoders file not found."
fi

# ================================
# Remove Wazuh Rules File
# ================================
echo "Removing Wazuh rules..."
if [ -f "$WAZUH_RULES_FILE" ]; then
    rm -f "$WAZUH_RULES_FILE"
    echo "  Removed $WAZUH_RULES_FILE"
else
    echo "  Rules file not found."
fi

# ================================
# Remove CDB Lists
# ================================
echo "Removing CDB lists..."
REMOVED_LISTS=0
for f in "$WAZUH_LISTS_DIR"/qfeeds-malware-ip "$WAZUH_LISTS_DIR"/qfeeds-malware-ip.cdb \
         "$WAZUH_LISTS_DIR"/qfeeds-malware-domains "$WAZUH_LISTS_DIR"/qfeeds-malware-domains.cdb \
         "$WAZUH_LISTS_DIR"/qfeeds-phishing-urls "$WAZUH_LISTS_DIR"/qfeeds-phishing-urls.cdb; do
    if [ -f "$f" ]; then
        rm -f "$f"
        echo "  Removed $(basename "$f")"
        REMOVED_LISTS=$((REMOVED_LISTS + 1))
    fi
done
if [ "$REMOVED_LISTS" -eq 0 ]; then
    echo "  No CDB lists found."
fi

# ================================
# Remove Updater Script
# ================================
echo "Removing updater script..."
if [ -f "$UPDATER_DEST" ]; then
    rm -f "$UPDATER_DEST"
    echo "  Removed $UPDATER_DEST"
else
    echo "  Updater script not found."
fi

# ================================
# Remove Configuration
# ================================
echo "Removing configuration..."
if [ -f "$CONFIG_FILE" ]; then
    rm -f "$CONFIG_FILE"
    echo "  Removed $CONFIG_FILE"
fi

# Remove config directory only if empty (other Q-Feeds integrations may share it)
if [ -d "/etc/qfeeds" ] && [ -z "$(ls -A /etc/qfeeds 2>/dev/null)" ]; then
    rmdir "/etc/qfeeds"
    echo "  Removed /etc/qfeeds/ directory."
fi

# ================================
# Remove Log and Lock Files
# ================================
echo "Removing log and lock files..."
if [ -f "$LOG_FILE" ]; then
    rm -f "$LOG_FILE"
    echo "  Removed $LOG_FILE"
fi

rm -f /var/lock/qfeeds_wazuh.lock 2>/dev/null || true

# ================================
# Restart Wazuh Manager
# ================================
echo
echo "Restarting Wazuh manager..."
if systemctl is-active --quiet wazuh-manager 2>/dev/null; then
    systemctl restart wazuh-manager
    echo "  Wazuh manager restarted."
elif [ -x "$WAZUH_DIR/bin/wazuh-control" ]; then
    "$WAZUH_DIR/bin/wazuh-control" restart
    echo "  Wazuh manager restarted."
elif [ -x "$WAZUH_DIR/bin/ossec-control" ]; then
    "$WAZUH_DIR/bin/ossec-control" restart
    echo "  Wazuh manager restarted."
else
    echo "  Warning: Could not restart Wazuh manager. Please restart manually."
fi

echo
echo "================================================================================"
echo "Q-Feeds Wazuh Integration has been uninstalled."
echo "================================================================================"
echo
echo "Note: ossec.conf backup files (ossec.conf.bak.*) have been preserved."
echo "You may remove them manually if no longer needed."
echo
exit 0
