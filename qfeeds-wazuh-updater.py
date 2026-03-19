#!/var/ossec/framework/python/bin/python3
# =============================================================================
# Q-Feeds Wazuh Integration - Feed Updater
# =============================================================================
# Copyright (c) 2026 Q-Feeds
# All rights reserved.
#
# Downloads threat intelligence feeds from the Q-Feeds API, converts them to
# Wazuh CDB list format, and triggers a recompile/restart when changes are
# detected.
#
# Designed to run as a cron job. Respects the license API schedule so it only
# fetches when new data is available.
# =============================================================================

import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from urllib.parse import urlencode

# ================================
# Constants
# ================================
CONFIG_FILE = "/etc/qfeeds/qfeeds_wazuh.conf"
LOCK_FILE = "/var/lock/qfeeds_wazuh.lock"
WAZUH_LISTS_DIR = "/var/ossec/etc/lists"
WAZUH_MAKELISTS = "/var/ossec/bin/ossec-makelists"
API_BASE = "https://api.qfeeds.com"

FEED_TYPE_IP = "malware_ip"
FEED_TYPE_DOMAINS = "malware_domains"
FEED_TYPE_PHISHING_URLS = "phishing_urls"

CDB_FILE_IP = os.path.join(WAZUH_LISTS_DIR, "qfeeds-malware-ip")
CDB_FILE_DOMAINS = os.path.join(WAZUH_LISTS_DIR, "qfeeds-malware-domains")
CDB_FILE_PHISHING_URLS = os.path.join(WAZUH_LISTS_DIR, "qfeeds-phishing-urls")
CDB_FILE_HASHES_MD5 = os.path.join(WAZUH_LISTS_DIR, "qfeeds-malicious-hashes-md5")
CDB_FILE_HASHES_SHA1 = os.path.join(WAZUH_LISTS_DIR, "qfeeds-malicious-hashes-sha1")
CDB_FILE_HASHES_SHA256 = os.path.join(WAZUH_LISTS_DIR, "qfeeds-malicious-hashes-sha256")

# Supported CIDR masks for Wazuh CDB address_match_key (IPv4 only)
SUPPORTED_MASKS = {32, 24, 16, 8}

TAXII_CONTENT_TYPE = "application/taxii+json;version=2.1"
TAXII_OBJECTS_LIMIT = 1000
DEFAULT_TAXII_URL = "https://taxii.qfeeds.com"

IOC_TYPE_IP = "ip"
IOC_TYPE_DOMAIN = "domain"
IOC_TYPE_URL = "url"
IOC_TYPE_MD5 = "md5"
IOC_TYPE_SHA1 = "sha1"
IOC_TYPE_SHA256 = "sha256"

STIX_FIELD_MAP = {
    "ipv4-addr:value": IOC_TYPE_IP,
    "ipv6-addr:value": IOC_TYPE_IP,
    "domain-name:value": IOC_TYPE_DOMAIN,
    "url:value": IOC_TYPE_URL,
    # Quoted hash keys (STIX 2.1 spec)
    "file:hashes.'MD5'": IOC_TYPE_MD5,
    "file:hashes.'SHA-1'": IOC_TYPE_SHA1,
    "file:hashes.'SHA-256'": IOC_TYPE_SHA256,
    # Unquoted hash keys (Q-Feeds TAXII and other servers)
    "file:hashes.MD5": IOC_TYPE_MD5,
    "file:hashes.SHA-1": IOC_TYPE_SHA1,
    "file:hashes.SHA-256": IOC_TYPE_SHA256,
}

CDB_FILE_BY_IOC_TYPE = {
    IOC_TYPE_IP: CDB_FILE_IP,
    IOC_TYPE_DOMAIN: CDB_FILE_DOMAINS,
    IOC_TYPE_URL: CDB_FILE_PHISHING_URLS,
    IOC_TYPE_MD5: CDB_FILE_HASHES_MD5,
    IOC_TYPE_SHA1: CDB_FILE_HASHES_SHA1,
    IOC_TYPE_SHA256: CDB_FILE_HASHES_SHA256,
}


# ================================
# Logging
# ================================
LOG_FILE = "/var/log/qfeeds_wazuh.log"


def log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{timestamp} : {message}"
    print(line)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass


# ================================
# Configuration
# ================================
def read_config():
    """Parse the shell-style config file into a dict."""
    config = {}
    if not os.path.isfile(CONFIG_FILE):
        log(f"Error: Config file not found: {CONFIG_FILE}")
        sys.exit(1)

    with open(CONFIG_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.match(r'^([A-Z_]+)="?(.*?)"?\s*$', line)
            if match:
                config[match.group(1)] = match.group(2)

    mode = config.get("INTEGRATION_MODE", "standard").lower()
    if mode == "taxii":
        required = ["TAXII_URL", "TAXII_USERNAME", "TAXII_PASSWORD", "TAXII_API_ROOT", "TAXII_COLLECTIONS"]
    else:
        required = ["API_TOKEN"]

    for key in required:
        if key not in config or not config[key]:
            log(f"Error: Required config key '{key}' is missing or empty.")
            sys.exit(1)

    return config


# ================================
# HTTP via curl
# ================================
def curl_get(url, timeout=120):
    """
    Fetch a URL using curl. Returns (http_status_code, response_body) on
    success, or (None, error_message) on failure.
    """
    try:
        result = subprocess.run(
            [
                "curl", "-s",
                "-w", "\n%{http_code}",
                "-m", str(timeout),
                "-A", "Q-Feeds-Wazuh/1.0",
                "-o", "-",
                url,
            ],
            capture_output=True,
            text=True,
            timeout=timeout + 10,
        )
    except FileNotFoundError:
        return None, "curl is not installed"
    except subprocess.TimeoutExpired:
        return None, "curl timed out"

    if result.returncode != 0:
        stderr = result.stderr.strip() if result.stderr else f"exit code {result.returncode}"
        return None, f"curl failed: {stderr}"

    output = result.stdout
    last_newline = output.rfind("\n")
    if last_newline == -1:
        return None, "unexpected curl output (no status code)"

    body = output[:last_newline]
    status_str = output[last_newline + 1:].strip()
    try:
        status = int(status_str)
    except ValueError:
        return None, f"could not parse HTTP status: {status_str}"

    return status, body


# ================================
# TAXII 2.1 Client
# ================================
def taxii_get(url, username, password, timeout=300):
    """
    Fetch from a TAXII 2.1 endpoint using curl with Basic auth.
    Returns (http_status_code, response_body) or (None, error_message).
    """
    try:
        result = subprocess.run(
            [
                "curl", "-s",
                "-w", "\n%{http_code}",
                "-m", str(timeout),
                "-u", f"{username}:{password}",
                "-H", f"Accept: {TAXII_CONTENT_TYPE}",
                "-A", "Q-Feeds-Wazuh/1.0",
                "-o", "-",
                url,
            ],
            capture_output=True,
            text=True,
            timeout=timeout + 10,
        )
    except FileNotFoundError:
        return None, "curl is not installed"
    except subprocess.TimeoutExpired:
        return None, "curl timed out"

    if result.returncode != 0:
        stderr = result.stderr.strip() if result.stderr else f"exit code {result.returncode}"
        return None, f"curl failed: {stderr}"

    output = result.stdout
    last_newline = output.rfind("\n")
    if last_newline == -1:
        return None, "unexpected curl output (no status code)"

    body = output[:last_newline]
    status_str = output[last_newline + 1:].strip()
    try:
        status = int(status_str)
    except ValueError:
        return None, f"could not parse HTTP status: {status_str}"

    return status, body


# ================================
# STIX Pattern Parsing
# ================================
# Match STIX patterns; operator may have optional spaces (e.g. value='x' or value = 'x')
_STIX_PATTERN_RE = re.compile(
    r"\[(\S+)\s*(?:=|LIKE)\s*'(.+?)'\]"
)


def parse_stix_pattern(pattern):
    """
    Parse a STIX indicator pattern and return (ioc_type, value).
    Returns None if the pattern is not recognized.

    Supported patterns:
      [ipv4-addr:value = '1.2.3.4']
      [ipv6-addr:value = '2001:db8::1']
      [domain-name:value = 'evil.com']
      [url:value = 'evil.com/path']
      [url:value LIKE 'evil.com/path']
      [file:hashes.'SHA-256' = 'ABCD...']
      [file:hashes.'SHA-1' = 'ABCD...']
      [file:hashes.'MD5' = 'ABCD...']
    """
    if not pattern:
        return None

    m = _STIX_PATTERN_RE.search(pattern)
    if not m:
        return None

    field = m.group(1)
    value = m.group(2)

    ioc_type = STIX_FIELD_MAP.get(field)
    if not ioc_type:
        return None

    if ioc_type in (IOC_TYPE_MD5, IOC_TYPE_SHA1, IOC_TYPE_SHA256):
        value = value.lower()

    return ioc_type, value


# Keys in description that map to our context fields (from Kilo/Echo TAXII feeds)
DESC_KEY_ALIASES = {
    "threat": "threat",
    "malware_name": "threat",
    "malware": "threat",
    "name": "threat",
    "label": "threat",
    "category": "category",
    "mitre": "mitre",
    "geo": "geo",
    "country": "geo",
    "industry": "industry",
    "file_type": "file_type",
}
CONTEXT_FIELDS = {"threat", "category", "mitre", "geo", "industry", "file_type"}


def parse_description_context(description):
    """
    Extract useful threat context from a STIX description field.
    Returns a compact string for use as a CDB value, or empty string.

    Supports:
    - key1=val1;key2=val2 (standard; keys: threat, category, mitre, geo + aliases)
    - JSON object with threat/name/category etc.
    - Plain text (single word or short phrase used as threat)
    """
    if not description or not isinstance(description, str):
        return ""

    desc = description.strip()
    if not desc:
        return ""

    parts = []

    # 1. Try JSON (e.g. {"threat":"WannaCry","category":"Ransomware"})
    if desc.startswith("{"):
        try:
            data = json.loads(desc)
            if isinstance(data, dict):
                for key in ("threat", "malware_name", "malware", "name", "category", "mitre", "geo"):
                    val = data.get(key) or data.get(key.replace("_", "-"))
                    if val and isinstance(val, str) and val.strip():
                        norm = DESC_KEY_ALIASES.get(key, key)
                        if norm in CONTEXT_FIELDS:
                            parts.append(f"{norm}={val.strip()}")
                if parts:
                    return ";".join(parts)
        except (json.JSONDecodeError, TypeError):
            pass

    # 2. Try key=value pairs (semicolon-separated)
    for pair in desc.split(";"):
        pair = pair.strip()
        if not pair or "=" not in pair:
            continue
        key, _, val = pair.partition("=")
        key = key.strip().lower().replace(" ", "_")
        norm = DESC_KEY_ALIASES.get(key, key)
        if norm in CONTEXT_FIELDS and val.strip():
            parts.append(f"{norm}={val.strip()}")

    if parts:
        return ";".join(parts)

    # 3. Plain text fallback: use whole description as threat if short and reasonable
    clean = re.sub(r"\s+", " ", desc).strip()
    if len(clean) <= 150 and re.search(r"[a-zA-Z0-9]", clean):
        return f"threat={clean}"

    return ""


# Alternative keys used by various TAXII/STIX feeds (map to our CONTEXT_FIELDS)
CONTEXT_KEY_ALIASES = {
    "threat": "threat",
    "malware_name": "threat",
    "malware": "threat",
    "name": "threat",
    "label": "threat",
    "category": "category",
    "mitre": "mitre",
    "geo": "geo",
    "country": "geo",
}


# Generic top-level name values we skip (Echo/Kilo use these for all items)
GENERIC_NAMES = {"hash", "url", "ip", "domain", "blocked", "blockedobject"}


def extract_context_from_indicator(obj):
    """
    Extract threat context from a STIX indicator object.
    Sources (in order): description key=val, x_* custom props, top-level name, labels.
    """
    ctx = {}

    # 1. Parse description field (key=val; or plain text)
    desc = obj.get("description", "")
    desc_parsed = parse_description_context(desc)
    if desc_parsed:
        for p in desc_parsed.split(";"):
            if "=" in p:
                k, _, v = p.partition("=")
                ctx[k.strip().lower()] = v.strip()

    # 2. Extract from x_* custom properties (e.g. x_threat, x_malware_name)
    for key, val in obj.items():
        if not key.startswith("x_") or not val or not isinstance(val, str):
            continue
        raw_key = key[2:].lower().replace("-", "_")
        norm_key = CONTEXT_KEY_ALIASES.get(raw_key)
        if norm_key and val.strip():
            if norm_key not in ctx or not ctx[norm_key]:
                ctx[norm_key] = val.strip()

    # 3. Top-level name (Echo: "Blocked", "BlockedObject", "Unwanted"; skip generic "Hash", "URL")
    if "threat" not in ctx or not ctx["threat"]:
        name = obj.get("name")
        if name and isinstance(name, str):
            n = name.strip()
            if n.lower() not in GENERIC_NAMES and len(n) <= 80:
                ctx["threat"] = n

    # 4. labels array: first non-misp label as category (e.g. "malicious-activity", "unwanted-activity")
    if "category" not in ctx or not ctx["category"]:
        for lbl in obj.get("labels") or []:
            if not isinstance(lbl, str) or lbl.startswith("misp:"):
                continue
            clean = lbl.strip()
            if clean and len(clean) <= 80:
                ctx["category"] = clean
                break

    # 5. Top-level confidence (0-100, STIX 2.1)
    conf = obj.get("confidence")
    if conf is not None:
        try:
            n = int(conf)
            if 0 <= n <= 100:
                ctx["confidence"] = str(n)
        except (TypeError, ValueError):
            pass

    return ";".join(f"{k}={v}" for k, v in sorted(ctx.items()) if v)


def fetch_taxii_objects(taxii_url, api_root, collection_id, username, password):
    """
    Fetch all STIX indicator objects from a TAXII 2.1 collection.
    Handles pagination automatically. Returns a list of STIX objects (dicts).
    """
    objects = []
    base = f"{taxii_url.rstrip('/')}/{api_root.strip('/')}/collections/{collection_id}/objects/"
    next_token = None
    page = 0

    while True:
        page += 1
        params = {"limit": TAXII_OBJECTS_LIMIT, "match[type]": "indicator"}
        if next_token:
            params["next"] = next_token
        url = f"{base}?{urlencode(params)}"

        status, body = taxii_get(url, username, password)

        if status is None:
            log(f"Error: TAXII fetch failed for {collection_id}: {body}")
            break

        if status != 200:
            log(f"Error: TAXII returned HTTP {status} for {collection_id}.")
            break

        try:
            data = json.loads(body)
        except json.JSONDecodeError as e:
            log(f"Error: Could not parse TAXII response for {collection_id}: {e}")
            break

        batch = data.get("objects", [])
        objects.extend(batch)

        if page == 1:
            log(f"  Fetching {collection_id} (page {page}, {len(batch)} objects)...")
        else:
            log(f"  Page {page}: {len(batch)} objects ({len(objects)} total)...")

        if not data.get("more", False):
            break

        next_token = data.get("next")
        if not next_token:
            break

    return objects


def process_taxii_indicators(stix_objects, skip_expired=True):
    """
    Process a list of STIX indicator objects into IOC buckets.
    Returns a dict: {ioc_type: [(value, context), ...]}.
    When skip_expired is True (default), skips indicators with valid_until in the past.
    """
    now = datetime.now(timezone.utc)
    buckets = {}
    skipped_expired = 0
    skipped_unknown = 0

    for obj in stix_objects:
        if obj.get("type") != "indicator":
            continue

        if skip_expired:
            valid_until = obj.get("valid_until")
            if valid_until:
                try:
                    until_dt = datetime.fromisoformat(valid_until.replace("Z", "+00:00"))
                    if until_dt < now:
                        skipped_expired += 1
                        continue
                except (ValueError, TypeError):
                    pass

        pattern = obj.get("pattern", "")
        parsed = parse_stix_pattern(pattern)
        if not parsed:
            skipped_unknown += 1
            continue

        ioc_type, value = parsed
        context = extract_context_from_indicator(obj)

        buckets.setdefault(ioc_type, []).append((value, context))

    if skipped_expired:
        log(f"  Skipped {skipped_expired} expired indicators.")
    if skipped_unknown:
        log(f"  Skipped {skipped_unknown} indicators with unrecognized patterns.")

    return buckets


def sanitize_cdb_value(val):
    """
    Sanitize a value for Wazuh CDB list format.
    Wazuh rejects: double quotes, newlines, and lines with more than 2 colons.
    """
    if not val or not isinstance(val, str):
        return ""
    # Replace newlines (CDB is one entry per line)
    s = val.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    # Remove double quotes (cause "Bad format" per Wazuh)
    s = s.replace('"', "")
    # Replace colons in value to avoid "more than 2 colons" error (key:value uses first colon)
    s = s.replace(":", "-")
    # Collapse multiple spaces
    s = " ".join(s.split())
    return s.strip()


def convert_taxii_iocs_to_cdb(ioc_type, iocs, whitelist_v4=None, whitelist_v6=None):
    """
    Convert a list of (value, context) IOC tuples to CDB content for a given type.
    Returns a sorted, deduplicated CDB string. Keys must be unique (CDB requirement).
    """
    whitelist = set()
    if whitelist_v4:
        whitelist |= whitelist_v4
    if whitelist_v6:
        whitelist |= whitelist_v6

    # Use dict to enforce unique keys (CDB requires unique keys per line)
    by_key = {}
    skipped = 0

    for value, context in iocs:
        if ioc_type == IOC_TYPE_IP:
            if value in whitelist:
                continue
            key = ip_to_cdb_key(value)
            if not key:
                skipped += 1
                continue
        elif ioc_type == IOC_TYPE_DOMAIN:
            key = value
        elif ioc_type == IOC_TYPE_URL:
            key = value.rstrip("/")
        elif ioc_type in (IOC_TYPE_MD5, IOC_TYPE_SHA1, IOC_TYPE_SHA256):
            key = value.lower()
        else:
            continue

        # Sanitize context for CDB format (no quotes, newlines, excess colons)
        safe_ctx = sanitize_cdb_value(context) if context else ""
        # Keep first context seen for this key, or merge if different
        if key not in by_key:
            by_key[key] = safe_ctx
        elif safe_ctx and by_key[key] != safe_ctx and safe_ctx not in by_key[key]:
            by_key[key] = by_key[key] + " | " + safe_ctx if by_key[key] else safe_ctx

    if skipped:
        log(f"  Skipped {skipped} entries (unsupported format).")

    lines = []
    for k in sorted(by_key.keys()):
        ctx = sanitize_cdb_value(by_key[k]) if by_key[k] else ""
        if ctx:
            lines.append(f"{k}:{ctx}")
        else:
            lines.append(f"{k}:")

    log(f"  {ioc_type}: {len(lines)} CDB entries generated.")
    return "\n".join(lines)


# ================================
# License Check
# ================================
def fetch_license_data(api_token):
    """
    Fetch license data from the API once and return a dict keyed by feed_type.
    Each value is a dict with 'licensed' (bool) and 'next_update' (str or None).
    Returns None if the API call fails (caller should treat all feeds as due).
    """
    url = f"{API_BASE}/licenses?api_token={api_token}"
    status, body = curl_get(url, timeout=60)

    if status is None:
        log(f"Warning: License check failed: {body}. Proceeding with all updates.")
        return None

    if status != 200:
        log(f"Warning: License API returned HTTP {status}. Proceeding with all updates.")
        return None

    try:
        data = json.loads(body)
    except json.JSONDecodeError as e:
        log(f"Warning: Could not parse license response: {e}. Proceeding with all updates.")
        return None

    result = {}
    for feed in data.get("feeds", []):
        ft = feed.get("feed_type")
        if ft:
            result[ft] = {
                "licensed": feed.get("licensed", False),
                "next_update": feed.get("next_update"),
            }

    return result


def should_update_feed(license_data, feed_type):
    """
    Check whether a feed should be updated based on cached license data.
    Returns True if the feed should be downloaded, False if it should be skipped.
    """
    if license_data is None:
        return True

    feed_info = license_data.get(feed_type)
    if not feed_info:
        log(f"Warning: Feed '{feed_type}' not found in license data. Skipping.")
        return False

    if not feed_info["licensed"]:
        log(f"Warning: Feed '{feed_type}' is not licensed. Skipping.")
        return False

    next_update = feed_info.get("next_update")
    if not next_update:
        return True

    try:
        next_dt = datetime.fromisoformat(next_update.replace("Z", "+00:00"))
        now_dt = datetime.now(timezone.utc)
        if now_dt < next_dt:
            log(f"Skipping {feed_type}: next update at {next_update}.")
            return False
    except (ValueError, TypeError):
        log(f"Warning: Could not parse next_update '{next_update}' for {feed_type}.")
        return True

    return True


# ================================
# Feed Download
# ================================
def download_feed(api_token, feed_type, ipv6_param=None):
    """
    Download a feed from the API in plain text format.
    Returns the response text, or None on failure.
    """
    url = f"{API_BASE}/api?api_token={api_token}&feed_type={feed_type}&type=text"
    if ipv6_param is not None:
        url += f"&ipv6={ipv6_param}"

    log(f"Downloading {feed_type} (ipv6={ipv6_param})...")
    status, body = curl_get(url, timeout=300)

    if status is None:
        log(f"Error: Download failed for {feed_type}: {body}")
        return None

    if status != 200:
        log(f"Error: API returned HTTP {status} for {feed_type}.")
        return None

    lines = [l for l in body.strip().splitlines() if l.strip()]
    log(f"Downloaded {feed_type}: {len(lines)} indicators.")
    return body


# ================================
# CDB Conversion
# ================================
def parse_whitelist(whitelist_str):
    """Parse a comma-separated whitelist string into a set."""
    if not whitelist_str:
        return set()
    return {ip.strip() for ip in whitelist_str.split(",") if ip.strip()}


def ip_to_cdb_key(line):
    """
    Convert a single IP or CIDR line to a Wazuh CDB key.
    Returns the CDB key string (without trailing newline), or None if the
    entry cannot be represented.

    Wazuh CDB address_match_key supports:
    - Full IPv4: 1.2.3.4:
    - /24 subnet: 1.2.3.:
    - /16 subnet: 1.2.:
    - /8 subnet:  1.:
    - Full IPv6:  2001:db8::1:  (exact match only)
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    if "/" in line:
        parts = line.rsplit("/", 1)
        ip_part = parts[0]
        try:
            mask = int(parts[1])
        except ValueError:
            return None

        if ":" in ip_part:
            # IPv6 CIDR -- only /128 (exact match) is representable
            if mask == 128:
                return ip_part + ":"
            return None
        else:
            # IPv4 CIDR
            if mask not in SUPPORTED_MASKS:
                return None
            octets = ip_part.split(".")
            if mask == 32:
                return ip_part + ":"
            elif mask == 24:
                return ".".join(octets[:3]) + ".:"
            elif mask == 16:
                return ".".join(octets[:2]) + ".:"
            elif mask == 8:
                return octets[0] + ".:"
    else:
        # Plain IP address
        return line + ":"

    return None


def domain_to_cdb_key(line):
    """Convert a domain line to a Wazuh CDB key."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    return line + ":"


def convert_ip_feed_to_cdb(feed_text, whitelist_v4, whitelist_v6):
    """
    Convert plain-text IP feed to CDB list content.
    Returns a sorted, deduplicated string of CDB entries.
    """
    whitelist = whitelist_v4 | whitelist_v6
    entries = set()
    skipped = 0

    for line in feed_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Check whitelist (match the raw IP/CIDR before conversion)
        if line in whitelist:
            continue

        key = ip_to_cdb_key(line)
        if key:
            entries.add(key)
        else:
            skipped += 1

    if skipped > 0:
        log(f"IP feed: skipped {skipped} entries with unsupported CIDR masks.")

    log(f"IP feed: {len(entries)} CDB entries generated.")
    return "\n".join(sorted(entries))


def convert_domain_feed_to_cdb(feed_text):
    """
    Convert plain-text domain feed to CDB list content.
    Returns a sorted, deduplicated string of CDB entries.
    """
    entries = set()

    for line in feed_text.splitlines():
        key = domain_to_cdb_key(line)
        if key:
            entries.add(key)

    log(f"Domain feed: {len(entries)} CDB entries generated.")
    return "\n".join(sorted(entries))


def url_to_cdb_keys(line):
    """
    Convert a phishing URL line to one or more Wazuh CDB keys.

    Stores two variants for maximum matching coverage:
      1. The URL as-is (with protocol) — matches proxy logs that log full URLs
      2. Without protocol prefix    — matches decoders that strip the scheme

    Trailing slashes are normalized (removed).
    Returns a list of CDB key strings, or an empty list if the line is invalid.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return []

    url = line.rstrip("/")
    keys = [url + ":"]

    for prefix in ("https://", "http://"):
        if url.lower().startswith(prefix):
            stripped = url[len(prefix):]
            if stripped:
                keys.append(stripped + ":")
            break

    return keys


def convert_url_feed_to_cdb(feed_text):
    """
    Convert plain-text phishing URL feed to CDB list content.
    Returns a sorted, deduplicated string of CDB entries.
    """
    entries = set()

    for line in feed_text.splitlines():
        for key in url_to_cdb_keys(line):
            entries.add(key)

    unique_urls = sum(1 for line in feed_text.splitlines() if line.strip() and not line.strip().startswith("#"))
    log(f"Phishing URL feed: {unique_urls} URLs -> {len(entries)} CDB entries generated.")
    return "\n".join(sorted(entries))


# ================================
# File Operations
# ================================
def file_hash(filepath):
    """Return the SHA-256 hash of a file, or None if it doesn't exist."""
    if not os.path.isfile(filepath):
        return None
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def content_hash(content):
    """Return the SHA-256 hash of a string."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def write_cdb_list(filepath, cdb_content):
    """
    Atomically write a CDB list file. Uses a temp file + rename to avoid
    partial writes. Returns True if the file content changed, False otherwise.
    """
    old_hash = file_hash(filepath)
    new_hash = content_hash(cdb_content)

    if old_hash == new_hash:
        log(f"No changes detected for {os.path.basename(filepath)}.")
        return False

    dirpath = os.path.dirname(filepath)
    fd, tmp_path = tempfile.mkstemp(dir=dirpath, prefix="qfeeds_tmp_")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(cdb_content)
            if cdb_content and not cdb_content.endswith("\n"):
                f.write("\n")
        os.rename(tmp_path, filepath)
    except Exception:
        os.unlink(tmp_path)
        raise

    # Set ownership to wazuh user
    try:
        import pwd
        try:
            wazuh_user = pwd.getpwnam("wazuh")
        except KeyError:
            wazuh_user = pwd.getpwnam("ossec")
        os.chown(filepath, wazuh_user.pw_uid, wazuh_user.pw_gid)
    except (KeyError, ImportError, OSError):
        pass

    os.chmod(filepath, 0o660)
    log(f"Updated {os.path.basename(filepath)}.")
    return True


# ================================
# Wazuh Integration
# ================================
def get_wazuh_version():
    """Return the Wazuh major version as an int, or None if it cannot be determined."""
    version_file = "/var/ossec/etc/ossec-init.conf"
    if os.path.isfile(version_file):
        try:
            with open(version_file, "r") as f:
                for line in f:
                    match = re.match(r'^VERSION="?v?(\d+)', line)
                    if match:
                        return int(match.group(1))
        except OSError:
            pass

    for ctl in ["/var/ossec/bin/wazuh-control", "/var/ossec/bin/ossec-control"]:
        if os.path.isfile(ctl):
            try:
                result = subprocess.run(
                    [ctl, "info"], capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.splitlines():
                    match = re.match(r'^WAZUH_VERSION="?v?(\d+)', line)
                    if match:
                        return int(match.group(1))
            except (OSError, subprocess.TimeoutExpired):
                continue

    return None


def compile_cdb_lists():
    """Run ossec-makelists to compile CDB lists into .cdb format."""
    if os.path.isfile(WAZUH_MAKELISTS):
        log("Compiling CDB lists...")
        try:
            result = subprocess.run(
                [WAZUH_MAKELISTS],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0:
                log("CDB lists compiled successfully.")
                return True
            else:
                log(f"Warning: ossec-makelists returned code {result.returncode}.")
                if result.stderr:
                    log(f"  stderr: {result.stderr.strip()}")
                return True
        except subprocess.TimeoutExpired:
            log("Error: ossec-makelists timed out.")
            return False
        except OSError as e:
            log(f"Error running ossec-makelists: {e}")
            return False

    major = get_wazuh_version()
    if major is not None and major >= 4:
        log(f"Wazuh {major}.x detected — skipping manual CDB compile (handled automatically on restart).")
        return True

    log(f"Warning: {WAZUH_MAKELISTS} not found and Wazuh version could not be determined. "
        "CDB lists will be compiled on manager restart.")
    return True


def restart_wazuh_manager():
    """Restart the Wazuh manager to load updated CDB lists."""
    log("Restarting Wazuh manager...")

    # Try systemctl first
    try:
        result = subprocess.run(
            ["systemctl", "restart", "wazuh-manager"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0:
            log("Wazuh manager restarted via systemctl.")
            return True
    except (OSError, subprocess.TimeoutExpired):
        pass

    # Fall back to wazuh-control
    for ctl in ["/var/ossec/bin/wazuh-control", "/var/ossec/bin/ossec-control"]:
        if os.path.isfile(ctl):
            try:
                result = subprocess.run(
                    [ctl, "restart"],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                if result.returncode == 0:
                    log(f"Wazuh manager restarted via {ctl}.")
                    return True
            except (OSError, subprocess.TimeoutExpired):
                continue

    log("Warning: Could not restart Wazuh manager. Please restart manually.")
    return False


# ================================
# Main — Standard Mode
# ================================
def main_standard(config):
    """Standard API mode: fetch feeds from Q-Feeds REST API."""
    api_token = config["API_TOKEN"]
    feed_ip_enabled = config.get("FEED_MALWARE_IP", "yes").lower() == "yes"
    feed_domains_enabled = config.get("FEED_MALWARE_DOMAINS", "yes").lower() == "yes"
    feed_phishing_urls_enabled = config.get("FEED_PHISHING_URLS", "no").lower() == "yes"
    ipv6_enabled = config.get("IPV6", "yes").lower() == "yes"

    whitelist_v4 = parse_whitelist(config.get("WHITELIST_V4", ""))
    whitelist_v6 = parse_whitelist(config.get("WHITELIST_V6", ""))

    force_update = os.environ.get("QFEEDS_FORCE_UPDATE") == "1"

    if not feed_ip_enabled and not feed_domains_enabled and not feed_phishing_urls_enabled:
        log("No feeds enabled. Nothing to do.")
        return

    os.makedirs(WAZUH_LISTS_DIR, exist_ok=True)

    license_data = None if force_update else fetch_license_data(api_token)

    any_changed = False

    # --- Malware IP Feed ---
    if feed_ip_enabled:
        if force_update or should_update_feed(license_data, FEED_TYPE_IP):
            combined_text = ""

            ipv4_text = download_feed(api_token, FEED_TYPE_IP, ipv6_param="0")
            if ipv4_text:
                combined_text += ipv4_text

            if ipv6_enabled:
                ipv6_text = download_feed(api_token, FEED_TYPE_IP, ipv6_param="only")
                if ipv6_text:
                    if combined_text and not combined_text.endswith("\n"):
                        combined_text += "\n"
                    combined_text += ipv6_text

            if combined_text:
                cdb_content = convert_ip_feed_to_cdb(combined_text, whitelist_v4, whitelist_v6)
                if write_cdb_list(CDB_FILE_IP, cdb_content):
                    any_changed = True
            else:
                log("Warning: No IP feed data received. Keeping existing CDB list.")

    # --- Malware Domains Feed ---
    if feed_domains_enabled:
        if force_update or should_update_feed(license_data, FEED_TYPE_DOMAINS):
            domain_text = download_feed(api_token, FEED_TYPE_DOMAINS)
            if domain_text:
                cdb_content = convert_domain_feed_to_cdb(domain_text)
                if write_cdb_list(CDB_FILE_DOMAINS, cdb_content):
                    any_changed = True
            else:
                log("Warning: No domain feed data received. Keeping existing CDB list.")

    # --- Phishing URLs Feed ---
    if feed_phishing_urls_enabled:
        if force_update or should_update_feed(license_data, FEED_TYPE_PHISHING_URLS):
            url_text = download_feed(api_token, FEED_TYPE_PHISHING_URLS)
            if url_text:
                cdb_content = convert_url_feed_to_cdb(url_text)
                if write_cdb_list(CDB_FILE_PHISHING_URLS, cdb_content):
                    any_changed = True
            else:
                log("Warning: No phishing URL feed data received. Keeping existing CDB list.")

    # --- Compile and Restart ---
    if any_changed:
        compile_cdb_lists()
        restart_wazuh_manager()
        log("Update completed: CDB lists updated and Wazuh restarted.")
    else:
        log("Update completed: no changes detected.")


# ================================
# Main — TAXII Mode
# ================================
def main_taxii(config):
    """TAXII 2.1 mode: fetch STIX indicators from Q-Feeds TAXII server."""
    taxii_url = config["TAXII_URL"].rstrip("/")
    api_root = config["TAXII_API_ROOT"].strip("/")
    username = config["TAXII_USERNAME"]
    password = config["TAXII_PASSWORD"]
    collections = [c.strip() for c in config["TAXII_COLLECTIONS"].split(",") if c.strip()]

    whitelist_v4 = parse_whitelist(config.get("WHITELIST_V4", ""))
    whitelist_v6 = parse_whitelist(config.get("WHITELIST_V6", ""))
    skip_expired = config.get("TAXII_SKIP_EXPIRED", "yes").lower() == "yes"

    if not collections:
        log("No TAXII collections configured. Nothing to do.")
        return

    os.makedirs(WAZUH_LISTS_DIR, exist_ok=True)

    log(f"TAXII server: {taxii_url}/{api_root}")
    log(f"Collections: {', '.join(collections)}")

    all_buckets = {}

    for collection_id in collections:
        log(f"Fetching collection: {collection_id}")
        stix_objects = fetch_taxii_objects(taxii_url, api_root, collection_id, username, password)

        if not stix_objects:
            log(f"  No objects received for {collection_id}.")
            continue

        log(f"  Received {len(stix_objects)} objects from {collection_id}.")
        buckets = process_taxii_indicators(stix_objects, skip_expired=skip_expired)

        for ioc_type, iocs in buckets.items():
            all_buckets.setdefault(ioc_type, []).extend(iocs)

    if not all_buckets:
        log("No indicators extracted from any collection.")
        # Ensure placeholder CDB files exist so Wazuh does not complain about missing lists
        _ensure_placeholder_cdb_files()
        log("Update completed: no changes detected.")
        return

    any_changed = False

    for ioc_type, iocs in all_buckets.items():
        cdb_file = CDB_FILE_BY_IOC_TYPE.get(ioc_type)
        if not cdb_file:
            continue

        cdb_content = convert_taxii_iocs_to_cdb(
            ioc_type, iocs, whitelist_v4, whitelist_v6
        )
        if write_cdb_list(cdb_file, cdb_content):
            any_changed = True

    if any_changed:
        compile_cdb_lists()
        restart_wazuh_manager()
        log("Update completed: CDB lists updated and Wazuh restarted.")
    else:
        log("Update completed: no changes detected.")


# ================================
# Main — Dispatcher
# ================================
def main():
    global LOG_FILE

    config = read_config()

    if config.get("LOG_FILE"):
        LOG_FILE = config["LOG_FILE"]

    mode = config.get("INTEGRATION_MODE", "standard").lower()

    log("=" * 60)
    log(f"Q-Feeds Wazuh updater starting (mode: {mode}).")

    if mode == "taxii":
        main_taxii(config)
    else:
        main_standard(config)

    log("=" * 60)


if __name__ == "__main__":
    # Acquire lock to prevent concurrent runs
    lock_fd = None
    try:
        lock_fd = open(LOCK_FILE, "w")
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print("Another instance of the Q-Feeds Wazuh updater is already running.")
        sys.exit(0)

    try:
        main()
    except Exception as e:
        log(f"Fatal error: {e}")
        sys.exit(1)
    finally:
        if lock_fd:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            lock_fd.close()
