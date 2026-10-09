"""
OT PCAP Analyzer - Utilities
============================
Helper functions and logging configuration.
"""

import datetime as dt
import functools
import re
import hashlib
import ipaddress
import logging
import os
from collections import Counter
from typing import Optional

import numpy as np



# =============================================================================
# LOGGING
# =============================================================================

logger = logging.getLogger("OT_PCAP_ANALYZER")


def setup_logging(level: str = "INFO") -> None:
    """Setup logging configuration"""
    log_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )


# =============================================================================
# REGEX CACHE
# =============================================================================

@functools.lru_cache(maxsize=None)
def cached_regex(pattern: str, flags: int = 0) -> "re.Pattern":
    """Compile a regex once and reuse it.

    The detection rule tables hold well over 1,000 patterns, more than the 512
    entries of Python's internal ``re`` cache, so ``re.search(pattern, ...)``
    in a loop recompiled patterns for every HTTP request (previously the
    single largest CPU cost of an analysis).
    """
    return re.compile(pattern, flags)


# =============================================================================
# IP/MAC UTILITIES
# =============================================================================

def ip4_to_str(b: bytes) -> str:
    """Convert 4 bytes to IPv4 string"""
    return ".".join(map(str, b))


def ip6_to_str(b: bytes) -> str:
    """Convert 16 bytes to IPv6 string"""
    try:
        return str(ipaddress.IPv6Address(b))
    except Exception:
        return ":".join(f"{b[i]:02x}{b[i+1]:02x}" for i in range(0, 16, 2))


def is_private_ip(ip: str) -> bool:
    """Check if IP address is private"""
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


def mac_to_str(b: bytes) -> str:
    """Convert 6 bytes to MAC address string"""
    return ":".join(f"{byte:02X}" for byte in b)


def get_vendor(mac: str) -> str:
    """Get vendor name from MAC address (longest-prefix match on OT_MAC_OUI)."""
    from .constants import get_vendor as _lookup
    return _lookup(mac)


# =============================================================================
# TIME UTILITIES
# =============================================================================

def timestamp() -> str:
    """Generate timestamp string for filenames"""
    return dt.datetime.now().strftime("%Y%m%d_%H%M%S")


def utc_str(ts: float) -> str:
    """Convert Unix timestamp to UTC string"""
    try:
        if ts is None or ts == 0 or not isinstance(ts, (int, float)) or ts <= 0:
            return ""

        # Normalize timestamp to avoid "year out of range" errors
        # Valid range: 0 to 253402300799 (year 9999)
        MAX_VALID_TIMESTAMP = 253402300799

        # Auto-detect and correct millisecond/microsecond timestamps
        if ts > MAX_VALID_TIMESTAMP:
            if ts > 1e12:  # Likely milliseconds
                ts = ts / 1000.0
            if ts > MAX_VALID_TIMESTAMP and ts > 1e15:  # Likely microseconds
                ts = ts / 1000000.0

        # Final validation
        if ts < 0 or ts > MAX_VALID_TIMESTAMP:
            return ""

        dt_obj = dt.datetime.fromtimestamp(ts, dt.timezone.utc)
        if not (1970 <= dt_obj.year <= 2100):
            return ""
        return dt_obj.isoformat(sep=" ")
    except Exception:
        return ""


# =============================================================================
# FILE UTILITIES
# =============================================================================

def ensure_dir(path: str) -> str:
    """Ensure directory exists, create if not"""
    os.makedirs(path, exist_ok=True)
    return path


def sha256_file(path: str, chunk: int = 1024*1024) -> str:
    """Calculate SHA256 hash of a file"""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk_data := f.read(chunk):
            h.update(chunk_data)
    return h.hexdigest()


def format_bytes(n: int) -> str:
    """Format byte count to human readable string"""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024.0 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} {unit}"
        n /= 1024.0
    return f"{n} B"


# =============================================================================
# DATA ANALYSIS UTILITIES
# =============================================================================

def entropy(data: bytes) -> float:
    """Calculate Shannon entropy of data"""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c/length) * np.log2(c/length) for c in counts.values())


# =============================================================================
# TIMESTAMP NORMALIZATION
# =============================================================================

# Maximum valid Unix timestamp (year 9999-12-31)
MAX_VALID_TIMESTAMP = 253402300799

def normalize_timestamp(ts: float) -> Optional[float]:
    """
    Normalize timestamp to valid Unix seconds format.
    Auto-corrects millisecond/microsecond timestamps.

    Args:
        ts: Raw timestamp value

    Returns:
        Normalized timestamp in seconds, or None if invalid

    Examples:
        >>> normalize_timestamp(1595363772.733)  # Valid seconds
        1595363772.733
        >>> normalize_timestamp(1595363772733.227)  # Milliseconds
        1595363772.733
        >>> normalize_timestamp(1595363772733227.0)  # Microseconds
        1595363772.733
    """
    if ts is None or ts < 0:
        return None

    # Already valid
    if ts <= MAX_VALID_TIMESTAMP:
        return ts

    original_ts = ts

    # Auto-detect and correct timestamp format
    if ts > 1e12:  # Likely milliseconds (> year 2286 in ms)
        ts = ts / 1000.0

    # Re-validate after correction
    if ts > MAX_VALID_TIMESTAMP:
        # Check original value for microsecond detection (not modified ts)
        if original_ts > 1e15:  # Likely microseconds
            ts = original_ts / 1000000.0
        else:
            # Still invalid after correction
            return None

    # Final validation
    if ts < 0 or ts > MAX_VALID_TIMESTAMP:
        return None

    return ts


def is_internal_ip(ip: str) -> bool:
    """True for private, loopback, link-local, reserved or unparsable addresses.

    Such addresses are never sent to third-party services: it would leak plant
    topology and they have no public reputation anyway.
    """
    import ipaddress
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return True
    return not addr.is_global


# Cells starting with these characters are interpreted as formulas by Excel /
# LibreOffice. Captured traffic is attacker-controlled (URLs, user agents, DNS
# names...), so such values are prefixed with a quote to stay plain text
# (CSV/formula injection, OWASP).
_PLAIN_NUMBER_RE = re.compile(r"^[+-]?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?$")
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\uff1d", "\uff0b", "\uff0d", "\uff20")


def neutralize_formula(value):
    """Return value unchanged unless it is a string a spreadsheet would evaluate."""
    if isinstance(value, str) and len(value) > 1 and value.startswith(_FORMULA_PREFIXES):
        # Plain signed numbers ("-12.5") are harmless and stay as they are.
        if _PLAIN_NUMBER_RE.match(value):
            return value
        return "'" + value
    return value
