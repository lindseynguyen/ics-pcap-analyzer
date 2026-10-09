"""
OT PCAP Analyzer - Report export helpers
========================================
Excel export sanitising helpers.
"""

import re

from .utils import neutralize_formula

import pandas as pd


# =============================================================================
# EXCEL CELL SANITISING
# =============================================================================

_EXCEL_ILLEGAL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_EXCEL_MAX_CELL = 32_000


def _excel_safe_value(value):
    """Make a cell value writable by openpyxl (no control chars, no containers, max length)."""
    if isinstance(value, (dict, list, tuple, set)):
        value = str(value)
    elif isinstance(value, (bytes, bytearray)):
        value = bytes(value).hex()
    if isinstance(value, str):
        value = _EXCEL_ILLEGAL_CHARS.sub("", value)
        if len(value) > _EXCEL_MAX_CELL:
            value = value[:_EXCEL_MAX_CELL] + "...[truncated]"
        value = neutralize_formula(value)
    return value


def _excel_safe(df: "pd.DataFrame") -> "pd.DataFrame":
    """Sanitize a DataFrame so payload previews with binary data cannot break the export."""
    return df.apply(lambda col: col.map(_excel_safe_value))
