# =============================================================================
# ENHANCED HTTP STREAM DECODER - Advanced WebShell Detection
# =============================================================================

import re
import hashlib
import base64
import binascii
import zlib
import logging
from typing import List
import numpy as np


# Temporary logger for EnhancedHTTPStreamDecoder (before main imports)
logger = logging.getLogger("OT_PCAP_ANALYZER")


def entropy(data: bytes) -> float:
    """Calculate Shannon entropy of bytes data"""
    if not data:
        return 0.0
    from collections import Counter
    cnt = Counter(data)
    length = len(data)
    probs = [count / length for count in cnt.values()]
    return -sum(p * np.log2(p) for p in probs if p > 0)


class EnhancedHTTPStreamDecoder:
    """
    Advanced HTTP Stream Decoder with comprehensive WebShell detection.
    Features:
    - Deep payload inspection (base64, hex, gzip, multi-layer)
    - Behavioral analysis (eval chains, obfuscation patterns)
    - File upload detection (multipart forms, binary uploads)
    - Shell command detection (cmd.exe, powershell, bash)
    - Payload fingerprinting (known webshell signatures)
    """
    KNOWN_WEBSHELLS = {
        "b374k": {"patterns": [b"b374k", b"Jayalah Indonesiaku"], "description": "b374k Shell - Popular PHP Shell"},
        "c99": {"patterns": [b"c99shell", b"c99sh"], "description": "C99 Shell - Classic PHP Shell"},
        "r57": {"patterns": [b"r57shell", b"r57 Shell"], "description": "R57 Shell"},
        "wso": {"patterns": [b"WSO ", b"Web Shell by oRb"], "description": "WSO Shell"},
        "china_chopper": {"patterns": [b"<?php @eval($_POST", b"<?@eval($_POST"], "description": "China Chopper - APT Webshell"},
        "weevely": {"patterns": [b"weevely", b"str_rot13", b"base64_decode"], "description": "Weevely - Stealth PHP Shell"},
    }
    PHP_DANGEROUS_FUNCTIONS = {
        b"eval(": "CRITICAL", b"assert(": "CRITICAL", b"system(": "CRITICAL", b"exec(": "CRITICAL", b"passthru(": "CRITICAL", b"shell_exec(": "CRITICAL", b"popen(": "HIGH", b"proc_open(": "HIGH", b"pcntl_exec(": "HIGH", b"`": "HIGH", b"create_function(": "CRITICAL", b"call_user_func(": "HIGH", b"call_user_func_array(": "HIGH", b"preg_replace(/.*e": "CRITICAL", b"file_put_contents(": "MEDIUM", b"fwrite(": "MEDIUM", b"fputs(": "MEDIUM", b"move_uploaded_file(": "MEDIUM", b"base64_decode(": "MEDIUM", b"gzinflate(": "MEDIUM", b"gzuncompress(": "MEDIUM", b"str_rot13(": "MEDIUM",
    }
    SHELL_COMMANDS = {
        b"cmd.exe": "CRITICAL", b"cmd /c": "CRITICAL", b"powershell.exe": "CRITICAL", b"powershell -": "CRITICAL", b"powershell.exe -enc": "CRITICAL", b"powershell -encodedcommand": "CRITICAL", b"wscript.exe": "HIGH", b"cscript.exe": "HIGH", b"mshta.exe": "HIGH", b"/bin/bash": "CRITICAL", b"/bin/sh": "CRITICAL", b"bash -c": "CRITICAL", b"sh -c": "CRITICAL", b"/usr/bin/perl": "HIGH", b"python -c": "HIGH", b"ruby -e": "HIGH", b"nc -": "HIGH", b"ncat": "HIGH", b"whoami": "MEDIUM", b"uname -a": "MEDIUM", b"cat /etc/passwd": "HIGH", b"cat /etc/shadow": "CRITICAL", b"net user": "MEDIUM", b"net localgroup": "MEDIUM", b"ipconfig": "LOW", b"ifconfig": "LOW",
    }
    UPLOAD_INDICATORS = {
        b"Content-Disposition: form-data": "MEDIUM", b"filename=": "MEDIUM", b"Content-Type: application/octet-stream": "HIGH", b"Content-Type: application/x-php": "CRITICAL", b"Content-Type: application/x-httpd-php": "CRITICAL",
    }
    BINARY_SIGNATURES = {
        b"\x7fELF": "ELF_BINARY", b"MZ": "PE_BINARY", b"\x50\x4b\x03\x04": "ZIP_ARCHIVE", b"\x1f\x8b\x08": "GZIP_COMPRESSED",
    }
    def __init__(self, max_cache_size: int = 10000):
        """
        Initialize HTTP stream decoder with threat detection.

        Args:
            max_cache_size: Maximum number of payloads to cache (default: 10,000)
        """
        self.detection_cache = {}
        self.cache_access_order = []  # Track access order for LRU eviction
        self.max_cache_size = max_cache_size
    def analyze_http_payload(self, payload: bytes, uri: str = "", method: str = "", headers: dict = None) -> dict:
        if not payload:
            return {"threat_level": "NONE", "risk_score": 0}
        payload_hash = hashlib.sha256(payload).hexdigest()

        # Check cache (LRU access)
        if payload_hash in self.detection_cache:
            # Move to end (most recently used)
            if payload_hash in self.cache_access_order:
                self.cache_access_order.remove(payload_hash)
            self.cache_access_order.append(payload_hash)
            return self.detection_cache[payload_hash]
        result = {"threat_level": "NONE", "detected_threats": [], "webshell_indicators": [], "shell_commands": [], "php_dangerous_funcs": [], "obfuscation_layers": 0, "payload_hash": payload_hash, "risk_score": 0, "file_upload_detected": False, "binary_detected": False, "decode_chain": [],}
        self._detect_known_webshells(payload, result)
        decoded_layers = self._decode_multilayer(payload)
        result["obfuscation_layers"] = len(decoded_layers)
        result["decode_chain"] = [d["encoding"] for d in decoded_layers]
        all_layers = [payload] + [d["decoded"] for d in decoded_layers]
        for layer_idx, layer_data in enumerate(all_layers):
            self._detect_php_functions(layer_data, result)
            self._detect_shell_commands(layer_data, result)
            if layer_idx > 0:
                self._detect_obfuscation_patterns(layer_data, result)
        self._detect_file_uploads(payload, headers or {}, result)
        self._detect_binary_content(payload, result)
        self._behavioral_analysis(payload, uri, method, result)
        result["risk_score"] = self._calculate_risk_score(result)
        result["threat_level"] = self._determine_threat_level(result["risk_score"])

        # Add to cache with LRU eviction
        if len(self.detection_cache) >= self.max_cache_size:
            # Evict oldest entry (LRU)
            if self.cache_access_order:
                oldest = self.cache_access_order.pop(0)
                self.detection_cache.pop(oldest, None)

        self.detection_cache[payload_hash] = result
        self.cache_access_order.append(payload_hash)

        return result
    def _detect_known_webshells(self, payload: bytes, result: dict):
        payload_lower = payload.lower()
        for shell_name, shell_info in self.KNOWN_WEBSHELLS.items():
            for pattern in shell_info["patterns"]:
                if pattern.lower() in payload_lower:
                    result["webshell_indicators"].append({"name": shell_name, "description": shell_info["description"], "pattern": pattern.decode('utf-8', errors='replace')})
                    result["detected_threats"].append(f"KNOWN_WEBSHELL_{shell_name.upper()}")
    def _decode_multilayer(self, payload: bytes, max_layers: int = 5) -> List[dict]:
        layers = []
        current = payload
        for layer in range(max_layers):
            # Order matters: every hex string is also valid base64, so the
            # stricter encodings (gzip magic, hex alphabet) are tried first.
            decoded, encoding = self._try_gzip(current)
            if decoded and decoded != current:
                layers.append({"layer": layer + 1, "encoding": "gzip", "decoded": decoded, "size_before": len(current), "size_after": len(decoded)})
                current = decoded
                continue
            decoded, encoding = self._try_hex(current)
            if decoded and decoded != current:
                layers.append({"layer": layer + 1, "encoding": "hex", "decoded": decoded, "size_before": len(current), "size_after": len(decoded)})
                current = decoded
                continue
            decoded, encoding = self._try_base64(current)
            if decoded and decoded != current:
                layers.append({"layer": layer + 1, "encoding": "base64", "decoded": decoded, "size_before": len(current), "size_after": len(decoded)})
                current = decoded
                continue
            decoded, encoding = self._try_urldecode(current)
            if decoded and decoded != current:
                layers.append({"layer": layer + 1, "encoding": "url", "decoded": decoded, "size_before": len(current), "size_after": len(decoded)})
                current = decoded
                continue
            break
        return layers
    def _try_base64(self, data: bytes):
        try:
            if len(data) < 20:
                return None, ""
            cleaned = data.replace(b'\n', b'').replace(b'\r', b'').replace(b' ', b'')
            missing_padding = len(cleaned) % 4
            if missing_padding:
                cleaned += b'=' * (4 - missing_padding)
            decoded = base64.b64decode(cleaned, validate=True)
            if len(decoded) > 0 and entropy(decoded) > 1.0:
                return decoded, "base64"
        except (ValueError, binascii.Error, TypeError) as e:
            logger.debug(f"Base64 decode error: {e}")
        return None, ""
    def _try_gzip(self, data: bytes):
        try:
            if data[:2] == b'\x1f\x8b':
                decoded = zlib.decompress(data, 16 + zlib.MAX_WBITS)
                return decoded, "gzip"
        except (zlib.error, ValueError) as e:
            logger.debug(f"Gzip decompress error: {e}")
        return None, ""
    def _try_hex(self, data: bytes):
        try:
            text = data.decode('ascii', errors='ignore')
            text = text.replace('0x', '').replace('\\x', '').replace(' ', '')
            if len(text) > 20 and all(c in '0123456789abcdefABCDEF' for c in text):
                decoded = binascii.unhexlify(text)
                return decoded, "hex"
        except (binascii.Error, ValueError, UnicodeDecodeError) as e:
            logger.debug(f"Hex decode error: {e}")
        return None, ""
    def _try_urldecode(self, data: bytes):
        try:
            from urllib.parse import unquote
            text = data.decode('utf-8', errors='replace')
            if '%' in text and sum(1 for c in text if c == '%') > 3:
                decoded = unquote(text).encode('utf-8')
                if decoded != data:
                    return decoded, "url"
        except (UnicodeDecodeError, UnicodeEncodeError, ValueError) as e:
            logger.debug(f"URL decode error: {e}")
        return None, ""
    def _detect_php_functions(self, payload: bytes, result: dict):
        for func, severity in self.PHP_DANGEROUS_FUNCTIONS.items():
            if func in payload:
                func_name = func.decode('utf-8', errors='replace').strip('(')
                if func_name not in [d["function"] for d in result["php_dangerous_funcs"]]:
                    result["php_dangerous_funcs"].append({"function": func_name, "severity": severity})
                    result["detected_threats"].append(f"PHP_{func_name.upper()}")
    def _detect_shell_commands(self, payload: bytes, result: dict):
        payload_lower = payload.lower()
        for cmd, severity in self.SHELL_COMMANDS.items():
            if cmd in payload_lower:
                cmd_name = cmd.decode('utf-8', errors='replace')
                if cmd_name not in [d["command"] for d in result["shell_commands"]]:
                    result["shell_commands"].append({"command": cmd_name, "severity": severity})
                    result["detected_threats"].append(f"SHELL_CMD_{cmd_name.replace('/', '_').replace('.', '_').upper()}")
    def _detect_obfuscation_patterns(self, payload: bytes, result: dict):
        if re.search(rb'\$\$[a-zA-Z_]', payload):
            result["detected_threats"].append("OBFUSCATION_VARIABLE_VARIABLE")
        if re.search(rb'chr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(\s*\d+\s*\)', payload):
            result["detected_threats"].append("OBFUSCATION_CHR_CONCAT")
        if re.search(rb'\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}', payload):
            result["detected_threats"].append("OBFUSCATION_HEX_STRING")
        if re.search(rb'eval\s*\(\s*[\$a-zA-Z_][\w$]*\s*\(', payload):
            result["detected_threats"].append("OBFUSCATION_EVAL_CHAIN")
    def _detect_file_uploads(self, payload: bytes, headers: dict, result: dict):
        content_type = headers.get('content-type', '').lower()
        if 'multipart/form-data' in content_type:
            result["file_upload_detected"] = True
            dangerous_exts = [b'.php', b'.jsp', b'.aspx', b'.asp', b'.exe', b'.sh']
            for ext in dangerous_exts:
                if ext in payload.lower():
                    result["detected_threats"].append(f"FILE_UPLOAD_DANGEROUS_EXT_{ext.decode()[1:].upper()}")
            if re.search(rb'filename=".*\.(jpg|png|gif)\.(php|jsp|aspx)"', payload, re.IGNORECASE):
                result["detected_threats"].append("FILE_UPLOAD_DOUBLE_EXTENSION")
            if b'\x00' in payload and re.search(rb'filename=', payload):
                result["detected_threats"].append("FILE_UPLOAD_NULL_BYTE")
    def _detect_binary_content(self, payload: bytes, result: dict):
        for sig, bin_type in self.BINARY_SIGNATURES.items():
            if payload.startswith(sig):
                result["binary_detected"] = True
                result["detected_threats"].append(f"BINARY_{bin_type}")
    def _behavioral_analysis(self, payload: bytes, uri: str, method: str, result: dict):
        if method == "POST":
            suspicious_paths = ['/upload', '/admin', '/shell', '/cmd', '/exec']
            for path in suspicious_paths:
                if path in uri.lower():
                    result["detected_threats"].append(f"SUSPICIOUS_POST_PATH_{path[1:].upper()}")
        if method == "POST" and len(payload) > 1000000:
            result["detected_threats"].append("LARGE_POST_BODY")
        payload_entropy = entropy(payload)
        if payload_entropy > 7.5 and len(payload) > 100:
            result["detected_threats"].append("HIGH_ENTROPY_PAYLOAD")
    def _calculate_risk_score(self, result: dict) -> int:
        score = 0
        if result["webshell_indicators"]:
            score += 80
        for func in result["php_dangerous_funcs"]:
            if func["severity"] == "CRITICAL":
                score += 30
            elif func["severity"] == "HIGH":
                score += 20
            elif func["severity"] == "MEDIUM":
                score += 10
        for cmd in result["shell_commands"]:
            if cmd["severity"] == "CRITICAL":
                score += 40
            elif cmd["severity"] == "HIGH":
                score += 25
            elif cmd["severity"] == "MEDIUM":
                score += 15
            elif cmd["severity"] == "LOW":
                score += 5
        score += result["obfuscation_layers"] * 15
        if result["file_upload_detected"]:
            score += 20
        if result["binary_detected"]:
            score += 25
        score += len(result["detected_threats"]) * 5
        return min(score, 100)
    def _determine_threat_level(self, risk_score: int) -> str:
        if risk_score >= 80:
            return "CRITICAL"
        elif risk_score >= 60:
            return "HIGH"
        elif risk_score >= 40:
            return "MEDIUM"
        elif risk_score >= 20:
            return "LOW"
        else:
            return "NONE"
"""
OT PCAP Analyzer - Parsers
==========================
PCAP file readers and OT protocol parsers.
"""

import struct
from collections import defaultdict
from typing import Iterator, Dict, Tuple, Optional

from .constants import (
    OTProtocol, MODBUS_FUNCTIONS, S7_FUNCTIONS,
    DNP3_FUNCTIONS, CIP_SERVICES, IEC104_ASDU_TYPES,
    DNS_QUERY_TYPES, HTTP_METHODS, HTTP_SUSPICIOUS_PATTERNS,
    DNS_TUNNELING_INDICATORS
)
from .models import PacketRecord, OTEvent

from .utils import cached_regex, entropy, logger, ip4_to_str, mac_to_str

# === Enhanced HTTP/WebShell Analysis ===
from .http_stream_analysis import (
    EnhancedHTTPStreamAnalyzer,
    analyze_http_stream_enhanced,
    get_webshell_report
)


def _safe_int(value, default: int = 0) -> int:
    """Parse an integer header value, returning default on malformed input."""
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


# =============================================================================
# PCAP READERS
# =============================================================================

def iter_pcap(path: str, max_packet_size: int = 262144) -> Iterator[PacketRecord]:
    """
    Iterate over packets in a PCAP file.

    Args:
        path: Path to PCAP file
        max_packet_size: Maximum packet size to accept (default: 256KB, tcpdump default snaplen)

    Yields:
        PacketRecord objects

    Raises:
        ValueError: If packet size exceeds limit
    """
    with open(path, "rb") as f:
        header = f.read(24)
        if len(header) < 24:
            raise ValueError("File too short")

        magic_le = struct.unpack("<I", header[:4])[0]
        magic_be = struct.unpack(">I", header[:4])[0]

        if magic_le == 0xA1B2C3D4:
            endian, scale = "<", 1_000_000.0
        elif magic_le == 0xA1B23C4D:
            endian, scale = "<", 1_000_000_000.0
        elif magic_be == 0xA1B2C3D4:
            endian, scale = ">", 1_000_000.0
        elif magic_be == 0xA1B23C4D:
            endian, scale = ">", 1_000_000_000.0
        elif magic_le == 0xD4C3B2A1:
            endian, scale = ">", 1_000_000.0
        elif magic_le == 0x4D3CB2A1:
            endian, scale = ">", 1_000_000_000.0
        else:
            raise ValueError("Not a valid PCAP file")

        linktype = struct.unpack(f"{endian}I", header[20:24])[0]

        while True:
            pkt_hdr = f.read(16)
            if len(pkt_hdr) < 16:
                break
            ts_sec, ts_us, cap_len, _ = struct.unpack(f"{endian}IIII", pkt_hdr)
            ts = float(ts_sec) + float(ts_us) / scale

            # Validate packet size
            if cap_len > max_packet_size:
                logger.warning(f"Packet size {cap_len} exceeds limit {max_packet_size}, skipping")
                f.read(cap_len)  # Skip the oversized packet
                continue

            pkt = f.read(cap_len)
            if len(pkt) < cap_len:
                break
            yield PacketRecord(ts=ts, data=pkt, linktype=linktype)


def iter_pcapng(path: str, max_packet_size: int = 262144) -> Iterator[PacketRecord]:
    """
    Iterate over packets in a PCAPNG file.

    Args:
        path: Path to PCAPNG file
        max_packet_size: Maximum packet size to accept (default: 256KB)

    Yields:
        PacketRecord objects
    """
    SHB, IDB, SPB, EPB, OPB = 0x0A0D0D0A, 0x00000001, 0x00000003, 0x00000006, 0x00000002
    interfaces: Dict[int, Tuple[int, int, int]] = {}  # iid -> (linktype, tsresol, snaplen)
    endian = "<"

    with open(path, "rb") as f:
        while True:
            block_hdr = f.read(8)
            if len(block_hdr) < 8:
                break
            if block_hdr[:4] == b"\x0a\x0d\x0d\x0a":
                # Section Header Block: byte-order magic decides endianness of the section
                bom = f.read(4)
                if len(bom) < 4:
                    break
                if bom == b"\x4d\x3c\x2b\x1a":
                    endian = "<"
                elif bom == b"\x1a\x2b\x3c\x4d":
                    endian = ">"
                else:
                    raise ValueError("Invalid PCAPNG byte-order magic")
                blen = struct.unpack(f"{endian}I", block_hdr[4:8])[0]
                if blen < 28:
                    break
                f.read(blen - 12)  # rest of SHB body + trailing length
                interfaces.clear()
                continue

            btype, blen = struct.unpack(f"{endian}II", block_hdr)
            if blen < 12 or blen % 4:
                break
            body = f.read(blen - 12)
            trailer = f.read(4)
            if len(body) < blen - 12 or len(trailer) < 4:
                break  # truncated file

            if btype == IDB:
                if len(body) >= 8:
                    lt = struct.unpack(f"{endian}H", body[0:2])[0]
                    snaplen = struct.unpack(f"{endian}I", body[4:8])[0]
                    iid = len(interfaces)
                    # Parse IDB options to find if_tsresol (option code 9)
                    tsresol = 6  # Default: microseconds (10^6)
                    opt_offset = 8
                    while opt_offset + 4 <= len(body):
                        opt_code, opt_len = struct.unpack(f"{endian}HH", body[opt_offset:opt_offset+4])
                        opt_offset += 4
                        if opt_code == 0:  # opt_endofopt
                            break
                        if opt_code == 9 and opt_len >= 1 and opt_offset < len(body):  # if_tsresol
                            tsresol = body[opt_offset]
                        opt_offset += (opt_len + 3) & ~3  # pad to 4-byte boundary
                    interfaces[iid] = (lt, tsresol, snaplen)
            elif btype in (EPB, OPB):
                if len(body) >= 20:
                    if btype == EPB:
                        iid = struct.unpack(f"{endian}I", body[0:4])[0]
                    else:  # obsolete Packet Block: 2-byte interface id + 2-byte drops count
                        iid = struct.unpack(f"{endian}H", body[0:2])[0]
                    if iid not in interfaces:
                        continue
                    ts_hi, ts_lo = struct.unpack(f"{endian}II", body[4:12])
                    cap_len = struct.unpack(f"{endian}I", body[12:16])[0]
                    ts_raw = (ts_hi << 32) | ts_lo
                    lt, tsresol, _ = interfaces[iid]
                    divisor = 10**tsresol if not (tsresol & 0x80) else 2**(tsresol & 0x7F)
                    ts = float(ts_raw) / float(divisor)

                    # Validate packet size
                    if cap_len > max_packet_size:
                        logger.warning(f"Packet size {cap_len} exceeds limit {max_packet_size}, skipping")
                        continue

                    pkt = body[20:20+cap_len]
                    yield PacketRecord(ts=ts, data=pkt, linktype=lt)
            elif btype == SPB:
                # Simple Packet Block: no timestamp, always interface 0
                if 0 in interfaces and len(body) >= 4:
                    orig_len = struct.unpack(f"{endian}I", body[0:4])[0]
                    lt, _, snaplen = interfaces[0]
                    cap_len = min(orig_len, snaplen or orig_len, len(body) - 4)
                    yield PacketRecord(ts=0.0, data=body[4:4 + cap_len], linktype=lt)


def iter_capture(path: str) -> Iterator[PacketRecord]:
    """
    Iterate over packets in either PCAP or PCAPNG file.

    Args:
        path: Path to PCAP/PCAPNG file

    Returns:
        Iterator of PacketRecord objects

    Raises:
        FileNotFoundError: If file doesn't exist
        ValueError: If file is too short or has invalid format
        PermissionError: If file cannot be read
    """
    import os

    # Validate file existence
    if not os.path.exists(path):
        raise FileNotFoundError(f"PCAP file not found: {path}")

    # Validate file is readable
    if not os.path.isfile(path):
        raise ValueError(f"Path is not a file: {path}")

    # Validate file size
    file_size = os.path.getsize(path)
    if file_size < 24:
        raise ValueError(f"File too short to be a valid PCAP file (size: {file_size} bytes, minimum: 24 bytes)")

    # Validate file format by magic number
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
            if len(magic) < 4:
                raise ValueError("Unable to read magic number from file")
            magic_val = struct.unpack("<I", magic)[0]
    except PermissionError:
        raise PermissionError(f"Permission denied reading file: {path}")
    except Exception as e:
        raise ValueError(f"Error reading PCAP file header: {e}")

    # Determine format and iterate
    if magic_val == 0x0A0D0D0A:
        logger.info(f"Detected PCAPNG format: {path}")
        yield from iter_pcapng(path)
    elif magic_val in {0xA1B2C3D4, 0xD4C3B2A1, 0xA1B23C4D, 0x4D3CB2A1}:
        logger.info(f"Detected PCAP format: {path}")
        yield from iter_pcap(path)
    else:
        raise ValueError(f"Unsupported capture format (magic: 0x{magic_val:08X}). Expected PCAP or PCAPNG file.")


# =============================================================================
# PROTOCOL PARSER
# =============================================================================

class ProtocolParser:
    """Protocol parsers for OT/ICS protocols"""
    _last_packet_time = defaultdict(lambda: 0.0)
    _last_payload_value = defaultdict(lambda: None)

    @staticmethod
    def _calculate_threat_score(risk: str) -> float:
        """Calculate threat score based on risk level"""
        if risk == "CRITICAL":
            return 1.0
        elif risk == "HIGH":
            return 0.75
        elif risk == "MEDIUM":
            return 0.5
        return 0.25

    @staticmethod
    def _get_time_features(key: tuple, ts: float, payload: bytes, payload_offset: int) -> tuple:
        """Get time-based features for ML"""
        time_since_last = ts - ProtocolParser._last_packet_time[key] if ProtocolParser._last_packet_time[key] else 0.0
        ProtocolParser._last_packet_time[key] = ts

        payload_val = payload[payload_offset] if len(payload) > payload_offset else None
        last_val = ProtocolParser._last_payload_value[key]
        payload_change_rate = 0.0
        if payload_val is not None and last_val is not None and time_since_last > 0:
            payload_change_rate = abs(payload_val - last_val) / time_since_last
        ProtocolParser._last_payload_value[key] = payload_val

        return time_since_last, payload_change_rate

    # Modbus exception codes for better error reporting
    MODBUS_EXCEPTIONS = {
        0x01: "ILLEGAL_FUNCTION",
        0x02: "ILLEGAL_DATA_ADDRESS",
        0x03: "ILLEGAL_DATA_VALUE",
        0x04: "SLAVE_DEVICE_FAILURE",
        0x05: "ACKNOWLEDGE",
        0x06: "SLAVE_DEVICE_BUSY",
        0x08: "MEMORY_PARITY_ERROR",
        0x0A: "GATEWAY_PATH_UNAVAILABLE",
        0x0B: "GATEWAY_TARGET_FAILED",
    }

    # Dangerous Modbus registers (common across vendors)
    DANGEROUS_REGISTERS = {
        # Safety-related registers (typical ranges)
        (0, 99): "SAFETY_OUTPUTS",
        (100, 199): "SAFETY_INPUTS",
        # Control registers
        (40000, 40099): "HOLDING_REGISTERS_CONTROL",
        (40100, 40199): "SETPOINT_REGISTERS",
        # Configuration
        (49999, 50000): "DEVICE_CONFIG",
    }

    @staticmethod
    def parse_modbus_tcp(payload: bytes, ts: float, src_ip: str, dst_ip: str,
                         src_port: int, dst_port: int, seq_id: int) -> Optional[OTEvent]:
        """
        Parse Modbus TCP packet with enhanced validation and threat detection.

        Enhanced features:
        - Function-specific payload validation
        - Detailed exception code interpretation
        - Write value extraction and analysis
        - Dangerous register detection
        - Broadcast detection (Unit ID 0 or 255)
        - Malformed packet detection
        """
        if len(payload) < 8:
            return None
        try:
            # MBAP Header parsing
            trans_id = struct.unpack(">H", payload[0:2])[0]
            proto_id = struct.unpack(">H", payload[2:4])[0]
            length = struct.unpack(">H", payload[4:6])[0]
            unit_id = payload[6]
            func_code = payload[7]

            # Validate protocol ID (must be 0 for Modbus TCP)
            if proto_id != 0:
                return None

            # Validate length field
            if length < 2 or length > 256:
                return None

            func_info = MODBUS_FUNCTIONS.get(func_code,
                (f"Unknown ({func_code})", "UNKNOWN", "MEDIUM", []))
            func_name, op_type, risk, mitre = func_info
            mitre = list(mitre)  # copy: never mutate the shared constant table

            # Direction: traffic from the server port is a response from the slave
            is_response = src_port == 502 and dst_port != 502

            data_addr, data_count = 0, 0
            write_values = []
            notes_extra = ""

            # Exception response handling
            if func_code >= 0x80:
                orig_func = func_code - 0x80
                exc_code = payload[8] if len(payload) > 8 else 0
                exc_name = ProtocolParser.MODBUS_EXCEPTIONS.get(exc_code, f"UNKNOWN_{exc_code}")
                func_name = f"Exception (FC={orig_func}, {exc_name})"
                op_type, risk = "ERROR", "MEDIUM"

                # Repeated illegal function exceptions may indicate scanning
                if exc_code == 0x01:
                    mitre = ["T0841", "T0808"]  # Network Service Scanning
                    notes_extra = "POSSIBLE_SCAN"

            elif is_response:
                # Normal response: echo of request (writes) or returned data (reads).
                # Request fields (address/count) are not at the same offsets, so
                # do not parse them, and do not count the response as a new write.
                func_name = f"{func_name} (Response)"
                op_type, risk, mitre = "RESPONSE", "LOW", []
                if func_code in (1, 2, 3, 4) and len(payload) > 8:
                    notes_extra = f"ByteCount={payload[8]}"

            else:
                # Function-specific parsing
                if func_code in [1, 2, 3, 4]:  # Read functions
                    if len(payload) >= 12:
                        data_addr = struct.unpack(">H", payload[8:10])[0]
                        data_count = struct.unpack(">H", payload[10:12])[0]

                        # Validate read request limits
                        if func_code in [1, 2] and data_count > 2000:  # Coils/DI max
                            notes_extra = "EXCESSIVE_READ_COUNT"
                            risk = "HIGH"
                        elif func_code in [3, 4] and data_count > 125:  # Registers max
                            notes_extra = "EXCESSIVE_READ_COUNT"
                            risk = "HIGH"

                elif func_code == 5:  # Write Single Coil
                    if len(payload) >= 12:
                        data_addr = struct.unpack(">H", payload[8:10])[0]
                        coil_value = struct.unpack(">H", payload[10:12])[0]
                        write_values = [coil_value]
                        notes_extra = f"Coil={data_addr}, Value={'ON' if coil_value == 0xFF00 else 'OFF'}"

                elif func_code == 6:  # Write Single Register
                    if len(payload) >= 12:
                        data_addr = struct.unpack(">H", payload[8:10])[0]
                        reg_value = struct.unpack(">H", payload[10:12])[0]
                        write_values = [reg_value]
                        notes_extra = f"Reg={data_addr}, Value={reg_value}"

                elif func_code == 15:  # Write Multiple Coils
                    if len(payload) >= 13:
                        data_addr = struct.unpack(">H", payload[8:10])[0]
                        data_count = struct.unpack(">H", payload[10:12])[0]
                        byte_count = payload[12]

                        if data_count > 1968:  # Max coils
                            notes_extra = "EXCESSIVE_WRITE_COUNT"
                            risk = "CRITICAL"
                            mitre.append("T0806")  # Brute Force I/O

                        # Extract coil values
                        if len(payload) >= 13 + byte_count:
                            coil_bytes = payload[13:13+byte_count]
                            notes_extra = f"Coils={data_addr}-{data_addr+data_count-1}, Bytes={byte_count}"

                elif func_code == 16:  # Write Multiple Registers
                    if len(payload) >= 13:
                        data_addr = struct.unpack(">H", payload[8:10])[0]
                        data_count = struct.unpack(">H", payload[10:12])[0]
                        byte_count = payload[12]

                        if data_count > 123:  # Max registers
                            notes_extra = "EXCESSIVE_WRITE_COUNT"
                            risk = "CRITICAL"

                        # Extract register values
                        if len(payload) >= 13 + byte_count:
                            for i in range(min(data_count, 10)):  # First 10 values
                                offset = 13 + i * 2
                                if offset + 2 <= len(payload):
                                    write_values.append(struct.unpack(">H", payload[offset:offset+2])[0])

                        notes_extra = f"Regs={data_addr}-{data_addr+data_count-1}"
                        if write_values:
                            notes_extra += f", Values={write_values[:5]}"

                elif func_code == 23:  # Read/Write Multiple Registers
                    if len(payload) >= 17:
                        read_addr = struct.unpack(">H", payload[8:10])[0]
                        read_count = struct.unpack(">H", payload[10:12])[0]
                        write_addr = struct.unpack(">H", payload[12:14])[0]
                        write_count = struct.unpack(">H", payload[14:16])[0]
                        data_addr = write_addr
                        data_count = write_count
                        notes_extra = f"Read={read_addr}:{read_count}, Write={write_addr}:{write_count}"

                elif func_code in [65, 66, 90]:  # Critical control functions
                    risk = "CRITICAL"
                    mitre.extend(["T0816", "T0815"])

            # Broadcast detection (Unit ID 0 or 255)
            if unit_id == 0 or unit_id == 255:
                if "BROADCAST" not in notes_extra:
                    notes_extra = f"BROADCAST, {notes_extra}" if notes_extra else "BROADCAST"
                if op_type in ["WRITE", "CONTROL"]:
                    risk = "CRITICAL"
                    mitre.append("T0806")

            # Dangerous register range detection
            for (start, end), reg_type in ProtocolParser.DANGEROUS_REGISTERS.items():
                if start <= data_addr <= end:
                    if op_type == "WRITE":
                        risk = "CRITICAL"
                        notes_extra += f", {reg_type}"
                    break

            ent = entropy(payload[8:]) if len(payload) > 8 else 0.0
            threat_score = ProtocolParser._calculate_threat_score(risk)

            # Additional threat score modifiers
            if ent > 7.5:
                threat_score += 0.2
            if data_count > 100:
                threat_score += 0.1
            if write_values and any(v > 32767 for v in write_values):  # Large values
                threat_score += 0.1

            key = (src_ip, dst_ip, func_code)
            time_since_last, payload_change_rate = ProtocolParser._get_time_features(key, ts, payload, 10)

            return OTEvent(
                timestamp=ts, src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=dst_port,
                protocol=OTProtocol.MODBUS_TCP, function_code=func_code,
                function_name=func_name, operation_type=op_type, risk_level=risk,
                unit_id=unit_id, data_address=data_addr, data_count=data_count,
                raw_data=payload[:min(64, len(payload))],
                notes=f"TransID={trans_id}, Len={length}" + (f", {notes_extra}" if notes_extra else ""),
                mitre_techniques=list(set(mitre)), threat_score=min(threat_score, 1.0),
                payload_entropy=ent, sequence_id=seq_id,
                time_since_last_packet=time_since_last,
                payload_change_rate=payload_change_rate
            )
        except Exception as e:
            logger.debug(f"Modbus parse error: {e}")
            return None

    @staticmethod
    def parse_s7comm(payload: bytes, ts: float, src_ip: str, dst_ip: str,
                     src_port: int, dst_port: int, seq_id: int) -> Optional[OTEvent]:
        """Parse S7Comm packet"""
        if len(payload) < 10:
            return None
        try:
            if payload[0] != 3:
                return None

            cotp_len = payload[4]
            s7_offset = 4 + 1 + cotp_len
            if len(payload) < s7_offset + 10:
                return None

            if payload[s7_offset] != 0x32:
                return None

            s7_type = payload[s7_offset + 1]
            # S7 header is 10 bytes for Job/Userdata and 12 bytes for Ack/AckData
            # (extra error class/code). The function code is the first parameter byte.
            param_offset = s7_offset + (12 if s7_type in (0x02, 0x03) else 10)
            param_len = struct.unpack(">H", payload[s7_offset + 6:s7_offset + 8])[0]
            if param_len == 0 or len(payload) <= param_offset:
                return None
            s7_func = payload[param_offset]
            if s7_type == 0x07 and len(payload) > param_offset + 5:
                # Userdata: parameter head (00 01 12), then type/function group nibble
                s7_func = 0x100 | (payload[param_offset + 5] & 0x0F)

            if s7_func & 0x100:
                groups = {1: "Programmer commands", 2: "Cyclic data", 3: "Block functions",
                          4: "CPU functions", 5: "Security", 7: "Time functions"}
                group = s7_func & 0x0F
                func_name = f"Userdata: {groups.get(group, f'Group {group}')}"
                op_type, risk, mitre = "READ", ("MEDIUM" if group in (1, 5) else "LOW"), []
            else:
                func_info = S7_FUNCTIONS.get(s7_func,
                    (f"Unknown ({s7_func})", "UNKNOWN", "MEDIUM", []))
                func_name, op_type, risk, mitre = func_info
                mitre = list(mitre)
            if s7_type in (0x02, 0x03):
                # Acknowledgements are responses: do not count them as new commands
                func_name = f"{func_name} (Response)"
                op_type, risk = "RESPONSE", "LOW"

            type_names = {0x01: "Job", 0x02: "Ack", 0x03: "AckData", 0x07: "Userdata"}
            type_name = type_names.get(s7_type, f"Type {s7_type}")

            ent = entropy(payload[s7_offset:])
            threat_score = ProtocolParser._calculate_threat_score(risk)

            if s7_func in [0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F]:
                threat_score = 1.0

            key = (src_ip, dst_ip, s7_func)
            time_since_last, payload_change_rate = ProtocolParser._get_time_features(key, ts, payload, s7_offset+10)

            return OTEvent(
                timestamp=ts, src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=dst_port,
                protocol=OTProtocol.S7COMM, function_code=s7_func,
                function_name=func_name, operation_type=op_type, risk_level=risk,
                raw_data=payload[:min(64, len(payload))],
                notes=f"Type={type_name}",
                mitre_techniques=mitre, threat_score=threat_score,
                payload_entropy=ent, sequence_id=seq_id,
                time_since_last_packet=time_since_last,
                payload_change_rate=payload_change_rate
            )
        except Exception as e:
            logger.debug(f"S7comm parse error: {e}")
            return None

    @staticmethod
    def parse_dnp3(payload: bytes, ts: float, src_ip: str, dst_ip: str,
                   src_port: int, dst_port: int, seq_id: int) -> Optional[OTEvent]:
        """Parse DNP3 packet"""
        if len(payload) < 10:
            return None
        try:
            # Start bytes are 0x05 0x64 on the wire (big-endian 0x0564)
            if payload[0] != 0x05 or payload[1] != 0x64:
                return None
            link_len = payload[2]

            ctrl = payload[3]
            dst_addr = struct.unpack("<H", payload[4:6])[0]
            src_addr = struct.unpack("<H", payload[6:8])[0]

            # Link header (10 bytes incl. CRC) -> transport header (byte 10)
            # -> application control (byte 11) -> function code (byte 12).
            # Frames with link length 5 carry no application layer.
            if link_len <= 5 or len(payload) < 13:
                func_code = 0xFF  # link-layer only frame
            else:
                func_code = payload[12]
            if func_code == 0xFF:
                func_name, op_type, risk, mitre = "Link Layer (no application data)", "LINK", "LOW", []
            else:
                func_info = DNP3_FUNCTIONS.get(func_code,
                    (f"Unknown ({func_code})", "UNKNOWN", "MEDIUM", []))
                func_name, op_type, risk, mitre = func_info
                mitre = list(mitre)

            ent = entropy(payload[10:])
            threat_score = ProtocolParser._calculate_threat_score(risk)

            key = (src_ip, dst_ip, func_code)
            time_since_last, payload_change_rate = ProtocolParser._get_time_features(key, ts, payload, 12)

            return OTEvent(
                timestamp=ts, src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=dst_port,
                protocol=OTProtocol.DNP3, function_code=func_code,
                function_name=func_name, operation_type=op_type, risk_level=risk,
                raw_data=payload[:min(64, len(payload))],
                notes=f"DNP3Dst={dst_addr}, DNP3Src={src_addr}, Ctrl=0x{ctrl:02X}",
                mitre_techniques=mitre, threat_score=threat_score,
                payload_entropy=ent, sequence_id=seq_id,
                time_since_last_packet=time_since_last,
                payload_change_rate=payload_change_rate
            )
        except Exception as e:
            logger.debug(f"DNP3 parse error: {e}")
            return None

    @staticmethod
    def parse_enip(payload: bytes, ts: float, src_ip: str, dst_ip: str,
                   src_port: int, dst_port: int, seq_id: int) -> Optional[OTEvent]:
        """Parse EtherNet/IP packet"""
        if len(payload) < 24:
            return None
        try:
            command = struct.unpack("<H", payload[0:2])[0]
            session = struct.unpack("<I", payload[4:8])[0]
            status = struct.unpack("<I", payload[8:12])[0]

            enip_cmds = {
                0x0001: ("ListServices", "DISCOVERY", "LOW", []),
                0x0004: ("ListIdentity", "DISCOVERY", "LOW", ["T0808"]),
                0x0063: ("ListInterfaces", "DISCOVERY", "LOW", []),
                0x0065: ("RegisterSession", "SESSION", "LOW", []),
                0x0066: ("UnregisterSession", "SESSION", "LOW", []),
                0x006F: ("SendRRData", "DATA", "MEDIUM", []),
                0x0070: ("SendUnitData", "DATA", "MEDIUM", []),
            }

            cmd_info = enip_cmds.get(command, (f"Unknown (0x{command:04X})", "UNKNOWN", "MEDIUM", []))
            func_name, op_type, risk, mitre = cmd_info

            mitre = list(mitre)
            cip_service = 0
            cip_offset = ProtocolParser._enip_cip_offset(payload, command)
            if cip_offset is not None and cip_offset < len(payload):
                cip_service = payload[cip_offset] & 0x7F
                is_reply = bool(payload[cip_offset] & 0x80)
                cip_info = CIP_SERVICES.get(cip_service, (f"CIP Service {cip_service}", "UNKNOWN", "MEDIUM", []))
                func_name = f"{func_name} -> {cip_info[0]}"
                if is_reply:
                    func_name += " (Response)"
                    op_type, risk = "RESPONSE", "LOW"
                else:
                    op_type, risk = cip_info[1], cip_info[2]
                    mitre.extend(cip_info[3])

            ent = entropy(payload[24:])
            threat_score = ProtocolParser._calculate_threat_score(risk)

            key = (src_ip, dst_ip, command)
            time_since_last, payload_change_rate = ProtocolParser._get_time_features(key, ts, payload, 24)

            return OTEvent(
                timestamp=ts, src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=dst_port,
                protocol=OTProtocol.ENIP, function_code=command,
                function_name=func_name, operation_type=op_type, risk_level=risk,
                raw_data=payload[:min(64, len(payload))],
                notes=f"Session=0x{session:08X}, Status=0x{status:08X}, CIP=0x{cip_service:02X}",
                mitre_techniques=list(set(mitre)), threat_score=threat_score,
                payload_entropy=ent, sequence_id=seq_id,
                time_since_last_packet=time_since_last,
                payload_change_rate=payload_change_rate
            )
        except Exception as e:
            logger.debug(f"EtherNet/IP parse error: {e}")
            return None

    @staticmethod
    def _enip_cip_offset(payload: bytes, command: int) -> Optional[int]:
        """Return the offset of the CIP service byte inside SendRRData/SendUnitData, or None."""
        if command not in (0x006F, 0x0070) or len(payload) < 32:
            return None
        offset = 24 + 6  # interface handle (4) + timeout (2)
        item_count = struct.unpack("<H", payload[offset:offset + 2])[0]
        offset += 2
        for _ in range(min(item_count, 8)):
            if offset + 4 > len(payload):
                return None
            item_type, item_len = struct.unpack("<HH", payload[offset:offset + 4])
            offset += 4
            if item_type == 0x00B2:      # Unconnected data item
                return offset
            if item_type == 0x00B1:      # Connected data item: 2-byte sequence count first
                return offset + 2
            offset += item_len
        return None

    @staticmethod
    def parse_iec104(payload: bytes, ts: float, src_ip: str, dst_ip: str,
                     src_port: int, dst_port: int, seq_id: int) -> Optional[OTEvent]:
        """Parse IEC 60870-5-104 packet"""
        if len(payload) < 6:
            return None
        try:
            start = payload[0]
            if start != 0x68:
                return None

            length = payload[1]
            if len(payload) < length + 2:
                return None

            ctrl1 = payload[2]
            ctrl3 = payload[4]
            ctrl4 = payload[5]

            # I-format
            if (ctrl1 & 0x01) == 0:
                if len(payload) < 12:
                    return None
                type_id = payload[6]
                vsq = payload[7]
                cot = payload[8]

                asdu_info = IEC104_ASDU_TYPES.get(type_id,
                    (f"Type_{type_id}", f"Unknown ASDU Type {type_id}", "UNKNOWN", "MEDIUM"))
                type_name, desc, op_type, risk = asdu_info

                mitre = []
                if op_type == "CONTROL":
                    mitre = ["T0831", "T0835"]
                    risk = "HIGH"
                elif op_type == "READ":
                    mitre = ["T0801", "T0802"]

                threat_score = 0.5 if op_type == "CONTROL" else 0.2

                key = (src_ip, dst_ip, type_id)
                time_since_last, payload_change_rate = ProtocolParser._get_time_features(key, ts, payload, 9)

                return OTEvent(
                    timestamp=ts, src_ip=src_ip, dst_ip=dst_ip,
                    src_port=src_port, dst_port=dst_port,
                    protocol=OTProtocol.IEC_104, function_code=type_id,
                    function_name=f"{type_name} - {desc}",
                    operation_type=op_type, risk_level=risk,
                    raw_data=payload[:min(64, len(payload))],
                    notes=f"I-Frame, COT={cot}, VSQ={vsq}",
                    mitre_techniques=mitre, threat_score=threat_score,
                    payload_entropy=entropy(payload[6:]), sequence_id=seq_id,
                    time_since_last_packet=time_since_last,
                    payload_change_rate=payload_change_rate
                )

            # S-format
            elif (ctrl1 & 0x03) == 0x01:
                recv_seq = (ctrl3 | (ctrl4 << 8)) >> 1
                key = (src_ip, dst_ip, 0xFE)
                time_since_last, _ = ProtocolParser._get_time_features(key, ts, payload, 2)

                return OTEvent(
                    timestamp=ts, src_ip=src_ip, dst_ip=dst_ip,
                    src_port=src_port, dst_port=dst_port,
                    protocol=OTProtocol.IEC_104, function_code=0xFE,
                    function_name="S-Format (Supervisory)",
                    operation_type="ACK", risk_level="LOW",
                    raw_data=payload[:min(64, len(payload))],
                    notes=f"S-Frame, RecvSeq={recv_seq}",
                    mitre_techniques=[], threat_score=0.1,
                    payload_entropy=0.0, sequence_id=seq_id,
                    time_since_last_packet=time_since_last,
                    payload_change_rate=0.0
                )

            # U-format
            elif (ctrl1 & 0x03) == 0x03:
                u_functions = {
                    0x07: ("STARTDT act", "Connection start request", "MEDIUM"),
                    0x0B: ("STARTDT con", "Connection start confirm", "LOW"),
                    0x13: ("STOPDT act", "Connection stop request", "HIGH"),
                    0x23: ("STOPDT con", "Connection stop confirm", "MEDIUM"),
                    0x43: ("TESTFR act", "Test frame request", "LOW"),
                    0x83: ("TESTFR con", "Test frame confirm", "LOW"),
                }

                u_info = u_functions.get(ctrl1, (f"U-Format 0x{ctrl1:02X}", "Unknown U-format", "MEDIUM"))
                func_name, desc, risk = u_info

                mitre = []
                if "STOPDT" in func_name:
                    mitre = ["T0813", "T0814"]
                    risk = "HIGH"

                key = (src_ip, dst_ip, 0xFF)
                time_since_last, _ = ProtocolParser._get_time_features(key, ts, payload, 2)

                return OTEvent(
                    timestamp=ts, src_ip=src_ip, dst_ip=dst_ip,
                    src_port=src_port, dst_port=dst_port,
                    protocol=OTProtocol.IEC_104, function_code=ctrl1,
                    function_name=f"{func_name} - {desc}",
                    operation_type="CONTROL", risk_level=risk,
                    raw_data=payload[:min(64, len(payload))],
                    notes=f"U-Frame",
                    mitre_techniques=mitre,
                    threat_score=0.6 if risk == "HIGH" else 0.3,
                    payload_entropy=0.0, sequence_id=seq_id,
                    time_since_last_packet=time_since_last,
                    payload_change_rate=0.0
                )

            return None

        except Exception as e:
            logger.debug(f"IEC-104 parse error: {e}")
            return None

    @staticmethod
    def parse_profinet_dcp(payload: bytes, ts: float, src_ip: str, dst_ip: str,
                           src_port: int, dst_port: int, seq_id: int) -> Optional[OTEvent]:
        """Parse PROFINET DCP packet"""
        if len(payload) < 10:
            return None
        try:
            service_id = payload[0]
            service_type = payload[1]

            dcp_services = {
                0x03: ("Get", "DISCOVERY", "LOW"),
                0x04: ("Set", "CONFIG", "HIGH"),
                0x05: ("Identify", "DISCOVERY", "LOW"),
                0x06: ("Hello", "DISCOVERY", "LOW"),
            }

            service_info = dcp_services.get(service_id, (f"Unknown (0x{service_id:02X})", "UNKNOWN", "MEDIUM"))
            func_name, op_type, risk = service_info

            mitre = []
            if service_id == 0x04:
                mitre = ["T0831", "T0836"]
                risk = "HIGH"

            key = (src_ip, dst_ip, service_id)
            time_since_last, payload_change_rate = ProtocolParser._get_time_features(key, ts, payload, 2)

            return OTEvent(
                timestamp=ts, src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=dst_port,
                protocol=OTProtocol.PROFINET_DCP, function_code=service_id,
                function_name=f"DCP {func_name}",
                operation_type=op_type, risk_level=risk,
                raw_data=payload[:min(64, len(payload))],
                notes=f"ServiceType=0x{service_type:02X}",
                mitre_techniques=mitre,
                threat_score=0.7 if risk == "HIGH" else 0.2,
                payload_entropy=entropy(payload), sequence_id=seq_id,
                time_since_last_packet=time_since_last,
                payload_change_rate=payload_change_rate
            )
        except Exception as e:
            logger.debug(f"PROFINET DCP parse error: {e}")
            return None

    # =========================================================================
    # IT PROTOCOL PARSERS
    # =========================================================================

    @staticmethod
    def parse_dns(payload: bytes, ts: float, src_ip: str, dst_ip: str,
                  src_port: int, dst_port: int) -> Optional[Dict]:
        """Parse DNS packet for tunneling detection"""
        if len(payload) < 12:
            return None

        try:
            # DNS Header
            trans_id = struct.unpack(">H", payload[0:2])[0]
            flags = struct.unpack(">H", payload[2:4])[0]
            qr = (flags >> 15) & 0x1          # 0=query, 1=response
            opcode = (flags >> 11) & 0xF
            rcode = flags & 0xF

            qdcount = struct.unpack(">H", payload[4:6])[0]
            ancount = struct.unpack(">H", payload[6:8])[0]

            # Parse question section
            offset = 12
            queries = []

            for _ in range(min(qdcount, 10)):  # Limit parsing
                qname, offset = ProtocolParser._parse_dns_name(payload, offset)
                if offset + 4 > len(payload):
                    break
                qtype = struct.unpack(">H", payload[offset:offset+2])[0]
                qclass = struct.unpack(">H", payload[offset+2:offset+4])[0]
                offset += 4

                queries.append({
                    'name': qname,
                    'type': qtype,
                    'type_name': DNS_QUERY_TYPES.get(qtype, f"TYPE{qtype}"),
                    'class': qclass,
                })

            return {
                'timestamp': ts,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'trans_id': trans_id,
                'is_response': qr == 1,
                'opcode': opcode,
                'rcode': rcode,
                'query_count': qdcount,
                'answer_count': ancount,
                'queries': queries,
            }
        except Exception as e:
            logger.debug(f"DNS parse error: {e}")
            return None

    @staticmethod
    def _parse_dns_name(payload: bytes, offset: int) -> Tuple[str, int]:
        """Parse DNS name with compression support"""
        labels = []
        jumped = False
        max_jumps = 10
        jumps = 0
        original_offset = offset

        while offset < len(payload):
            length = payload[offset]

            if length == 0:
                offset += 1
                break
            elif (length & 0xC0) == 0xC0:  # Compression pointer
                if not jumped:
                    original_offset = offset + 2
                pointer = struct.unpack(">H", payload[offset:offset+2])[0] & 0x3FFF
                offset = pointer
                jumped = True
                jumps += 1
                if jumps > max_jumps:
                    break
            else:
                offset += 1
                if offset + length > len(payload):
                    break
                try:
                    labels.append(payload[offset:offset+length].decode('utf-8', errors='replace'))
                except (UnicodeDecodeError, AttributeError) as e:
                    logger.debug(f"DNS label decode error: {e}")
                    labels.append(payload[offset:offset+length].hex())
                offset += length

        return '.'.join(labels), original_offset if jumped else offset

    @staticmethod
    def parse_http_request(payload: bytes, ts: float, src_ip: str, dst_ip: str,
                           src_port: int, dst_port: int, analyzer: EnhancedHTTPStreamAnalyzer = None) -> Optional[Dict]:
        """
        Parse HTTP request for security analysis (including enhanced WebShell/attack detection).
        Returns a dict with parsed HTTP info and, if enabled, enhanced threat analysis results.
        """
        try:
            # Try to decode as UTF-8
            text = payload[:8192].decode('utf-8', errors='replace')
            lines = text.split('\r\n')
            if not lines:
                return None
            # Parse request line
            request_line = lines[0].split(' ')
            if len(request_line) < 2:
                return None
            method = request_line[0].upper()
            if method not in HTTP_METHODS:
                return None  # Not a valid HTTP request
            uri = request_line[1] if len(request_line) > 1 else ""
            version = request_line[2] if len(request_line) > 2 else ""
            # Parse headers
            headers = {}
            headers_raw = []
            body_start_idx = 0
            for i, line in enumerate(lines[1:], 1):
                if line == '':
                    body_start_idx = i + 1
                    break
                headers_raw.append(line)
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
            # Extract body content
            body = ""
            if body_start_idx > 0 and body_start_idx < len(lines):
                body = '\r\n'.join(lines[body_start_idx:])
            op_type, risk = HTTP_METHODS.get(method, ("UNKNOWN", "MEDIUM"))
            http_info = {
                'timestamp': ts,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'method': method,
                'uri': uri,
                'version': version,
                'headers': headers,
                'headers_raw': '\r\n'.join(headers_raw),
                'host': headers.get('host', ''),
                'user_agent': headers.get('user-agent', ''),
                'content_length': _safe_int(headers.get('content-length', 0)),
                'content_type': headers.get('content-type', ''),
                'body': body[:4096],
                'raw_size': len(payload),
                'operation_type': op_type,
                'risk_level': risk,
            }
            # --- Enhanced HTTP/WebShell Analysis ---
            try:
                decoder = EnhancedHTTPStreamDecoder()
                threat_analysis = decoder.analyze_http_payload(
                    payload=body.encode('utf-8', errors='replace'),
                    uri=uri,
                    method=method,
                    headers=headers
                )
                http_info['threat_analysis'] = threat_analysis
            except Exception as e:
                logger.debug(f"Enhanced HTTP analysis error: {e}")
            return http_info
        except Exception as e:
            logger.debug(f"HTTP parse error: {e}")
            return None

    @staticmethod
    def parse_arp(frame: bytes, ts: float) -> Optional[Dict]:
        """Parse ARP packet for spoofing detection"""
        # ARP is at layer 2, frame includes Ethernet header
        if len(frame) < 42:  # 14 (Ethernet) + 28 (ARP)
            return None

        try:
            # Ethernet header
            eth_dst = mac_to_str(frame[0:6])
            eth_src = mac_to_str(frame[6:12])
            eth_type = struct.unpack(">H", frame[12:14])[0]

            if eth_type != 0x0806:  # Not ARP
                return None

            # ARP header
            arp_data = frame[14:]
            hw_type = struct.unpack(">H", arp_data[0:2])[0]
            proto_type = struct.unpack(">H", arp_data[2:4])[0]
            hw_size = arp_data[4]
            proto_size = arp_data[5]
            opcode = struct.unpack(">H", arp_data[6:8])[0]

            # Sender/Target info
            sender_mac = mac_to_str(arp_data[8:14])
            sender_ip = ip4_to_str(arp_data[14:18])
            target_mac = mac_to_str(arp_data[18:24])
            target_ip = ip4_to_str(arp_data[24:28])

            opcode_names = {1: "ARP_REQUEST", 2: "ARP_REPLY"}

            # Detect gratuitous ARP (sender IP == target IP)
            is_gratuitous = sender_ip == target_ip

            return {
                'timestamp': ts,
                'eth_src': eth_src,
                'eth_dst': eth_dst,
                'opcode': opcode,
                'opcode_name': opcode_names.get(opcode, f"UNKNOWN_{opcode}"),
                'sender_mac': sender_mac,
                'sender_ip': sender_ip,
                'target_mac': target_mac,
                'target_ip': target_ip,
                'is_gratuitous': is_gratuitous,
            }
        except Exception as e:
            logger.debug(f"ARP parse error: {e}")
            return None

    # =========================================================================
    # BACnet PARSER (Building Automation and Control Networks)
    # =========================================================================
    @staticmethod
    def parse_bacnet(payload: bytes, ts: float, src_ip: str, dst_ip: str,
                     src_port: int, dst_port: int, seq_id: int) -> Optional[OTEvent]:
        """
        Parse BACnet/IP packet for building automation security analysis.

        BACnet is commonly used in:
        - HVAC systems
        - Fire alarm systems
        - Access control
        - Lighting control
        - Building management systems (BMS)

        Critical functions that should be monitored:
        - WriteProperty/WritePropertyMultiple: Can modify setpoints, schedules
        - DeviceCommunicationControl: Can disable device communications
        - ReinitializeDevice: Can restart or reset devices
        - ConfirmedPrivateTransfer: Vendor-specific operations
        """
        if len(payload) < 4:
            return None
        try:
            # BACnet/IP header (BVLC)
            bvlc_type = payload[0]
            bvlc_function = payload[1]
            bvlc_length = struct.unpack(">H", payload[2:4])[0]

            if bvlc_type != 0x81:  # Not BACnet/IP
                return None

            # BVLC Functions
            bvlc_functions = {
                0x00: ("BVLC-Result", "CONTROL", "LOW"),
                0x01: ("Write-Broadcast-Distribution-Table", "CONFIG", "HIGH"),
                0x02: ("Read-Broadcast-Distribution-Table", "READ", "LOW"),
                0x03: ("Read-Broadcast-Distribution-Table-Ack", "READ", "LOW"),
                0x04: ("Forwarded-NPDU", "DATA", "LOW"),
                0x05: ("Register-Foreign-Device", "CONFIG", "MEDIUM"),
                0x06: ("Read-Foreign-Device-Table", "READ", "LOW"),
                0x07: ("Read-Foreign-Device-Table-Ack", "READ", "LOW"),
                0x08: ("Delete-Foreign-Device-Table-Entry", "CONFIG", "HIGH"),
                0x09: ("Distribute-Broadcast-To-Network", "DATA", "LOW"),
                0x0A: ("Original-Unicast-NPDU", "DATA", "LOW"),
                0x0B: ("Original-Broadcast-NPDU", "DATA", "LOW"),
            }

            bvlc_info = bvlc_functions.get(bvlc_function,
                (f"Unknown BVLC (0x{bvlc_function:02X})", "UNKNOWN", "MEDIUM"))
            bvlc_name, op_type, risk = bvlc_info

            # Parse NPDU if present (after BVLC header)
            npdu_offset = 4
            apdu_type = 0
            service_choice = 0
            mitre = []

            if bvlc_function in [0x04, 0x0A, 0x0B] and len(payload) > npdu_offset + 2:
                # NPDU header
                npdu_version = payload[npdu_offset]
                npdu_control = payload[npdu_offset + 1]

                # Skip NPDU addressing based on control byte
                apdu_offset = npdu_offset + 2
                if npdu_control & 0x20:  # DNET/DLEN/DADR present
                    dnet_len = payload[apdu_offset + 2] if apdu_offset + 2 < len(payload) else 0
                    apdu_offset += 3 + dnet_len
                if npdu_control & 0x08:  # SNET/SLEN/SADR present
                    snet_len = payload[apdu_offset + 2] if apdu_offset + 2 < len(payload) else 0
                    apdu_offset += 3 + snet_len
                if npdu_control & 0x20:  # Hop count present
                    apdu_offset += 1

                # Parse APDU
                if apdu_offset < len(payload):
                    apdu_type = (payload[apdu_offset] >> 4) & 0x0F

                    # BACnet APDU Types
                    apdu_types = {
                        0: "Confirmed-Request",
                        1: "Unconfirmed-Request",
                        2: "SimpleACK",
                        3: "ComplexACK",
                        4: "SegmentACK",
                        5: "Error",
                        6: "Reject",
                        7: "Abort",
                    }

                    # Confirmed services (security-critical)
                    if apdu_type == 0 and apdu_offset + 3 < len(payload):
                        # byte0 type/flags, byte1 max segs/APDU, byte2 invoke ID,
                        # (segmented: byte3 seq no, byte4 window), then service choice
                        segmented = bool(payload[apdu_offset] & 0x08)
                        svc_idx = apdu_offset + (5 if segmented else 3)
                        service_choice = payload[svc_idx] if svc_idx < len(payload) else 0

                        confirmed_services = {
                            # Alarm and Event Services
                            0: ("AcknowledgeAlarm", "CONTROL", "MEDIUM", ["T0838"]),
                            2: ("GetAlarmSummary", "READ", "LOW", []),
                            3: ("GetEnrollmentSummary", "READ", "LOW", []),
                            # File Access Services
                            6: ("AtomicReadFile", "READ", "MEDIUM", ["T0811"]),
                            7: ("AtomicWriteFile", "WRITE", "HIGH", ["T0809", "T0839"]),
                            # Object Access Services
                            12: ("ReadProperty", "READ", "LOW", ["T0801"]),
                            13: ("ReadPropertyConditional", "READ", "LOW", []),
                            14: ("ReadPropertyMultiple", "READ", "LOW", ["T0801", "T0802"]),
                            15: ("WriteProperty", "WRITE", "HIGH", ["T0831", "T0836"]),
                            16: ("WritePropertyMultiple", "WRITE", "CRITICAL", ["T0831", "T0833"]),
                            # Remote Device Management
                            17: ("DeviceCommunicationControl", "CONTROL", "CRITICAL", ["T0813", "T0814"]),
                            18: ("ConfirmedPrivateTransfer", "CONTROL", "HIGH", []),
                            19: ("ConfirmedTextMessage", "DATA", "LOW", []),
                            20: ("ReinitializeDevice", "CONTROL", "CRITICAL", ["T0816", "T0815"]),
                            # Virtual Terminal Services
                            21: ("VT-Open", "SESSION", "MEDIUM", []),
                            22: ("VT-Close", "SESSION", "LOW", []),
                            23: ("VT-Data", "DATA", "MEDIUM", []),
                            # Security Services
                            24: ("Authenticate", "AUTH", "MEDIUM", ["T0859"]),
                            25: ("RequestKey", "AUTH", "MEDIUM", []),
                            # Object Creation/Deletion
                            10: ("CreateObject", "CONFIG", "HIGH", []),
                            11: ("DeleteObject", "CONFIG", "HIGH", ["T0809"]),
                        }

                        service_info = confirmed_services.get(service_choice,
                            (f"ConfirmedService_{service_choice}", "UNKNOWN", "MEDIUM", []))
                        func_name, op_type, risk, mitre = service_info
                        bvlc_name = f"{bvlc_name} -> {func_name}"

                    # Unconfirmed services
                    elif apdu_type == 1 and apdu_offset + 1 < len(payload):
                        service_choice = payload[apdu_offset + 1]

                        unconfirmed_services = {
                            0: ("I-Am", "DISCOVERY", "LOW", ["T0808"]),
                            1: ("I-Have", "DISCOVERY", "LOW", []),
                            2: ("UnconfirmedCOVNotification", "DATA", "LOW", []),
                            3: ("UnconfirmedEventNotification", "DATA", "LOW", []),
                            4: ("UnconfirmedPrivateTransfer", "DATA", "MEDIUM", []),
                            5: ("UnconfirmedTextMessage", "DATA", "LOW", []),
                            6: ("TimeSynchronization", "CONFIG", "MEDIUM", ["T0825"]),
                            7: ("Who-Has", "DISCOVERY", "LOW", ["T0808"]),
                            8: ("Who-Is", "DISCOVERY", "LOW", ["T0808", "T0841"]),
                            9: ("UTCTimeSynchronization", "CONFIG", "MEDIUM", []),
                        }

                        service_info = unconfirmed_services.get(service_choice,
                            (f"UnconfirmedService_{service_choice}", "UNKNOWN", "LOW", []))
                        func_name, op_type, risk, mitre = service_info
                        bvlc_name = f"{bvlc_name} -> {func_name}"

            ent = entropy(payload[4:]) if len(payload) > 4 else 0.0
            threat_score = ProtocolParser._calculate_threat_score(risk)

            # Higher threat score for critical operations
            if service_choice in [15, 16, 17, 20]:  # Write, DeviceControl, Reinitialize
                threat_score = min(threat_score + 0.3, 1.0)

            key = (src_ip, dst_ip, bvlc_function)
            time_since_last, payload_change_rate = ProtocolParser._get_time_features(key, ts, payload, 4)

            return OTEvent(
                timestamp=ts, src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=dst_port,
                protocol=OTProtocol.BACNET, function_code=service_choice or bvlc_function,
                function_name=bvlc_name, operation_type=op_type, risk_level=risk,
                raw_data=payload[:min(64, len(payload))],
                notes=f"BVLC=0x{bvlc_function:02X}, APDU_Type={apdu_type}, Service={service_choice}",
                mitre_techniques=mitre, threat_score=threat_score,
                payload_entropy=ent, sequence_id=seq_id,
                time_since_last_packet=time_since_last,
                payload_change_rate=payload_change_rate
            )
        except Exception as e:
            logger.debug(f"BACnet parse error: {e}")
            return None

    # =========================================================================
    # MQTT PARSER (Message Queuing Telemetry Transport)
    # =========================================================================
    @staticmethod
    def parse_mqtt(payload: bytes, ts: float, src_ip: str, dst_ip: str,
                   src_port: int, dst_port: int, seq_id: int) -> Optional[OTEvent]:
        """
        Parse MQTT packet for IoT/IIoT security analysis.

        MQTT is commonly used in:
        - Industrial IoT (IIoT) sensors
        - SCADA data collection
        - Remote monitoring
        - Edge device communication

        Security concerns:
        - CONNECT without authentication
        - Subscription to sensitive topics (#, +, system topics)
        - PUBLISH to control topics
        - Payload injection
        """
        if len(payload) < 2:
            return None
        try:
            # Fixed header
            packet_type = (payload[0] >> 4) & 0x0F
            flags = payload[0] & 0x0F

            # Decode remaining length (variable length encoding)
            remaining_length = 0
            multiplier = 1
            idx = 1
            while idx < len(payload) and idx < 5:
                byte = payload[idx]
                remaining_length += (byte & 0x7F) * multiplier
                multiplier *= 128
                idx += 1
                if (byte & 0x80) == 0:
                    break

            variable_header_offset = idx

            # MQTT Control Packet Types
            mqtt_types = {
                1: ("CONNECT", "SESSION", "MEDIUM", ["T0859"]),
                2: ("CONNACK", "SESSION", "LOW", []),
                3: ("PUBLISH", "WRITE", "MEDIUM", ["T0831"]),
                4: ("PUBACK", "ACK", "LOW", []),
                5: ("PUBREC", "ACK", "LOW", []),
                6: ("PUBREL", "ACK", "LOW", []),
                7: ("PUBCOMP", "ACK", "LOW", []),
                8: ("SUBSCRIBE", "CONFIG", "MEDIUM", ["T0801"]),
                9: ("SUBACK", "ACK", "LOW", []),
                10: ("UNSUBSCRIBE", "CONFIG", "LOW", []),
                11: ("UNSUBACK", "ACK", "LOW", []),
                12: ("PINGREQ", "HEARTBEAT", "LOW", []),
                13: ("PINGRESP", "HEARTBEAT", "LOW", []),
                14: ("DISCONNECT", "SESSION", "LOW", []),
            }

            type_info = mqtt_types.get(packet_type,
                (f"Unknown ({packet_type})", "UNKNOWN", "MEDIUM", []))
            func_name, op_type, risk, mitre = type_info

            topic = ""
            client_id = ""
            username = ""
            notes_extra = ""

            # Parse CONNECT packet
            if packet_type == 1 and len(payload) > variable_header_offset + 10:
                vh = payload[variable_header_offset:]
                # Protocol name
                proto_name_len = struct.unpack(">H", vh[0:2])[0] if len(vh) > 2 else 0
                offset = 2 + proto_name_len

                if offset + 4 < len(vh):
                    proto_version = vh[offset]
                    connect_flags = vh[offset + 1]
                    keep_alive = struct.unpack(">H", vh[offset + 2:offset + 4])[0]

                    # Check authentication flags
                    has_username = (connect_flags >> 7) & 0x01
                    has_password = (connect_flags >> 6) & 0x01

                    if not has_username and not has_password:
                        risk = "HIGH"
                        mitre.append("T0812")  # Default Credentials
                        notes_extra = "NO_AUTH"

                    # Parse Client ID
                    offset += 4
                    if offset + 2 < len(vh):
                        client_id_len = struct.unpack(">H", vh[offset:offset+2])[0]
                        offset += 2
                        if offset + client_id_len <= len(vh):
                            client_id = vh[offset:offset+client_id_len].decode('utf-8', errors='replace')
                            offset += client_id_len

                    notes_extra = f"ClientID={client_id[:32]}, Auth={'Yes' if has_username else 'No'}"

            # Parse PUBLISH packet
            elif packet_type == 3 and len(payload) > variable_header_offset + 2:
                vh = payload[variable_header_offset:]
                topic_len = struct.unpack(">H", vh[0:2])[0] if len(vh) > 2 else 0
                if topic_len > 0 and 2 + topic_len <= len(vh):
                    topic = vh[2:2+topic_len].decode('utf-8', errors='replace')

                    # Check for dangerous topics
                    dangerous_topics = [
                        ("$SYS/", "SYSTEM_TOPIC", "HIGH"),
                        ("/cmd", "COMMAND_TOPIC", "HIGH"),
                        ("/control", "CONTROL_TOPIC", "HIGH"),
                        ("/actuator", "ACTUATOR_TOPIC", "HIGH"),
                        ("/setpoint", "SETPOINT_TOPIC", "CRITICAL"),
                        ("/plc/", "PLC_TOPIC", "CRITICAL"),
                        ("/scada/", "SCADA_TOPIC", "CRITICAL"),
                        ("/rtu/", "RTU_TOPIC", "HIGH"),
                    ]

                    for pattern, indicator, topic_risk in dangerous_topics:
                        if pattern.lower() in topic.lower():
                            risk = topic_risk
                            mitre.extend(["T0831", "T0836"])
                            break

                    notes_extra = f"Topic={topic[:50]}"

                    # QoS from flags
                    qos = (flags >> 1) & 0x03
                    retain = flags & 0x01
                    if retain:
                        notes_extra += ", RETAIN"

            # Parse SUBSCRIBE packet
            elif packet_type == 8 and len(payload) > variable_header_offset + 4:
                vh = payload[variable_header_offset:]
                # Skip packet identifier
                offset = 2
                topics = []
                while offset + 2 < len(vh):
                    topic_len = struct.unpack(">H", vh[offset:offset+2])[0]
                    offset += 2
                    if offset + topic_len + 1 <= len(vh):
                        topic = vh[offset:offset+topic_len].decode('utf-8', errors='replace')
                        topics.append(topic)
                        offset += topic_len + 1  # +1 for QoS byte
                    else:
                        break

                # Check for wildcard subscriptions
                for t in topics:
                    if t == "#" or t == "+" or t.startswith("$"):
                        risk = "HIGH"
                        mitre.append("T0802")  # Automated Collection
                        break

                notes_extra = f"Topics={','.join(topics[:3])}"

            ent = entropy(payload[variable_header_offset:]) if len(payload) > variable_header_offset else 0.0
            threat_score = ProtocolParser._calculate_threat_score(risk)

            key = (src_ip, dst_ip, packet_type)
            time_since_last, payload_change_rate = ProtocolParser._get_time_features(key, ts, payload, variable_header_offset)

            return OTEvent(
                timestamp=ts, src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=dst_port,
                protocol=OTProtocol.MQTT, function_code=packet_type,
                function_name=func_name, operation_type=op_type, risk_level=risk,
                raw_data=payload[:min(64, len(payload))],
                notes=f"Flags=0x{flags:X}, Len={remaining_length}" + (f", {notes_extra}" if notes_extra else ""),
                mitre_techniques=list(set(mitre)), threat_score=threat_score,
                payload_entropy=ent, sequence_id=seq_id,
                time_since_last_packet=time_since_last,
                payload_change_rate=payload_change_rate
            )
        except Exception as e:
            logger.debug(f"MQTT parse error: {e}")
            return None

    # =========================================================================
    # OPC UA PARSER (OPC Unified Architecture)
    # =========================================================================
    @staticmethod
    def parse_opc_ua(payload: bytes, ts: float, src_ip: str, dst_ip: str,
                     src_port: int, dst_port: int, seq_id: int) -> Optional[OTEvent]:
        """
        Parse OPC UA Binary protocol packet.

        OPC UA is the modern industrial protocol used in:
        - Industry 4.0 applications
        - Smart manufacturing
        - Cross-platform industrial communication
        - Cloud/Edge integration

        Security concerns:
        - Session establishment without security
        - Write operations to nodes
        - Method calls
        - Browse operations (reconnaissance)
        """
        if len(payload) < 8:
            return None
        try:
            # OPC UA message header (3-byte message type)
            msg_type = payload[0:3].decode('ascii', errors='replace')
            is_final = chr(payload[3]) if len(payload) > 3 else 'F'
            msg_size = struct.unpack("<I", payload[4:8])[0] if len(payload) >= 8 else 0

            # OPC UA Message Types
            ua_msg_types = {
                "HEL": ("Hello", "SESSION", "LOW", []),
                "ACK": ("Acknowledge", "SESSION", "LOW", []),
                "ERR": ("Error", "ERROR", "MEDIUM", []),
                "OPN": ("OpenSecureChannel", "SESSION", "MEDIUM", ["T0859"]),
                "CLO": ("CloseSecureChannel", "SESSION", "LOW", []),
                "MSG": ("Message", "DATA", "MEDIUM", []),
            }

            type_info = ua_msg_types.get(msg_type,
                (f"Unknown ({msg_type})", "UNKNOWN", "MEDIUM", []))
            func_name, op_type, risk, mitre = type_info

            service_id = 0
            security_mode = "Unknown"
            notes_extra = ""

            # Parse Hello message
            if msg_type == "HEL" and len(payload) > 28:
                protocol_version = struct.unpack("<I", payload[8:12])[0]
                recv_buffer_size = struct.unpack("<I", payload[12:16])[0]
                send_buffer_size = struct.unpack("<I", payload[16:20])[0]
                max_msg_size = struct.unpack("<I", payload[20:24])[0]
                max_chunk_count = struct.unpack("<I", payload[24:28])[0]

                # Get endpoint URL
                if len(payload) > 32:
                    url_len = struct.unpack("<I", payload[28:32])[0]
                    if url_len > 0 and url_len < 1000 and 32 + url_len <= len(payload):
                        endpoint_url = payload[32:32+url_len].decode('utf-8', errors='replace')
                        notes_extra = f"Endpoint={endpoint_url[:50]}"

            # Parse OpenSecureChannel
            elif msg_type == "OPN" and len(payload) > 16:
                # Security header starts at offset 8
                if len(payload) > 12:
                    secure_channel_id = struct.unpack("<I", payload[8:12])[0]

                    # Check for security policy (simplified)
                    policy_offset = 12
                    if policy_offset + 4 < len(payload):
                        policy_len = struct.unpack("<I", payload[policy_offset:policy_offset+4])[0]
                        if policy_len > 0 and policy_len < 500 and policy_offset + 4 + policy_len <= len(payload):
                            policy_uri = payload[policy_offset+4:policy_offset+4+policy_len].decode('utf-8', errors='replace')

                            if "None" in policy_uri:
                                security_mode = "None"
                                risk = "HIGH"
                                mitre.append("T0812")
                                notes_extra = "NO_SECURITY"
                            elif "Basic128" in policy_uri or "Basic256" in policy_uri:
                                security_mode = "SignAndEncrypt"

                            notes_extra = f"SecurityPolicy={policy_uri.split('#')[-1] if '#' in policy_uri else 'Unknown'}"

            # Parse MSG (Service requests/responses)
            elif msg_type == "MSG" and len(payload) > 24:
                # Secure channel header + sequence header
                secure_channel_id = struct.unpack("<I", payload[8:12])[0]
                token_id = struct.unpack("<I", payload[12:16])[0]
                seq_num = struct.unpack("<I", payload[16:20])[0]
                request_id = struct.unpack("<I", payload[20:24])[0]

                # Service type ID follows (4 bytes for NodeId)
                if len(payload) > 28:
                    # Simplified NodeId parsing (assuming numeric)
                    encoding_byte = payload[24]
                    if encoding_byte == 0x01:  # FourByte NodeId
                        namespace_idx = payload[25]
                        service_id = struct.unpack("<H", payload[26:28])[0]
                    elif encoding_byte == 0x00:  # TwoByte NodeId
                        service_id = payload[25]

                    # OPC UA Service IDs (common ones)
                    # Keys are the *_Encoding_DefaultBinary NodeIds that appear on the
                    # wire (OPC UA Part 6 / NodeIds.csv), not the DataType NodeIds.
                    ua_services = {
                        397: ("ServiceFault", "ERROR", "LOW", []),
                        # Discovery Services
                        422: ("FindServersRequest", "DISCOVERY", "LOW", ["T0808", "T0841"]),
                        425: ("FindServersResponse", "DISCOVERY", "LOW", []),
                        428: ("GetEndpointsRequest", "DISCOVERY", "LOW", ["T0808"]),
                        431: ("GetEndpointsResponse", "DISCOVERY", "LOW", []),

                        # SecureChannel / Session Services
                        446: ("OpenSecureChannelRequest", "SESSION", "LOW", []),
                        452: ("CloseSecureChannelRequest", "SESSION", "LOW", []),
                        461: ("CreateSessionRequest", "SESSION", "MEDIUM", []),
                        464: ("CreateSessionResponse", "SESSION", "LOW", []),
                        467: ("ActivateSessionRequest", "SESSION", "MEDIUM", ["T0859"]),
                        470: ("ActivateSessionResponse", "SESSION", "LOW", []),
                        473: ("CloseSessionRequest", "SESSION", "LOW", []),

                        # NodeManagement Services
                        488: ("AddNodesRequest", "CONFIG", "HIGH", ["T0831"]),
                        500: ("DeleteNodesRequest", "CONFIG", "HIGH", ["T0809", "T0831"]),

                        # View Services (Browse)
                        527: ("BrowseRequest", "READ", "MEDIUM", ["T0801", "T0808"]),
                        530: ("BrowseResponse", "READ", "LOW", []),
                        533: ("BrowseNextRequest", "READ", "MEDIUM", []),
                        554: ("TranslateBrowsePathsToNodeIdsRequest", "READ", "MEDIUM", []),

                        # Attribute Services
                        631: ("ReadRequest", "READ", "LOW", ["T0801"]),
                        634: ("ReadResponse", "RESPONSE", "LOW", []),
                        664: ("HistoryReadRequest", "READ", "LOW", ["T0801"]),
                        673: ("WriteRequest", "WRITE", "HIGH", ["T0831", "T0836"]),
                        676: ("WriteResponse", "RESPONSE", "LOW", []),
                        700: ("HistoryUpdateRequest", "WRITE", "HIGH", ["T0831"]),

                        # Method Services
                        712: ("CallRequest", "CONTROL", "HIGH", ["T0858", "T0831"]),
                        715: ("CallResponse", "RESPONSE", "LOW", []),

                        # MonitoredItem / Subscription Services
                        751: ("CreateMonitoredItemsRequest", "CONFIG", "LOW", []),
                        787: ("CreateSubscriptionRequest", "CONFIG", "MEDIUM", []),
                        799: ("SetPublishingModeRequest", "CONFIG", "MEDIUM", []),
                        826: ("PublishRequest", "READ", "LOW", []),
                        829: ("PublishResponse", "RESPONSE", "LOW", []),
                        832: ("RepublishRequest", "READ", "LOW", []),
                        847: ("DeleteSubscriptionsRequest", "CONFIG", "LOW", []),
                    }

                    service_info = ua_services.get(service_id,
                        (f"Service_{service_id}", "UNKNOWN", "MEDIUM", []))
                    service_name, op_type, risk, service_mitre = service_info
                    func_name = f"MSG -> {service_name}"
                    mitre.extend(service_mitre)

                    notes_extra = f"ServiceId={service_id}, SecureChannel={secure_channel_id}"

            ent = entropy(payload[8:]) if len(payload) > 8 else 0.0
            threat_score = ProtocolParser._calculate_threat_score(risk)

            # Increase threat for write/call operations
            if service_id in [668, 706]:  # WriteRequest, CallRequest
                threat_score = min(threat_score + 0.2, 1.0)

            key = (src_ip, dst_ip, service_id or hash(msg_type))
            time_since_last, payload_change_rate = ProtocolParser._get_time_features(key, ts, payload, 8)

            return OTEvent(
                timestamp=ts, src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=dst_port,
                protocol=OTProtocol.OPC_UA, function_code=service_id,
                function_name=func_name, operation_type=op_type, risk_level=risk,
                raw_data=payload[:min(64, len(payload))],
                notes=f"MsgType={msg_type}, Size={msg_size}" + (f", {notes_extra}" if notes_extra else ""),
                mitre_techniques=list(set(mitre)), threat_score=threat_score,
                payload_entropy=ent, sequence_id=seq_id,
                time_since_last_packet=time_since_last,
                payload_change_rate=payload_change_rate
            )
        except Exception as e:
            logger.debug(f"OPC UA parse error: {e}")
            return None


# =============================================================================
# HTTP STREAM DECODER MODULE
# =============================================================================
# This module provides:
# 1. TCP Stream Reassembly - Handle retransmissions, correct packet ordering
# 2. HTTP Message Reconstruction - Parse header+body, support chunked encoding
# 3. Content Decode - gzip, deflate, base64, url-encode, hex, multi-layer
# 4. Payload Extraction - Extract suspicious content with decode explanation
# =============================================================================

import zlib
import base64
import binascii
import hashlib
import re
from urllib.parse import unquote
from dataclasses import dataclass, field
from typing import List

# Try to import brotli (optional)
try:
    import brotli
    HAS_BROTLI = True
except ImportError:
    HAS_BROTLI = False


class ContentDecoder:
    """
    Multi-layer content decoder for HTTP payloads.

    Supports:
    - Compression: gzip, deflate, brotli
    - Encoding: base64, hex, url-encode
    - Multi-layer decode with step-by-step explanation

    Example usage:
        decoder = ContentDecoder()
        result = decoder.decode_multilayer(payload)
        print(result['final_payload'])
        for step in result['steps']:
            print(f"Layer {step['layer']}: {step['encoding']}")
    """

    # Encoding detection patterns
    BASE64_PATTERN = re.compile(rb'^[A-Za-z0-9+/=]{20,}$')
    HEX_PATTERN = re.compile(rb'^[0-9a-fA-F]{20,}$')
    URL_ENCODED_PATTERN = re.compile(rb'%[0-9a-fA-F]{2}')

    # Gzip magic bytes
    GZIP_MAGIC = b'\x1f\x8b'
    # Zlib header (deflate)
    ZLIB_HEADERS = [b'\x78\x01', b'\x78\x5e', b'\x78\x9c', b'\x78\xda']
    # Brotli magic (less reliable)
    BROTLI_MAGIC = b'\xce\xb2\xcf\x81'

    def __init__(self, max_layers: int = 5, max_output_size: int = 10 * 1024 * 1024):
        """
        Initialize decoder.

        Args:
            max_layers: Maximum decode layers (default 5, prevents infinite loops)
            max_output_size: Maximum output size in bytes (default 10MB)
        """
        self.max_layers = max_layers
        self.max_output_size = max_output_size

    def decode_gzip(self, data: bytes) -> tuple:
        """
        Decode gzip compressed data.

        Returns:
            (decoded_bytes, success, error_message)
        """
        try:
            decoded = zlib.decompress(data, 16 + zlib.MAX_WBITS)
            if len(decoded) > self.max_output_size:
                return decoded[:self.max_output_size], True, "truncated"
            return decoded, True, ""
        except Exception as e:
            return data, False, str(e)

    def decode_deflate(self, data: bytes) -> tuple:
        """
        Decode deflate compressed data.

        Returns:
            (decoded_bytes, success, error_message)
        """
        try:
            # Try with header
            decoded = zlib.decompress(data)
            if len(decoded) > self.max_output_size:
                return decoded[:self.max_output_size], True, "truncated"
            return decoded, True, ""
        except (zlib.error, ValueError) as e:
            try:
                # Try raw deflate
                decoded = zlib.decompress(data, -zlib.MAX_WBITS)
                if len(decoded) > self.max_output_size:
                    return decoded[:self.max_output_size], True, "truncated"
                return decoded, True, ""
            except Exception as e:
                return data, False, str(e)

    def decode_brotli(self, data: bytes) -> tuple:
        """
        Decode brotli compressed data.

        Returns:
            (decoded_bytes, success, error_message)
        """
        if not HAS_BROTLI:
            return data, False, "brotli not installed"
        try:
            decoded = brotli.decompress(data)
            if len(decoded) > self.max_output_size:
                return decoded[:self.max_output_size], True, "truncated"
            return decoded, True, ""
        except Exception as e:
            return data, False, str(e)

    def decode_base64(self, data: bytes) -> tuple:
        """
        Decode base64 encoded data.

        Returns:
            (decoded_bytes, success, error_message)
        """
        try:
            # Clean whitespace
            cleaned = data.replace(b'\n', b'').replace(b'\r', b'').replace(b' ', b'')

            # Add padding if needed
            missing_padding = len(cleaned) % 4
            if missing_padding:
                cleaned += b'=' * (4 - missing_padding)

            decoded = base64.b64decode(cleaned, validate=True)
            return decoded, True, ""
        except Exception as e:
            # Try URL-safe base64
            try:
                decoded = base64.urlsafe_b64decode(cleaned)
                return decoded, True, ""
            except (ValueError, binascii.Error):
                return data, False, str(e)

    def decode_hex(self, data: bytes) -> tuple:
        """
        Decode hex encoded data.

        Returns:
            (decoded_bytes, success, error_message)
        """
        try:
            # Remove common prefixes
            text = data.decode('ascii', errors='ignore')
            text = text.replace('0x', '').replace('\\x', '').replace(' ', '')
            decoded = binascii.unhexlify(text)
            return decoded, True, ""
        except Exception as e:
            return data, False, str(e)

    def decode_url(self, data: bytes) -> tuple:
        """
        Decode URL encoded data.

        Returns:
            (decoded_bytes, success, error_message)
        """
        try:
            text = data.decode('utf-8', errors='replace')
            decoded = unquote(text).encode('utf-8')
            return decoded, True, ""
        except Exception as e:
            return data, False, str(e)

    def detect_encoding(self, data: bytes) -> str:
        """
        Detect encoding type of data.

        Returns:
            Encoding type: "gzip", "deflate", "brotli", "base64", "hex", "url", or "none"
        """
        if len(data) < 2:
            return "none"

        # Check compression magic bytes first
        if data[:2] == self.GZIP_MAGIC:
            return "gzip"

        if data[:2] in self.ZLIB_HEADERS:
            return "deflate"

        if HAS_BROTLI and len(data) >= 4 and data[:4] == self.BROTLI_MAGIC:
            return "brotli"

        # Check for URL encoding
        if self.URL_ENCODED_PATTERN.search(data):
            # Count URL-encoded chars
            url_count = len(self.URL_ENCODED_PATTERN.findall(data))
            if url_count >= 5 or url_count / max(len(data), 1) > 0.1:
                return "url"

        # Check for hex first: every hex string also matches the base64 alphabet
        try:
            text = data.strip()
            if len(text) >= 20 and len(text) % 2 == 0 and self.HEX_PATTERN.match(text):
                return "hex"
        except (AttributeError, TypeError) as e:
            logger.debug(f"Hex pattern check error: {e}")

        # Check for base64
        try:
            text = data.strip()
            if len(text) >= 20 and self.BASE64_PATTERN.match(text):
                return "base64"
        except (AttributeError, TypeError) as e:
            logger.debug(f"Base64 pattern check error: {e}")


        return "none"

    def decode_single(self, data: bytes, encoding: str) -> tuple:
        """
        Decode data with specified encoding.

        Args:
            data: Input bytes
            encoding: Encoding type

        Returns:
            (decoded_bytes, success, error_message)
        """
        decoders = {
            "gzip": self.decode_gzip,
            "deflate": self.decode_deflate,
            "brotli": self.decode_brotli,
            "base64": self.decode_base64,
            "hex": self.decode_hex,
            "url": self.decode_url,
        }

        decoder = decoders.get(encoding)
        if decoder:
            return decoder(data)
        return data, False, f"Unknown encoding: {encoding}"

    def decode_multilayer(self, data: bytes, forced_encodings: List[str] = None) -> dict:
        """
        Decode data through multiple layers.

        Args:
            data: Input bytes
            forced_encodings: Optional list of encodings to try in order

        Returns:
            dict with keys:
            - final_payload: Final decoded bytes
            - steps: List of decode steps
            - success: Whether any decoding was successful
            - total_layers: Number of decode layers applied
        """
        steps = []
        current_data = data
        layer = 0

        if forced_encodings:
            # Use forced encoding order
            for encoding in forced_encodings:
                if layer >= self.max_layers:
                    break

                layer += 1
                input_preview = current_data[:100].decode('utf-8', errors='replace')
                input_size = len(current_data)

                decoded, success, error = self.decode_single(current_data, encoding)

                output_preview = decoded[:100].decode('utf-8', errors='replace')

                steps.append({
                    'layer': layer,
                    'encoding': encoding,
                    'input_preview': input_preview,
                    'output_preview': output_preview,
                    'input_size': input_size,
                    'output_size': len(decoded),
                    'success': success,
                    'error': error,
                })

                if success and decoded != current_data:
                    current_data = decoded
                else:
                    break
        else:
            # Auto-detect encoding layers
            while layer < self.max_layers:
                encoding = self.detect_encoding(current_data)
                if encoding == "none":
                    break

                layer += 1
                input_preview = current_data[:100].decode('utf-8', errors='replace')
                input_size = len(current_data)

                decoded, success, error = self.decode_single(current_data, encoding)

                output_preview = decoded[:100].decode('utf-8', errors='replace')

                steps.append({
                    'layer': layer,
                    'encoding': encoding,
                    'input_preview': input_preview,
                    'output_preview': output_preview,
                    'input_size': input_size,
                    'output_size': len(decoded),
                    'success': success,
                    'error': error,
                })

                if success and decoded != current_data:
                    current_data = decoded
                else:
                    break

        return {
            'final_payload': current_data,
            'steps': steps,
            'success': len(steps) > 0 and any(s['success'] for s in steps),
            'total_layers': layer,
        }


class TCPStreamReassembler:
    """
    TCP Stream Reassembler for reconstructing HTTP sessions.

    Features:
    - Correct packet ordering by sequence number
    - Handle retransmissions (detect and skip duplicates)
    - Handle out-of-order packets
    - Detect missing segments

    Usage:
        reassembler = TCPStreamReassembler()
        reassembler.add_segment(seq=1000, data=b"GET /...")
        reassembler.add_segment(seq=1500, data=b"Host: ...")
        stream_data = reassembler.get_stream()
    """

    def __init__(self, max_segments: int = 10000, max_stream_size: int = 50 * 1024 * 1024):
        """
        Initialize reassembler.

        Args:
            max_segments: Maximum segments to track (default 10000)
            max_stream_size: Maximum stream size in bytes (default 50MB)
        """
        self.max_segments = max_segments
        self.max_stream_size = max_stream_size

        # Segment storage: {seq_num: (data, timestamp)}
        self.segments: Dict[int, tuple] = {}

        # Stream metadata
        self.start_time = 0.0
        self.end_time = 0.0
        self.initial_seq = None
        self.expected_seq = None

        # Statistics
        self.total_segments = 0
        self.retransmissions = 0
        self.out_of_order = 0

        # Cached result of get_stream(): it is called for every packet of a
        # session, and rebuilding the stream each time was O(n^2) per session.
        self._stream_cache: Optional[bytes] = None
        self.byte_count = 0  # payload bytes accepted (cheap stream length estimate)

    def add_segment(self, seq: int, data: bytes, ts: float, flags: int = 0) -> bool:
        """
        Add a TCP segment to the reassembler.

        Args:
            seq: TCP sequence number
            data: Segment payload
            ts: Timestamp
            flags: TCP flags (for SYN/FIN detection)

        Returns:
            True if segment was added, False if duplicate/overflow
        """
        # Initialize on first segment
        if self.initial_seq is None:
            self.initial_seq = seq
            self.expected_seq = seq
            self.start_time = ts

        self.end_time = max(self.end_time, ts)
        self.total_segments += 1

        # Check for overflow
        if len(self.segments) >= self.max_segments:
            logger.warning("TCP reassembler: max segments reached")
            return False

        # Check for retransmission
        if seq in self.segments:
            self.retransmissions += 1
            return False

        # Check for out-of-order
        if seq != self.expected_seq:
            self.out_of_order += 1

        # Add segment
        self.segments[seq] = (data, ts)
        self._stream_cache = None
        self.byte_count += len(data)

        # Update expected sequence
        if data:
            next_seq = seq + len(data)
            if next_seq > self.expected_seq:
                self.expected_seq = next_seq

        return True

    def get_stream(self) -> bytes:
        """
        Get reassembled stream data.

        Returns:
            Reassembled bytes in correct order
        """
        if not self.segments:
            return b""
        if self._stream_cache is not None:
            return self._stream_cache

        # Sort by sequence number
        sorted_seqs = sorted(self.segments.keys())
        result = bytearray()
        expected = sorted_seqs[0]

        for seq in sorted_seqs:
            data, ts = self.segments[seq]

            # Handle gaps (missing data)
            if seq > expected:
                gap = seq - expected
                # Fill with placeholder (or skip)
                logger.debug(f"TCP gap: {gap} bytes missing at seq {expected}")

            # Add data
            if data:
                # Fully contained in data we already have (retransmitted overlap)
                if seq < expected and seq + len(data) <= expected:
                    continue
                # Handle overlap (partial retransmission)
                if seq < expected and seq + len(data) > expected:
                    offset = expected - seq
                    data = data[offset:]

                if len(result) + len(data) > self.max_stream_size:
                    logger.warning("TCP reassembler: max stream size reached")
                    break

                result.extend(data)
                expected = seq + len(data)

        self._stream_cache = bytes(result)
        return self._stream_cache

    def get_stats(self) -> dict:
        """Get reassembly statistics."""
        missing = 0
        if self.segments:
            sorted_seqs = sorted(self.segments.keys())
            expected = sorted_seqs[0]
            for seq in sorted_seqs:
                if seq > expected:
                    missing += 1
                data, _ = self.segments[seq]
                expected = seq + len(data) if data else expected

        return {
            'total_segments': self.total_segments,
            'retransmissions': self.retransmissions,
            'out_of_order': self.out_of_order,
            'missing_segments': missing,
            'stream_size': sum(len(d) for d, _ in self.segments.values()),
        }

    def clear(self):
        """Clear all stored segments."""
        self.segments.clear()
        self.initial_seq = None
        self.expected_seq = None
        self.total_segments = 0
        self.retransmissions = 0
        self.out_of_order = 0
        self._stream_cache = None
        self.byte_count = 0


class HTTPStreamDecoder:
    """
    HTTP Stream Decoder for reconstructing and decoding HTTP messages.

    Features:
    - Parse HTTP request/response headers
    - Handle Transfer-Encoding: chunked
    - Handle Content-Encoding: gzip, deflate, br
    - Multi-layer payload decoding
    - Suspicious payload extraction with explanation

    Usage:
        decoder = HTTPStreamDecoder()
        result = decoder.decode_stream(raw_http_data)
        print(result['method'], result['uri'])
        print(result['body_decoded'])
    """

    # HTTP line patterns
    REQUEST_LINE_PATTERN = re.compile(rb'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s+(\S+)\s+HTTP/(\d\.\d)')
    RESPONSE_LINE_PATTERN = re.compile(rb'^HTTP/(\d\.\d)\s+(\d{3})\s*(.*)')
    HEADER_PATTERN = re.compile(rb'^([^:]+):\s*(.*)$')

    def __init__(self):
        self.content_decoder = ContentDecoder()

    def decode_chunked(self, data: bytes) -> tuple:
        """
        Decode chunked transfer encoding.

        Args:
            data: Chunked encoded body

        Returns:
            (decoded_bytes, success, error_message)
        """
        try:
            result = bytearray()
            offset = 0

            while offset < len(data):
                # Find chunk size line
                line_end = data.find(b'\r\n', offset)
                if line_end == -1:
                    break

                # Parse chunk size (hex)
                chunk_line = data[offset:line_end]
                # Handle chunk extensions (;name=value)
                if b';' in chunk_line:
                    chunk_line = chunk_line.split(b';')[0]

                try:
                    chunk_size = int(chunk_line.strip(), 16)
                except ValueError:
                    break

                # End of chunks
                if chunk_size == 0:
                    break

                # Extract chunk data
                data_start = line_end + 2
                data_end = data_start + chunk_size

                if data_end > len(data):
                    # Incomplete chunk
                    break

                result.extend(data[data_start:data_end])
                offset = data_end + 2  # Skip trailing CRLF

            return bytes(result), True, ""

        except Exception as e:
            return data, False, str(e)

    def parse_headers(self, header_data: bytes) -> dict:
        """
        Parse HTTP headers.

        Args:
            header_data: Raw header bytes (excluding request/status line)

        Returns:
            Dict of headers (lowercase keys)
        """
        headers = {}
        lines = header_data.split(b'\r\n')

        for line in lines:
            if not line:
                continue
            match = self.HEADER_PATTERN.match(line)
            if match:
                key = match.group(1).decode('utf-8', errors='replace').strip().lower()
                value = match.group(2).decode('utf-8', errors='replace').strip()
                headers[key] = value

        return headers

    def decode_stream(self, data: bytes, src_ip: str = "", dst_ip: str = "",
                      src_port: int = 0, dst_port: int = 0, ts: float = 0.0) -> dict:
        """
        Decode HTTP stream data.

        Args:
            data: Raw HTTP data (headers + body)
            src_ip, dst_ip, src_port, dst_port: Connection info
            ts: Timestamp

        Returns:
            Dict with parsed HTTP message and decoded body
        """
        result = {
            'timestamp': ts,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'type': 'unknown',  # 'request' or 'response'
            'method': '',
            'uri': '',
            'http_version': '',
            'status_code': 0,
            'status_text': '',
            'headers': {},
            'headers_raw': b'',
            'body_raw': b'',
            'body_decoded': b'',
            'body_final': b'',
            'content_length': 0,
            'is_chunked': False,
            'content_encoding': '',
            'decode_steps': [],
            'decode_success': False,
            'parse_error': '',
        }

        try:
            # Find header/body boundary
            header_end = data.find(b'\r\n\r\n')
            if header_end == -1:
                # Try single newline
                header_end = data.find(b'\n\n')
                if header_end == -1:
                    result['parse_error'] = "No header/body boundary found"
                    return result
                boundary_len = 2
            else:
                boundary_len = 4

            header_data = data[:header_end]
            body_data = data[header_end + boundary_len:]

            # Parse first line
            first_line_end = header_data.find(b'\r\n')
            if first_line_end == -1:
                first_line_end = header_data.find(b'\n')
            if first_line_end == -1:
                first_line_end = len(header_data)

            first_line = header_data[:first_line_end]
            remaining_headers = header_data[first_line_end:].lstrip(b'\r\n')

            # Check if request or response
            req_match = self.REQUEST_LINE_PATTERN.match(first_line)
            resp_match = self.RESPONSE_LINE_PATTERN.match(first_line)

            if req_match:
                result['type'] = 'request'
                result['method'] = req_match.group(1).decode('ascii')
                result['uri'] = req_match.group(2).decode('utf-8', errors='replace')
                result['http_version'] = req_match.group(3).decode('ascii')
            elif resp_match:
                result['type'] = 'response'
                result['http_version'] = resp_match.group(1).decode('ascii')
                result['status_code'] = int(resp_match.group(2))
                result['status_text'] = resp_match.group(3).decode('utf-8', errors='replace')
            else:
                result['parse_error'] = "Invalid HTTP first line"
                return result

            # Parse headers
            result['headers'] = self.parse_headers(remaining_headers)
            result['headers_raw'] = header_data

            # Get relevant headers
            content_length = result['headers'].get('content-length', '')
            transfer_encoding = result['headers'].get('transfer-encoding', '').lower()
            content_encoding = result['headers'].get('content-encoding', '').lower()

            result['content_encoding'] = content_encoding
            result['is_chunked'] = 'chunked' in transfer_encoding

            if content_length.isdigit():
                result['content_length'] = int(content_length)

            # Store raw body
            result['body_raw'] = body_data

            # Decode chunked encoding
            current_body = body_data
            if result['is_chunked']:
                decoded, success, error = self.decode_chunked(body_data)
                if success:
                    result['decode_steps'].append({
                        'layer': 1,
                        'encoding': 'chunked',
                        'input_size': len(body_data),
                        'output_size': len(decoded),
                        'success': True,
                        'error': '',
                    })
                    current_body = decoded
                else:
                    result['decode_steps'].append({
                        'layer': 1,
                        'encoding': 'chunked',
                        'input_size': len(body_data),
                        'output_size': len(body_data),
                        'success': False,
                        'error': error,
                    })

            result['body_decoded'] = current_body

            # Decode content encoding
            if content_encoding:
                decode_result = self.content_decoder.decode_multilayer(
                    current_body,
                    forced_encodings=[content_encoding]
                )
                if decode_result['success']:
                    current_body = decode_result['final_payload']
                    for step in decode_result['steps']:
                        step['layer'] += len(result['decode_steps'])
                        result['decode_steps'].append(step)

            # Try additional auto-decode (base64, etc.)
            auto_decode = self.content_decoder.decode_multilayer(current_body)
            if auto_decode['success']:
                current_body = auto_decode['final_payload']
                for step in auto_decode['steps']:
                    step['layer'] += len(result['decode_steps'])
                    result['decode_steps'].append(step)

            result['body_final'] = current_body
            result['decode_success'] = len(result['decode_steps']) > 0

        except Exception as e:
            result['parse_error'] = str(e)

        return result

    def extract_payload_with_explanation(self, http_result: dict) -> dict:
        """
        Extract suspicious payload with full decode explanation.

        Args:
            http_result: Result from decode_stream()

        Returns:
            Dict with payload info and explanation
        """
        body = http_result.get('body_final', b'')
        if not body:
            body = http_result.get('body_decoded', b'')
        if not body:
            body = http_result.get('body_raw', b'')

        # Generate SHA256 hash
        sha256_hash = hashlib.sha256(body).hexdigest() if body else ""

        # Build decode explanation
        decode_explanation = []
        for step in http_result.get('decode_steps', []):
            if step.get('success'):
                decode_explanation.append(
                    f"Layer {step['layer']}: {step['encoding']} ({step['input_size']} -> {step['output_size']} bytes)"
                )

        # Detect payload type
        detected_type = "UNKNOWN"
        detection_patterns = []
        risk_level = "LOW"

        body_text = body.decode('utf-8', errors='replace') if body else ""

        # Check for webshell patterns
        webshell_patterns = [
            (r'eval\s*\(', 'WEBSHELL_EVAL'),
            (r'exec\s*\(', 'WEBSHELL_EXEC'),
            (r'system\s*\(', 'WEBSHELL_SYSTEM'),
            (r'passthru\s*\(', 'WEBSHELL_PASSTHRU'),
            (r'shell_exec\s*\(', 'WEBSHELL_SHELLEXEC'),
            (r'base64_decode\s*\(', 'OBFUSCATION_BASE64'),
            (r'Runtime\.getRuntime\(\)\.exec', 'WEBSHELL_JSP'),
            (r'Process\.Start', 'WEBSHELL_ASPX'),
            (r'cmd\.exe', 'WEBSHELL_CMD'),
            (r'powershell', 'WEBSHELL_POWERSHELL'),
            (r'/bin/bash', 'WEBSHELL_BASH'),
        ]

        for pattern, name in webshell_patterns:
            if cached_regex(pattern, re.IGNORECASE).search(body_text):
                detection_patterns.append(name)
                detected_type = "WEBSHELL"
                risk_level = "CRITICAL"

        # Check for script content
        if detected_type == "UNKNOWN":
            if re.search(r'<\?php', body_text, re.IGNORECASE):
                detected_type = "PHP_SCRIPT"
                risk_level = "HIGH"
            elif re.search(r'<%.*%>', body_text):
                detected_type = "JSP_SCRIPT"
                risk_level = "HIGH"
            elif re.search(r'<script', body_text, re.IGNORECASE):
                detected_type = "JAVASCRIPT"
                risk_level = "MEDIUM"

        # Check for binary
        if detected_type == "UNKNOWN" and body:
            if body[:4] == b'\x7fELF':
                detected_type = "ELF_BINARY"
                risk_level = "CRITICAL"
            elif body[:2] == b'MZ':
                detected_type = "PE_BINARY"
                risk_level = "CRITICAL"

        # Build behavior summary
        behavior_summary = ""

        if detected_type == "WEBSHELL":
            behavior_summary = f"Detected webshell payload with {len(detection_patterns)} execution patterns. "
            if decode_explanation:
                behavior_summary += f"Payload was decoded through {len(decode_explanation)} layers: {', '.join(decode_explanation)}."

        elif detected_type in ["ELF_BINARY", "PE_BINARY"]:
            behavior_summary = f"Detected {detected_type} executable binary in HTTP payload."

        elif detected_type in ["PHP_SCRIPT", "JSP_SCRIPT"]:
            behavior_summary = f"Detected server-side script ({detected_type}) in HTTP payload."

        return {
            'timestamp': http_result.get('timestamp', 0),
            'src_ip': http_result.get('src_ip', ''),
            'dst_ip': http_result.get('dst_ip', ''),
            'src_port': http_result.get('src_port', 0),
            'dst_port': http_result.get('dst_port', 0),
            'http_method': http_result.get('method', ''),
            'http_uri': http_result.get('uri', ''),
            'content_type': http_result.get('headers', {}).get('content-type', ''),
            'raw_payload': http_result.get('body_raw', b''),
            'raw_size': len(http_result.get('body_raw', b'')),
            'raw_preview': http_result.get('body_raw', b'')[:200].decode('utf-8', errors='replace'),
            'final_payload': body,
            'final_size': len(body),
            'final_preview': body[:200].decode('utf-8', errors='replace') if body else '',
            'decode_steps': http_result.get('decode_steps', []),
            'total_layers': len(http_result.get('decode_steps', [])),
            'detected_type': detected_type,
            'detection_patterns': detection_patterns,
            'risk_level': risk_level,
            'sha256_hash': sha256_hash,
            'behavior_summary': behavior_summary,
            'decode_explanation': decode_explanation,
        }


class HTTPSessionTracker:
    """
    Track and reassemble HTTP sessions from TCP packets.

    This class manages multiple concurrent HTTP sessions,
    reassembling TCP streams and decoding HTTP messages.

    Enhanced: Tracks HTTP message completion for proper multi-packet analysis.

    Usage:
        tracker = HTTPSessionTracker()
        tracker.add_packet(src_ip, dst_ip, src_port, dst_port, seq, data, ts)
        sessions = tracker.get_complete_sessions()
    """

    def __init__(self, session_timeout: float = 300.0):
        """
        Initialize tracker.

        Args:
            session_timeout: Session timeout in seconds (default 5 minutes)
        """
        self.session_timeout = session_timeout
        self.sessions: Dict[str, dict] = {}  # session_id -> session data
        self.decoder = HTTPStreamDecoder()
        self.analyzed_sessions: set = set()  # Track already analyzed sessions

    def _make_session_id(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> str:
        """Generate unique session ID."""
        return f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"

    def add_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                   seq: int, data: bytes, ts: float, tcp_flags: int = 0) -> bool:
        """
        Add a TCP packet to the appropriate session.

        Args:
            src_ip, dst_ip: IP addresses
            src_port, dst_port: Ports
            seq: TCP sequence number
            data: TCP payload
            ts: Timestamp
            tcp_flags: TCP flags

        Returns:
            True if packet was added successfully
        """
        session_id = self._make_session_id(src_ip, dst_ip, src_port, dst_port)

        if session_id not in self.sessions:
            self.sessions[session_id] = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'reassembler': TCPStreamReassembler(),
                'start_time': ts,
                'last_time': ts,
                'complete': False,
                'http_parsed': False,
                'content_length': -1,  # -1 = unknown
                'headers_received': False,
                'body_received_bytes': 0,
                'is_chunked': False,
                'chunked_complete': False,
                'http_method': '',  # Track HTTP method for bodyless request detection
            }

        session = self.sessions[session_id]
        session['last_time'] = ts

        # Add to reassembler
        result = session['reassembler'].add_segment(seq, data, ts, tcp_flags)
        session['tail'] = (session.get('tail', b'') + data)[-32:]

        # Give up looking for HTTP headers in long non-HTTP streams: rebuilding
        # the stream for every packet would be O(n^2).
        if not session['headers_received'] and session['reassembler'].byte_count > 64 * 1024:
            return result

        # Check if HTTP headers are complete to track body progress
        if not session['headers_received']:
            raw_data = session['reassembler'].get_stream()
            header_end = raw_data.find(b'\r\n\r\n')
            if header_end == -1:
                header_end = raw_data.find(b'\n\n')

            if header_end > 0:
                session['headers_received'] = True
                header_part = raw_data[:header_end]
                sep_len = 4 if raw_data[header_end:header_end + 4] == b'\r\n\r\n' else 2
                session['body_start'] = header_end + sep_len

                # Extract HTTP method from request line (e.g. "GET /path HTTP/1.1")
                request_line_end = header_part.find(b'\r\n')
                if request_line_end == -1:
                    request_line_end = header_part.find(b'\n')
                if request_line_end > 0:
                    request_line = header_part[:request_line_end].decode('ascii', errors='replace')
                    parts = request_line.split(' ', 2)
                    # Responses start with "HTTP/x.y": they have no method
                    if len(parts) >= 2 and not parts[0].upper().startswith('HTTP/'):
                        session['http_method'] = parts[0].upper()

                # Parse Content-Length
                cl_match = re.search(rb'content-length:\s*(\d+)', header_part, re.IGNORECASE)
                if cl_match:
                    session['content_length'] = int(cl_match.group(1))

                # Check for chunked encoding
                if b'transfer-encoding:' in header_part.lower():
                    if b'chunked' in header_part.lower():
                        session['is_chunked'] = True

        # Update body received tracking (O(1): no stream rebuild per packet)
        if session['headers_received']:
            body_start = session.get('body_start', 0)
            if body_start > 0:
                session['body_received_bytes'] = max(0, session['reassembler'].byte_count - body_start)

        return result

    def is_http_complete(self, session_id: str) -> bool:
        """
        Check if HTTP message is complete (headers + full body received).

        Handles bodyless requests (GET, HEAD, OPTIONS, DELETE without Content-Length)
        and response messages properly.

        Returns:
            True if message is complete and ready for analysis
        """
        if session_id not in self.sessions:
            return False

        session = self.sessions[session_id]

        if not session['headers_received']:
            return False

        # HTTP methods that typically have NO body (RFC 7230/7231)
        # If method is known and doesn't have Content-Length or Transfer-Encoding,
        # the message is complete once headers are received
        bodyless_methods = {'GET', 'HEAD', 'OPTIONS', 'DELETE', 'CONNECT', 'TRACE'}
        method = session.get('http_method', '')

        if method in bodyless_methods and session['content_length'] < 0 and not session['is_chunked']:
            # Bodyless request - complete as soon as headers are received
            return True

        # HTTP responses: check if it's a response (starts with HTTP/)
        # Responses to HEAD, 1xx, 204, 304 have no body
        if not method and session['content_length'] < 0 and not session['is_chunked']:
            raw_data = session['reassembler'].get_stream()
            if raw_data[:5] in (b'HTTP/', b'http/'):
                # Response without Content-Length or chunked - check for known no-body codes
                status_match = re.search(rb'HTTP/\d\.\d\s+(\d{3})', raw_data[:50])
                if status_match:
                    status_code = int(status_match.group(1))
                    if status_code < 200 or status_code in (204, 304):
                        return True
                # Response with body but no Content-Length - consider complete
                # if we've received some body data
                if session['body_received_bytes'] > 0:
                    return True

        # Check chunked encoding completion
        if session['is_chunked']:
            # Chunked ends with the last-chunk line "0\r\n" followed by an empty
            # line (or trailers). Require the zero to start a line: a chunk-size
            # line such as "10\r\n" must not be mistaken for the terminator.
            tail = session.get('tail', b'')
            return bool(re.search(rb'(?:^|\r?\n)0+(?:;[^\r\n]*)?\r?\n(?:[^\r\n]+\r?\n)*\r?\n$', tail))

        # Check Content-Length based completion
        if session['content_length'] >= 0:
            return session['body_received_bytes'] >= session['content_length']

        # No Content-Length header - use heuristics
        # Consider complete after receiving any body data
        if session['body_received_bytes'] > 0:
            return True

        return False

    def get_session_data(self, session_id: str) -> dict:
        """
        Get decoded HTTP data for a session.

        Args:
            session_id: Session identifier

        Returns:
            Decoded HTTP message dict
        """
        if session_id not in self.sessions:
            return {}

        session = self.sessions[session_id]
        raw_data = session['reassembler'].get_stream()

        if not raw_data:
            return {}

        result = self.decoder.decode_stream(
            raw_data,
            src_ip=session['src_ip'],
            dst_ip=session['dst_ip'],
            src_port=session['src_port'],
            dst_port=session['dst_port'],
            ts=session['start_time'],
        )

        # Add completion status
        result['is_complete'] = self.is_http_complete(session_id)
        result['body_received_bytes'] = session['body_received_bytes']
        result['content_length_expected'] = session['content_length']

        return result

    def get_complete_sessions_for_analysis(self) -> List[str]:
        """
        Get session IDs that are complete and haven't been analyzed yet.

        Returns:
            List of session IDs ready for analysis
        """
        ready = []
        for session_id in self.sessions:
            if session_id not in self.analyzed_sessions:
                if self.is_http_complete(session_id):
                    ready.append(session_id)
        return ready

    def mark_analyzed(self, session_id: str):
        """Mark a session as analyzed to avoid re-processing."""
        self.analyzed_sessions.add(session_id)

    def get_all_sessions(self) -> List[dict]:
        """Get decoded data for all sessions."""
        results = []
        for session_id in self.sessions:
            data = self.get_session_data(session_id)
            if data and data.get('type') in ['request', 'response']:
                data['session_id'] = session_id
                stats = self.sessions[session_id]['reassembler'].get_stats()
                data['tcp_stats'] = stats
                results.append(data)
        return results

    def cleanup_old_sessions(self, current_time: float):
        """Remove sessions that have timed out."""
        to_remove = []
        for session_id, session in self.sessions.items():
            if current_time - session['last_time'] > self.session_timeout:
                to_remove.append(session_id)

        for session_id in to_remove:
            del self.sessions[session_id]
            self.analyzed_sessions.discard(session_id)

    def clear(self):
        """Clear all sessions."""
        self.sessions.clear()
        self.analyzed_sessions.clear()
