"""
Shared helpers for OT protocol decoders.

Every decoder returns an :class:`~ot_pcap_analyzer.models.OTEvent` (or ``None``
when the bytes are not that protocol). Besides the classic fields, decoders
fill ``event.details`` with a small, protocol-independent vocabulary so that
the detection rules can reason about *what happened* without knowing every
protocol:

``op``          canonical operation, one of :data:`OPS` (e.g. ``"PLC_STOP"``)
``is_request``  True for client→device requests, False for responses, None if unknown
``target``      human-readable object acted on (``"CA=1 IOA=4001"``, ``"DB1"``, ``"D100"``)
``value``       numeric value written / commanded, when known
``count``       number of items (registers, objects, IOAs) touched
``station``     device / station identifier when the protocol has one

Protocol-specific keys may be added freely (``goose_st_num``, ``s7_block`` …);
document them in the decoder module.
"""
from typing import Any, Dict, List, Optional

from ..constants import OTProtocol
from ..models import OTEvent
from ..utils import entropy

# Canonical operations understood by the protocol rule engine
OPS = frozenset({
    # device / program state
    "PLC_STOP", "PLC_START", "PLC_PAUSE", "PLC_RESET", "RESTART", "PROGRAM_DOWNLOAD",
    "PROGRAM_UPLOAD", "PROGRAM_DELETE", "FIRMWARE_UPDATE", "MEMORY_CLEAR",
    # process control
    "CONTROL_SELECT", "CONTROL_EXECUTE", "CONTROL_DIRECT", "CONTROL_CANCEL", "SETPOINT",
    "WRITE", "READ", "FORCE",
    # configuration / maintenance
    "CONFIG_WRITE", "CLOCK_SET", "SET_IP", "SET_NAME", "FACTORY_RESET", "PASSWORD",
    "FILE_READ", "FILE_WRITE", "FILE_DELETE", "DIAG_LISTEN_ONLY", "LOG_CLEAR",
    "UNSOLICITED_DISABLE", "TRANSMISSION_OFF",
    # discovery / sessions
    "IDENTIFY", "INTERROGATION", "BROWSE", "SESSION_START", "SESSION_STOP", "KEEPALIVE",
    # streaming / publish-subscribe
    "PUBLISH", "ALARM", "STATUS", "RESPONSE", "ERROR", "OTHER",
})

RISK_THREAT = {"CRITICAL": 0.9, "HIGH": 0.7, "MEDIUM": 0.4, "LOW": 0.15}


def make_event(*, ts: float, src: str, dst: str, sport: int, dport: int,
               protocol: OTProtocol, code: int, name: str, op_type: str, risk: str,
               payload: bytes, seq_id: int = 0, notes: str = "",
               mitre: Optional[List[str]] = None, details: Optional[Dict[str, Any]] = None,
               unit_id: int = 0, address: int = 0, count: int = 0) -> OTEvent:
    """Build an OTEvent with consistent defaults (entropy, threat score, raw bytes)."""
    details = dict(details or {})
    if count and "count" not in details:
        details["count"] = count
    return OTEvent(
        timestamp=ts, src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport,
        protocol=protocol, function_code=int(code), function_name=name,
        operation_type=op_type, risk_level=risk, unit_id=unit_id,
        data_address=address, data_count=count,
        raw_data=bytes(payload[:64]), notes=notes,
        mitre_techniques=list(mitre or []),
        threat_score=RISK_THREAT.get(risk, 0.3),
        payload_entropy=entropy(payload) if payload else 0.0,
        sequence_id=seq_id, details=details,
    )


# ---------------------------------------------------------------- BER / ASN.1

def ber_read_tlv(buf: bytes, pos: int):
    """Read one BER TLV at ``pos`` -> (tag, value_start, value_end) or None.

    Supports single-byte and multi-byte (high-tag-number) tags and short/long
    definite lengths up to 4 bytes. Never reads past ``buf``.
    """
    n = len(buf)
    if pos >= n:
        return None
    tag = buf[pos]
    pos += 1
    if tag & 0x1F == 0x1F:                     # high tag number form
        tag_bytes = [tag]
        while pos < n:
            b = buf[pos]
            pos += 1
            tag_bytes.append(b)
            if not b & 0x80 or len(tag_bytes) > 4:
                break
        tag = int.from_bytes(bytes(tag_bytes), "big")
    if pos >= n:
        return None
    length = buf[pos]
    pos += 1
    if length & 0x80:
        nbytes = length & 0x7F
        if nbytes == 0 or nbytes > 4 or pos + nbytes > n:
            return None
        length = int.from_bytes(buf[pos:pos + nbytes], "big")
        pos += nbytes
    end = pos + length
    if end > n:
        return None
    return tag, pos, end


def ber_children(buf: bytes, start: int, end: int):
    """Iterate (tag, value_start, value_end) of the TLVs between start and end."""
    pos = start
    guard = 0
    while pos < end and guard < 4096:
        guard += 1
        tlv = ber_read_tlv(buf[:end], pos)
        if tlv is None:
            return
        yield tlv
        pos = tlv[2]


def ber_uint(data: bytes) -> int:
    return int.from_bytes(data[:8], "big") if data else 0


def mac_str(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw[:6])
